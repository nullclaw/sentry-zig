const std = @import("std");
const testing = std.testing;

const Client = @import("../client.zig").Client;
const Hub = @import("../hub.zig").Hub;
const Transaction = @import("../transaction.zig").Transaction;
const TransactionOpts = @import("../transaction.zig").TransactionOpts;
const SpanStatus = @import("../transaction.zig").SpanStatus;
const SendOutcome = @import("../worker.zig").SendOutcome;

pub const RequestOptions = struct {
    name: []const u8,
    op: []const u8 = "http.server",
    method: ?[]const u8 = null,
    url: ?[]const u8 = null,
    query_string: ?[]const u8 = null,
    sentry_trace_header: ?[]const u8 = null,
    baggage_header: ?[]const u8 = null,
    set_scope_transaction_name: bool = true,
    origin: ?[]const u8 = "auto.http.server",
};

/// Per-request instrumentation context.
///
/// `begin` creates an isolated Hub scope for the request, starts a transaction,
/// and binds that Hub as TLS current. Call `finish` once a response status is
/// available, then `deinit` at request completion.
pub const RequestContext = struct {
    allocator: std.mem.Allocator,
    hub: *Hub,
    previous_hub: ?*Hub,
    txn: Transaction,
    finished: bool = false,
    active: bool = true,
    response_status_code: ?u16 = null,

    pub fn begin(allocator: std.mem.Allocator, client: *Client, options: RequestOptions) !RequestContext {
        const hub_ptr = try allocator.create(Hub);
        errdefer allocator.destroy(hub_ptr);

        if (Hub.current()) |existing| {
            hub_ptr.* = try Hub.initFromTop(allocator, existing, client);
        } else {
            hub_ptr.* = try Hub.init(allocator, client);
        }
        errdefer hub_ptr.deinit();

        const previous_hub = Hub.setCurrent(hub_ptr);
        errdefer {
            if (Hub.current()) |current| {
                if (current == hub_ptr) {
                    _ = Hub.clearCurrent();
                    if (previous_hub) |previous| _ = Hub.setCurrent(previous);
                }
            }
        }

        const txn_opts = TransactionOpts{
            .name = options.name,
            .op = options.op,
        };
        var txn = if (options.sentry_trace_header != null or options.baggage_header != null)
            try hub_ptr.startTransactionFromPropagationHeaders(
                txn_opts,
                options.sentry_trace_header,
                options.baggage_header,
            )
        else
            hub_ptr.startTransaction(txn_opts);
        errdefer txn.deinit();

        if (options.origin) |origin| {
            try txn.setOrigin(origin);
        }

        if (options.method != null or options.url != null or options.query_string != null) {
            try txn.setRequest(.{
                .method = options.method,
                .url = options.url,
                .query_string = options.query_string,
            });
        }

        if (options.set_scope_transaction_name) {
            try hub_ptr.trySetTransaction(options.name);
        }

        hub_ptr.setSpan(.{ .transaction = &txn });

        return .{
            .allocator = allocator,
            .hub = hub_ptr,
            .previous_hub = previous_hub,
            .txn = txn,
        };
    }

    pub fn setTag(self: *RequestContext, key: []const u8, value: []const u8) void {
        self.hub.setTag(key, value);
    }

    pub fn setStatusCode(self: *RequestContext, status_code: u16) void {
        self.response_status_code = status_code;
    }

    pub fn captureError(self: *RequestContext, err: anyerror) ?[32]u8 {
        return self.hub.captureErrorId(err);
    }

    pub fn captureException(self: *RequestContext, exception_type: []const u8, value: []const u8) ?[32]u8 {
        return self.hub.captureExceptionId(exception_type, value);
    }

    pub fn finish(self: *RequestContext, status_code_override: ?u16) void {
        if (self.finished) return;

        const status_code = status_code_override orelse self.response_status_code;
        if (status_code) |code| {
            self.txn.setStatus(spanStatusFromHttpStatus(code));
            self.txn.setData("status_code", .{ .integer = @as(i64, code) }) catch {};
        }

        self.hub.finishTransaction(&self.txn);
        self.hub.setSpan(null);
        self.finished = true;
    }

    pub fn fail(self: *RequestContext, err: anyerror, status_code_override: ?u16) ?[32]u8 {
        const event_id = self.captureError(err);
        if (status_code_override == null and self.response_status_code == null) {
            self.response_status_code = 500;
        }
        self.finish(status_code_override);
        return event_id;
    }

    pub fn deinit(self: *RequestContext) void {
        if (!self.active) return;
        self.active = false;

        if (!self.finished) {
            self.finish(null);
        }

        if (Hub.current()) |current| {
            if (current == self.hub) {
                _ = Hub.clearCurrent();
                if (self.previous_hub) |previous| _ = Hub.setCurrent(previous);
            }
        }

        self.txn.deinit();
        self.hub.deinit();
        self.allocator.destroy(self.hub);
    }
};

pub fn spanStatusFromHttpStatus(status_code: u16) SpanStatus {
    return switch (status_code) {
        401 => .unauthenticated,
        403 => .permission_denied,
        404 => .not_found,
        409 => .already_exists,
        429 => .resource_exhausted,
        501 => .unimplemented,
        503 => .unavailable,
        500...599 => .internal_error,
        400...499 => .invalid_argument,
        200...399 => .ok,
        else => .unknown,
    };
}

test "spanStatusFromHttpStatus follows server mapping semantics" {
    try testing.expectEqual(SpanStatus.ok, spanStatusFromHttpStatus(200));
    try testing.expectEqual(SpanStatus.ok, spanStatusFromHttpStatus(302));
    try testing.expectEqual(SpanStatus.unauthenticated, spanStatusFromHttpStatus(401));
    try testing.expectEqual(SpanStatus.permission_denied, spanStatusFromHttpStatus(403));
    try testing.expectEqual(SpanStatus.not_found, spanStatusFromHttpStatus(404));
    try testing.expectEqual(SpanStatus.already_exists, spanStatusFromHttpStatus(409));
    try testing.expectEqual(SpanStatus.resource_exhausted, spanStatusFromHttpStatus(429));
    try testing.expectEqual(SpanStatus.unimplemented, spanStatusFromHttpStatus(501));
    try testing.expectEqual(SpanStatus.unavailable, spanStatusFromHttpStatus(503));
    try testing.expectEqual(SpanStatus.internal_error, spanStatusFromHttpStatus(500));
    try testing.expectEqual(SpanStatus.invalid_argument, spanStatusFromHttpStatus(400));
    try testing.expectEqual(SpanStatus.unknown, spanStatusFromHttpStatus(101));
}

const PayloadState = struct {
    allocator: std.mem.Allocator,
    payloads: std.ArrayListUnmanaged([]u8) = .{},

    fn deinit(self: *PayloadState) void {
        for (self.payloads.items) |payload| self.allocator.free(payload);
        self.payloads.deinit(self.allocator);
        self.* = undefined;
    }
};

fn payloadSendFn(data: []const u8, ctx: ?*anyopaque) SendOutcome {
    const state: *PayloadState = @ptrCast(@alignCast(ctx.?));
    const copied = state.allocator.dupe(u8, data) catch return .{};
    state.payloads.append(state.allocator, copied) catch state.allocator.free(copied);
    return .{};
}

test "RequestContext begin/finish captures transaction with propagated trace and status" {
    var payload_state = PayloadState{ .allocator = testing.allocator };
    defer payload_state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .transport = .{
            .send_fn = payloadSendFn,
            .ctx = &payload_state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var parent_hub = try Hub.init(testing.allocator, client);
    defer parent_hub.deinit();
    _ = Hub.setCurrent(&parent_hub);
    defer _ = Hub.clearCurrent();
    parent_hub.setTag("tenant", "acme");

    var req = try RequestContext.begin(testing.allocator, client, .{
        .name = "GET /orders/:id",
        .method = "GET",
        .url = "https://api.example.com/orders/42",
        .query_string = "expand=items",
        .sentry_trace_header = "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
        .baggage_header = "foo=bar,sentry-release=legacy",
    });
    defer req.deinit();

    try testing.expect(Hub.current().? == req.hub);
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", req.txn.trace_id[0..]);

    req.setTag("route", "orders.show");
    _ = req.captureError(error.HttpIntegrationParityError);
    req.setStatusCode(404);
    req.finish(null);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 2);

    var saw_transaction = false;
    var saw_error_event = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") != null) {
            saw_transaction = true;
            try testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"GET /orders/:id\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"op\":\"http.server\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"not_found\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"method\":\"GET\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"url\":\"https://api.example.com/orders/42\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"query_string\":\"expand=items\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"tenant\":\"acme\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"route\":\"orders.show\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":404") != null);
        }

        if (std.mem.indexOf(u8, payload, "\"type\":\"event\"") != null and
            std.mem.indexOf(u8, payload, "HttpIntegrationParityError") != null)
        {
            saw_error_event = true;
        }
    }

    try testing.expect(saw_transaction);
    try testing.expect(saw_error_event);
}
