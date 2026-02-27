const std = @import("std");
const testing = std.testing;

const Client = @import("../client.zig").Client;
const Hub = @import("../hub.zig").Hub;
const Span = @import("../transaction.zig").Span;
const Transaction = @import("../transaction.zig").Transaction;
const TransactionOpts = @import("../transaction.zig").TransactionOpts;
const TransactionOrSpan = @import("../transaction.zig").TransactionOrSpan;
const SpanStatus = @import("../transaction.zig").SpanStatus;
const PropagationHeader = @import("../propagation.zig").PropagationHeader;
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

    /// Same as `begin`, but source propagation headers are extracted from raw
    /// incoming header pairs. Explicit header values in `options` have priority.
    pub fn beginFromHeaders(
        allocator: std.mem.Allocator,
        client: *Client,
        options: RequestOptions,
        headers: []const PropagationHeader,
    ) !RequestContext {
        var merged_options = options;
        const extracted = extractIncomingPropagationHeaders(headers);
        if (merged_options.sentry_trace_header == null) {
            merged_options.sentry_trace_header = extracted.sentry_trace_header;
        }
        if (merged_options.baggage_header == null) {
            merged_options.baggage_header = extracted.baggage_header;
        }
        return begin(allocator, client, merged_options);
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

pub const OutgoingRequestOptions = struct {
    op: []const u8 = "http.client",
    description: ?[]const u8 = null,
    method: ?[]const u8 = null,
    url: ?[]const u8 = null,
    query_string: ?[]const u8 = null,
};

pub const PropagationHeaders = struct {
    sentry_trace: []u8,
    baggage: []u8,

    pub fn deinit(self: *PropagationHeaders, allocator: std.mem.Allocator) void {
        allocator.free(self.sentry_trace);
        allocator.free(self.baggage);
        self.* = undefined;
    }
};

pub const PropagationHeaderList = struct {
    headers: [2]PropagationHeader,
    owned: PropagationHeaders,

    pub fn deinit(self: *PropagationHeaderList, allocator: std.mem.Allocator) void {
        self.owned.deinit(allocator);
        self.* = undefined;
    }

    pub fn slice(self: *const PropagationHeaderList) []const PropagationHeader {
        return self.headers[0..];
    }
};

/// Outbound request instrumentation context.
///
/// Requires an active current Hub with a bound transaction/span. `begin` creates
/// a child span (`http.client` by default), binds it as current span, and allows
/// generating propagation headers for downstream requests.
pub const OutgoingRequestContext = struct {
    hub: *Hub,
    previous_span: TransactionOrSpan,
    span: *Span,
    finished: bool = false,
    active: bool = true,
    response_status_code: ?u16 = null,

    pub fn begin(options: OutgoingRequestOptions) !OutgoingRequestContext {
        const hub = Hub.current() orelse return error.NoCurrentHub;
        const previous_span = hub.getSpan() orelse return error.NoActiveSpan;
        const span = try previous_span.startChild(.{
            .op = options.op,
            .description = options.description,
        });
        errdefer span.finish();

        if (options.method != null or options.url != null or options.query_string != null) {
            span.setRequest(.{
                .method = options.method,
                .url = options.url,
                .query_string = options.query_string,
            }) catch {};
        }

        hub.setSpan(.{ .span = span });
        return .{
            .hub = hub,
            .previous_span = previous_span,
            .span = span,
        };
    }

    pub fn setTag(self: *OutgoingRequestContext, key: []const u8, value: []const u8) void {
        self.span.setTag(key, value) catch {};
    }

    pub fn setStatusCode(self: *OutgoingRequestContext, status_code: u16) void {
        self.response_status_code = status_code;
    }

    pub fn captureError(self: *OutgoingRequestContext, err: anyerror) ?[32]u8 {
        return self.hub.captureErrorId(err);
    }

    pub fn captureException(self: *OutgoingRequestContext, exception_type: []const u8, value: []const u8) ?[32]u8 {
        return self.hub.captureExceptionId(exception_type, value);
    }

    pub fn sentryTraceHeaderAlloc(self: *OutgoingRequestContext, allocator: std.mem.Allocator) ![]u8 {
        return self.span.sentryTraceHeaderAlloc(allocator);
    }

    pub fn baggageHeaderAlloc(self: *OutgoingRequestContext, allocator: std.mem.Allocator) ![]u8 {
        return self.hub.baggageHeader(self.span.owner, allocator);
    }

    pub fn propagationHeadersAlloc(self: *OutgoingRequestContext, allocator: std.mem.Allocator) !PropagationHeaders {
        const sentry_trace = try self.sentryTraceHeaderAlloc(allocator);
        errdefer allocator.free(sentry_trace);

        const baggage = try self.baggageHeaderAlloc(allocator);
        return .{
            .sentry_trace = sentry_trace,
            .baggage = baggage,
        };
    }

    /// Build standard outgoing `sentry-trace` and `baggage` headers in a form
    /// that can be passed directly to APIs using `[]PropagationHeader`.
    pub fn propagationHeaderListAlloc(
        self: *OutgoingRequestContext,
        allocator: std.mem.Allocator,
    ) !PropagationHeaderList {
        const owned = try self.propagationHeadersAlloc(allocator);
        return .{
            .headers = .{
                .{
                    .name = "sentry-trace",
                    .value = owned.sentry_trace,
                },
                .{
                    .name = "baggage",
                    .value = owned.baggage,
                },
            },
            .owned = owned,
        };
    }

    pub fn finish(self: *OutgoingRequestContext, status_code_override: ?u16) void {
        if (self.finished) return;

        const status_code = status_code_override orelse self.response_status_code;
        if (status_code) |code| {
            self.span.setStatus(spanStatusFromHttpStatus(code));
            self.span.setData("status_code", .{ .integer = @as(i64, code) }) catch {};
        }
        self.span.finish();
        self.finished = true;

        if (self.isCurrentSpan()) {
            self.hub.setSpan(self.previous_span);
        }
    }

    pub fn fail(self: *OutgoingRequestContext, err: anyerror, status_code_override: ?u16) ?[32]u8 {
        const event_id = self.captureError(err);
        if (status_code_override == null and self.response_status_code == null) {
            self.response_status_code = 500;
        }
        self.finish(status_code_override);
        return event_id;
    }

    pub fn deinit(self: *OutgoingRequestContext) void {
        if (!self.active) return;
        self.active = false;

        if (!self.finished) {
            self.finish(null);
            return;
        }

        if (self.isCurrentSpan()) {
            self.hub.setSpan(self.previous_span);
        }
    }

    fn isCurrentSpan(self: *const OutgoingRequestContext) bool {
        const current = self.hub.getSpan() orelse return false;
        return switch (current) {
            .span => |value| value == self.span,
            .transaction => false,
        };
    }
};

pub const IncomingHandlerFn = *const fn (*RequestContext, ?*anyopaque) anyerror!u16;

pub const IncomingRunOptions = struct {
    error_status_code: ?u16 = 500,
    capture_errors: bool = true,
};

pub const IncomingPropagationHeaders = struct {
    sentry_trace_header: ?[]const u8 = null,
    baggage_header: ?[]const u8 = null,
};

/// Extract `sentry-trace` and `baggage` values from case-insensitive header
/// list representation.
pub fn extractIncomingPropagationHeaders(headers: []const PropagationHeader) IncomingPropagationHeaders {
    var result: IncomingPropagationHeaders = .{};
    for (headers) |header| {
        const name = std.mem.trim(u8, header.name, " \t");
        if (result.sentry_trace_header == null and std.ascii.eqlIgnoreCase(name, "sentry-trace")) {
            result.sentry_trace_header = header.value;
            continue;
        }
        if (result.baggage_header == null and std.ascii.eqlIgnoreCase(name, "baggage")) {
            result.baggage_header = header.value;
        }
    }
    return result;
}

/// Run an incoming HTTP handler inside `RequestContext` lifecycle.
///
/// The handler returns response status code. On success the transaction is
/// finished with that status. On error the handler error is optionally captured
/// and transaction finishes with `error_status_code`.
pub fn runIncomingRequest(
    allocator: std.mem.Allocator,
    client: *Client,
    request_options: RequestOptions,
    handler: IncomingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: IncomingRunOptions,
) anyerror!u16 {
    var request_context = try RequestContext.begin(allocator, client, request_options);
    defer request_context.deinit();

    const status_code = handler(&request_context, handler_ctx) catch |err| {
        if (run_options.capture_errors) {
            _ = request_context.fail(err, run_options.error_status_code);
        } else {
            request_context.finish(run_options.error_status_code);
        }
        return err;
    };

    request_context.finish(status_code);
    return status_code;
}

/// Same as `runIncomingRequest`, with propagation headers auto-extracted from
/// raw header list.
pub fn runIncomingRequestFromHeaders(
    allocator: std.mem.Allocator,
    client: *Client,
    request_options: RequestOptions,
    headers: []const PropagationHeader,
    handler: IncomingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: IncomingRunOptions,
) anyerror!u16 {
    var request_context = try RequestContext.beginFromHeaders(allocator, client, request_options, headers);
    defer request_context.deinit();

    const status_code = handler(&request_context, handler_ctx) catch |err| {
        if (run_options.capture_errors) {
            _ = request_context.fail(err, run_options.error_status_code);
        } else {
            request_context.finish(run_options.error_status_code);
        }
        return err;
    };

    request_context.finish(status_code);
    return status_code;
}

pub const OutgoingHandlerFn = *const fn (*OutgoingRequestContext, ?*anyopaque) anyerror!u16;

pub const OutgoingRunOptions = struct {
    error_status_code: ?u16 = 500,
    capture_errors: bool = true,
};

/// Run an outgoing HTTP operation inside `OutgoingRequestContext` lifecycle.
///
/// The handler returns upstream status code. On success the child span is
/// finished with that status. On error the handler error is optionally captured
/// and span finishes with `error_status_code`.
pub fn runOutgoingRequest(
    request_options: OutgoingRequestOptions,
    handler: OutgoingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: OutgoingRunOptions,
) anyerror!u16 {
    var request_context = try OutgoingRequestContext.begin(request_options);
    defer request_context.deinit();

    const status_code = handler(&request_context, handler_ctx) catch |err| {
        if (run_options.capture_errors) {
            _ = request_context.fail(err, run_options.error_status_code);
        } else {
            request_context.finish(run_options.error_status_code);
        }
        return err;
    };

    request_context.finish(status_code);
    return status_code;
}

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

test "OutgoingRequestContext creates child span with propagation headers and restores previous span" {
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

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();
    _ = Hub.setCurrent(&hub);
    defer _ = Hub.clearCurrent();

    var txn = hub.startTransaction(.{
        .name = "GET /checkout",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var out = try OutgoingRequestContext.begin(.{
        .method = "POST",
        .url = "https://payments.example.com/charge",
        .description = "POST payments charge",
    });
    defer out.deinit();

    const current_span = hub.getSpan().?;
    try testing.expect(switch (current_span) {
        .span => |value| value == out.span,
        .transaction => false,
    });

    var headers = try out.propagationHeadersAlloc(testing.allocator);
    defer headers.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, headers.sentry_trace, txn.trace_id[0..]) != null);
    try testing.expect(std.mem.indexOf(u8, headers.sentry_trace, out.span.span_id[0..]) != null);
    try testing.expect(std.mem.indexOf(u8, headers.baggage, "sentry-trace_id=") != null);

    out.setTag("peer.service", "payments");
    out.setStatusCode(503);
    out.finish(null);

    const restored = hub.getSpan().?;
    try testing.expect(switch (restored) {
        .transaction => |value| value == &txn,
        .span => false,
    });

    hub.finishTransaction(&txn);
    hub.setSpan(null);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") != null) {
            saw_transaction = true;
            try testing.expect(std.mem.indexOf(u8, payload, "\"op\":\"http.client\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"description\":\"POST payments charge\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"unavailable\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"method\":\"POST\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"url\":\"https://payments.example.com/charge\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":503") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"peer.service\":\"payments\"") != null);
        }
    }
    try testing.expect(saw_transaction);
}

test "OutgoingRequestContext propagationHeaderListAlloc returns standard header pairs" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();
    _ = Hub.setCurrent(&hub);
    defer _ = Hub.clearCurrent();

    var txn = hub.startTransaction(.{
        .name = "GET /headers",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var out = try OutgoingRequestContext.begin(.{
        .method = "GET",
        .url = "https://downstream.example.com/health",
    });
    defer out.deinit();

    var list = try out.propagationHeaderListAlloc(testing.allocator);
    defer list.deinit(testing.allocator);

    const headers = list.slice();
    try testing.expectEqual(@as(usize, 2), headers.len);
    try testing.expectEqualStrings("sentry-trace", headers[0].name);
    try testing.expectEqualStrings("baggage", headers[1].name);
    try testing.expect(std.mem.indexOf(u8, headers[0].value, txn.trace_id[0..]) != null);
    try testing.expect(std.mem.indexOf(u8, headers[1].value, "sentry-trace_id=") != null);
}

test "OutgoingRequestContext fail captures error and defaults HTTP status to 500" {
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

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();
    _ = Hub.setCurrent(&hub);
    defer _ = Hub.clearCurrent();

    var txn = hub.startTransaction(.{
        .name = "POST /checkout",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var out = try OutgoingRequestContext.begin(.{
        .method = "POST",
        .url = "https://inventory.example.com/reserve",
    });
    defer out.deinit();

    const event_id = out.fail(error.OutgoingDependencyTimeout, null);
    try testing.expect(event_id != null);

    hub.finishTransaction(&txn);
    hub.setSpan(null);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 2);

    var saw_transaction = false;
    var saw_error_event = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") != null) {
            saw_transaction = true;
            try testing.expect(std.mem.indexOf(u8, payload, "\"op\":\"http.client\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"internal_error\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":500") != null);
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"event\"") != null and
            std.mem.indexOf(u8, payload, "OutgoingDependencyTimeout") != null)
        {
            saw_error_event = true;
        }
    }

    try testing.expect(saw_transaction);
    try testing.expect(saw_error_event);
}

test "OutgoingRequestContext begin requires current hub and active span" {
    try testing.expectError(error.NoCurrentHub, OutgoingRequestContext.begin(.{}));

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();
    _ = Hub.setCurrent(&hub);
    defer _ = Hub.clearCurrent();

    try testing.expect(hub.getSpan() == null);
    try testing.expectError(error.NoActiveSpan, OutgoingRequestContext.begin(.{}));
}

const IncomingHandlerSuccessState = struct {
    headers_seen: bool = false,
};

fn incomingHandlerSuccess(context: *RequestContext, ctx: ?*anyopaque) anyerror!u16 {
    const state: *IncomingHandlerSuccessState = @ptrCast(@alignCast(ctx.?));
    state.headers_seen = true;
    context.setTag("handler", "incoming-success");
    return 204;
}

fn incomingHandlerFailure(_: *RequestContext, _: ?*anyopaque) anyerror!u16 {
    return error.IncomingPipelineFailure;
}

const OutgoingHandlerSuccessState = struct {
    saw_trace_header: bool = false,
    saw_baggage_header: bool = false,
};

fn outgoingHandlerSuccess(context: *OutgoingRequestContext, ctx: ?*anyopaque) anyerror!u16 {
    const state: *OutgoingHandlerSuccessState = @ptrCast(@alignCast(ctx.?));
    var headers = try context.propagationHeadersAlloc(testing.allocator);
    defer headers.deinit(testing.allocator);

    state.saw_trace_header = std.mem.indexOf(u8, headers.sentry_trace, "-") != null;
    state.saw_baggage_header = std.mem.indexOf(u8, headers.baggage, "sentry-trace_id=") != null;
    context.setTag("handler", "outgoing-success");
    return 202;
}

fn outgoingHandlerFailure(_: *OutgoingRequestContext, _: ?*anyopaque) anyerror!u16 {
    return error.OutgoingPipelineFailure;
}

test "runIncomingRequest auto-finishes transaction and captures handler data" {
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

    var state = IncomingHandlerSuccessState{};
    const status_code = try runIncomingRequest(
        testing.allocator,
        client,
        .{
            .name = "GET /pipeline",
            .method = "GET",
            .url = "https://api.example.com/pipeline",
        },
        incomingHandlerSuccess,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 204), status_code);
    try testing.expect(state.headers_seen);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") != null) {
            saw_transaction = true;
            try testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"GET /pipeline\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":204") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"handler\":\"incoming-success\"") != null);
        }
    }
    try testing.expect(saw_transaction);
}

test "extractIncomingPropagationHeaders reads case-insensitive sentry headers" {
    const headers = [_]PropagationHeader{
        .{
            .name = "Sentry-Trace",
            .value = "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
        },
        .{
            .name = "BAGGAGE",
            .value = "sentry-trace_id=0123456789abcdef0123456789abcdef,sentry-sampled=true",
        },
    };

    const extracted = extractIncomingPropagationHeaders(&headers);
    try testing.expect(extracted.sentry_trace_header != null);
    try testing.expect(extracted.baggage_header != null);
    try testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
        extracted.sentry_trace_header.?,
    );
    try testing.expect(std.mem.indexOf(u8, extracted.baggage_header.?, "sentry-trace_id=") != null);
}

test "runIncomingRequestFromHeaders continues trace using extracted sentry-trace header" {
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

    const headers = [_]PropagationHeader{
        .{
            .name = "sentry-trace",
            .value = "fedcba9876543210fedcba9876543210-0123456789abcdef-1",
        },
        .{
            .name = "baggage",
            .value = "sentry-trace_id=fedcba9876543210fedcba9876543210,sentry-sampled=true",
        },
    };

    var state = IncomingHandlerSuccessState{};
    const status_code = try runIncomingRequestFromHeaders(
        testing.allocator,
        client,
        .{
            .name = "GET /pipeline-headers",
            .method = "GET",
            .url = "https://api.example.com/pipeline-headers",
        },
        &headers,
        incomingHandlerSuccess,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 204), status_code);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "fedcba9876543210fedcba9876543210") != null);
}

test "runIncomingRequest captures handler errors and marks transaction as internal_error" {
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

    try testing.expectError(
        error.IncomingPipelineFailure,
        runIncomingRequest(
            testing.allocator,
            client,
            .{
                .name = "GET /pipeline-fail",
                .method = "GET",
                .url = "https://api.example.com/pipeline-fail",
            },
            incomingHandlerFailure,
            null,
            .{},
        ),
    );

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 2);

    var saw_transaction = false;
    var saw_error_event = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") != null) {
            saw_transaction = true;
            try testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"internal_error\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":500") != null);
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"event\"") != null and
            std.mem.indexOf(u8, payload, "\"value\":\"IncomingPipelineFailure\"") != null)
        {
            saw_error_event = true;
        }
    }
    try testing.expect(saw_transaction);
    try testing.expect(saw_error_event);
}

test "runOutgoingRequest auto-finishes span and propagates headers" {
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

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();
    _ = Hub.setCurrent(&hub);
    defer _ = Hub.clearCurrent();

    var txn = hub.startTransaction(.{
        .name = "POST /checkout",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var state = OutgoingHandlerSuccessState{};
    const status_code = try runOutgoingRequest(
        .{
            .method = "POST",
            .url = "https://payments.example.com/v1/charge",
            .description = "POST payments charge",
        },
        outgoingHandlerSuccess,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 202), status_code);
    try testing.expect(state.saw_trace_header);
    try testing.expect(state.saw_baggage_header);

    hub.finishTransaction(&txn);
    hub.setSpan(null);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") != null) {
            saw_transaction = true;
            try testing.expect(std.mem.indexOf(u8, payload, "\"description\":\"POST payments charge\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":202") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"handler\":\"outgoing-success\"") != null);
        }
    }
    try testing.expect(saw_transaction);
}

test "runOutgoingRequest can skip error capture while still finishing span" {
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

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();
    _ = Hub.setCurrent(&hub);
    defer _ = Hub.clearCurrent();

    var txn = hub.startTransaction(.{
        .name = "POST /checkout-skip-capture",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    try testing.expectError(
        error.OutgoingPipelineFailure,
        runOutgoingRequest(
            .{
                .method = "POST",
                .url = "https://inventory.example.com/v1/reserve",
            },
            outgoingHandlerFailure,
            null,
            .{
                .capture_errors = false,
                .error_status_code = 504,
            },
        ),
    );

    hub.finishTransaction(&txn);
    hub.setSpan(null);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var saw_transaction = false;
    var saw_error_event = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") != null) {
            saw_transaction = true;
            try testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"internal_error\"") != null or
                std.mem.indexOf(u8, payload, "\"status\":\"unavailable\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":504") != null);
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"event\"") != null and
            std.mem.indexOf(u8, payload, "\"value\":\"OutgoingPipelineFailure\"") != null)
        {
            saw_error_event = true;
        }
    }
    try testing.expect(saw_transaction);
    try testing.expect(!saw_error_event);
}
