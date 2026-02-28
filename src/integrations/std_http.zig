const std = @import("std");
const testing = std.testing;

const Client = @import("../client.zig").Client;
const Hub = @import("../hub.zig").Hub;
const SendOutcome = @import("../worker.zig").SendOutcome;
const propagation = @import("../propagation.zig");
const http = @import("http.zig");

pub const IncomingOptions = struct {
    transaction_name: ?[]const u8 = null,
    op: []const u8 = "http.server",
    set_scope_transaction_name: bool = true,
    origin: ?[]const u8 = "auto.http.server.std",
    add_breadcrumb_on_finish: bool = true,
    breadcrumb_category: []const u8 = "http.server",
};

fn splitTarget(target: []const u8) struct { path: []const u8, query: ?[]const u8 } {
    if (std.mem.indexOfScalar(u8, target, '?')) |idx| {
        const query = if (idx + 1 < target.len) target[idx + 1 ..] else null;
        return .{
            .path = target[0..idx],
            .query = query,
        };
    }
    return .{
        .path = target,
        .query = null,
    };
}

fn parseIncomingHeaders(headers: []const std.http.Header) propagation.ParsedPropagationHeaders {
    var parsed: propagation.ParsedPropagationHeaders = .{};
    for (headers) |header| {
        propagation.applyPropagationHeaderPair(&parsed, header.name, header.value);
    }
    return parsed;
}

/// Parse propagation headers directly from `std.http.HeaderIterator`.
pub fn parseIncomingHeaderIterator(it: *std.http.HeaderIterator) propagation.ParsedPropagationHeaders {
    var parsed: propagation.ParsedPropagationHeaders = .{};
    while (it.next()) |header| {
        propagation.applyPropagationHeaderPair(&parsed, header.name, header.value);
    }
    return parsed;
}

fn buildRequestOptionsFromParsed(
    method: std.http.Method,
    target: []const u8,
    parsed_headers: propagation.ParsedPropagationHeaders,
    options: IncomingOptions,
    trace_buffer: *[51]u8,
) http.RequestOptions {
    var sentry_trace_header = parsed_headers.sentry_trace_header;
    if (sentry_trace_header == null) {
        if (parsed_headers.traceparent_header) |traceparent| {
            sentry_trace_header = propagation.sentryTraceFromTraceParent(traceparent, trace_buffer);
        }
    }

    const target_parts = splitTarget(target);
    const transaction_name = options.transaction_name orelse target_parts.path;
    return .{
        .name = transaction_name,
        .op = options.op,
        .method = @tagName(method),
        .url = target_parts.path,
        .query_string = target_parts.query,
        .sentry_trace_header = sentry_trace_header,
        .baggage_header = parsed_headers.baggage_header,
        .set_scope_transaction_name = options.set_scope_transaction_name,
        .origin = options.origin,
        .add_breadcrumb_on_finish = options.add_breadcrumb_on_finish,
        .breadcrumb_category = options.breadcrumb_category,
    };
}

fn buildRequestOptions(
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    options: IncomingOptions,
    trace_buffer: *[51]u8,
) http.RequestOptions {
    const parsed_headers = parseIncomingHeaders(headers);
    return buildRequestOptionsFromParsed(method, target, parsed_headers, options, trace_buffer);
}

/// Start incoming HTTP instrumentation from std.http request metadata.
pub fn beginIncomingRequest(
    allocator: std.mem.Allocator,
    client: *Client,
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    options: IncomingOptions,
) !http.RequestContext {
    var trace_buffer: [51]u8 = undefined;
    const request_options = buildRequestOptions(method, target, headers, options, &trace_buffer);
    return http.RequestContext.begin(allocator, client, request_options);
}

/// Start incoming instrumentation from `std.http.HeaderIterator`.
pub fn beginIncomingRequestFromHeaderIterator(
    allocator: std.mem.Allocator,
    client: *Client,
    method: std.http.Method,
    target: []const u8,
    header_it: *std.http.HeaderIterator,
    options: IncomingOptions,
) !http.RequestContext {
    const parsed_headers = parseIncomingHeaderIterator(header_it);
    var trace_buffer: [51]u8 = undefined;
    const request_options = buildRequestOptionsFromParsed(
        method,
        target,
        parsed_headers,
        options,
        &trace_buffer,
    );
    return http.RequestContext.begin(allocator, client, request_options);
}

/// Run incoming HTTP handler using std.http method/target/headers.
pub fn runIncomingRequest(
    allocator: std.mem.Allocator,
    client: *Client,
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    options: IncomingOptions,
    handler: http.IncomingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    var trace_buffer: [51]u8 = undefined;
    const request_options = buildRequestOptions(method, target, headers, options, &trace_buffer);
    return http.runIncomingRequest(
        allocator,
        client,
        request_options,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Run incoming handler using `std.http.HeaderIterator` as header source.
pub fn runIncomingRequestFromHeaderIterator(
    allocator: std.mem.Allocator,
    client: *Client,
    method: std.http.Method,
    target: []const u8,
    header_it: *std.http.HeaderIterator,
    options: IncomingOptions,
    handler: http.IncomingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    const parsed_headers = parseIncomingHeaderIterator(header_it);
    var trace_buffer: [51]u8 = undefined;
    const request_options = buildRequestOptionsFromParsed(
        method,
        target,
        parsed_headers,
        options,
        &trace_buffer,
    );
    return http.runIncomingRequest(
        allocator,
        client,
        request_options,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Typed variant of `runIncomingRequest`.
pub fn runIncomingRequestTyped(
    allocator: std.mem.Allocator,
    client: *Client,
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    options: IncomingOptions,
    comptime handler: anytype,
    handler_ctx: anytype,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    var trace_buffer: [51]u8 = undefined;
    const request_options = buildRequestOptions(method, target, headers, options, &trace_buffer);
    return http.runIncomingRequestTyped(
        allocator,
        client,
        request_options,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Typed variant of `runIncomingRequestFromHeaderIterator`.
pub fn runIncomingRequestFromHeaderIteratorTyped(
    allocator: std.mem.Allocator,
    client: *Client,
    method: std.http.Method,
    target: []const u8,
    header_it: *std.http.HeaderIterator,
    options: IncomingOptions,
    comptime handler: anytype,
    handler_ctx: anytype,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    const parsed_headers = parseIncomingHeaderIterator(header_it);
    var trace_buffer: [51]u8 = undefined;
    const request_options = buildRequestOptionsFromParsed(
        method,
        target,
        parsed_headers,
        options,
        &trace_buffer,
    );
    return http.runIncomingRequestTyped(
        allocator,
        client,
        request_options,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Current-hub variant of `runIncomingRequest`.
pub fn runIncomingRequestWithCurrentHub(
    allocator: std.mem.Allocator,
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    options: IncomingOptions,
    handler: http.IncomingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    const hub = Hub.current() orelse return error.NoCurrentHub;
    return runIncomingRequest(
        allocator,
        hub.clientPtr(),
        method,
        target,
        headers,
        options,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Typed current-hub variant of `runIncomingRequest`.
pub fn runIncomingRequestWithCurrentHubTyped(
    allocator: std.mem.Allocator,
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    options: IncomingOptions,
    comptime handler: anytype,
    handler_ctx: anytype,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    const hub = Hub.current() orelse return error.NoCurrentHub;
    return runIncomingRequestTyped(
        allocator,
        hub.clientPtr(),
        method,
        target,
        headers,
        options,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Current-hub variant of `runIncomingRequestFromHeaderIterator`.
pub fn runIncomingRequestFromHeaderIteratorWithCurrentHub(
    allocator: std.mem.Allocator,
    method: std.http.Method,
    target: []const u8,
    header_it: *std.http.HeaderIterator,
    options: IncomingOptions,
    handler: http.IncomingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    const hub = Hub.current() orelse return error.NoCurrentHub;
    return runIncomingRequestFromHeaderIterator(
        allocator,
        hub.clientPtr(),
        method,
        target,
        header_it,
        options,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Typed current-hub variant of `runIncomingRequestFromHeaderIterator`.
pub fn runIncomingRequestFromHeaderIteratorWithCurrentHubTyped(
    allocator: std.mem.Allocator,
    method: std.http.Method,
    target: []const u8,
    header_it: *std.http.HeaderIterator,
    options: IncomingOptions,
    comptime handler: anytype,
    handler_ctx: anytype,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    const hub = Hub.current() orelse return error.NoCurrentHub;
    return runIncomingRequestFromHeaderIteratorTyped(
        allocator,
        hub.clientPtr(),
        method,
        target,
        header_it,
        options,
        handler,
        handler_ctx,
        run_options,
    );
}

pub const OutgoingOptions = struct {
    method: std.http.Method,
    op: []const u8 = "http.client",
    description: ?[]const u8 = null,
    url: ?[]const u8 = null,
    query_string: ?[]const u8 = null,
    add_breadcrumb_on_finish: bool = true,
    breadcrumb_category: []const u8 = "http.client",
};

fn toOutgoingRequestOptions(options: OutgoingOptions) http.OutgoingRequestOptions {
    return .{
        .op = options.op,
        .description = options.description,
        .method = @tagName(options.method),
        .url = options.url,
        .query_string = options.query_string,
        .add_breadcrumb_on_finish = options.add_breadcrumb_on_finish,
        .breadcrumb_category = options.breadcrumb_category,
    };
}

/// Begin outgoing request instrumentation with std.http method semantics.
pub fn beginOutgoingRequest(options: OutgoingOptions) !http.OutgoingRequestContext {
    return http.OutgoingRequestContext.begin(toOutgoingRequestOptions(options));
}

/// Run outgoing request instrumentation with std.http method semantics.
pub fn runOutgoingRequest(
    options: OutgoingOptions,
    handler: http.OutgoingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: http.OutgoingRunOptions,
) anyerror!u16 {
    return http.runOutgoingRequest(
        toOutgoingRequestOptions(options),
        handler,
        handler_ctx,
        run_options,
    );
}

/// Typed variant of `runOutgoingRequest`.
pub fn runOutgoingRequestTyped(
    options: OutgoingOptions,
    comptime handler: anytype,
    handler_ctx: anytype,
    run_options: http.OutgoingRunOptions,
) anyerror!u16 {
    return http.runOutgoingRequestTyped(
        toOutgoingRequestOptions(options),
        handler,
        handler_ctx,
        run_options,
    );
}

/// std.http header list generated from outgoing Sentry propagation context.
pub const OutgoingStdHeaderList = struct {
    headers: [3]std.http.Header,
    owned: http.PropagationHeaderListWithTraceParent,

    pub fn deinit(self: *OutgoingStdHeaderList, allocator: std.mem.Allocator) void {
        self.owned.deinit(allocator);
        self.* = undefined;
    }

    pub fn slice(self: *const OutgoingStdHeaderList) []const std.http.Header {
        return self.headers[0..];
    }
};

/// Build `sentry-trace`, `baggage`, and `traceparent` headers as `std.http.Header`.
pub fn outgoingStdHeadersAlloc(
    context: *http.OutgoingRequestContext,
    allocator: std.mem.Allocator,
) !OutgoingStdHeaderList {
    const list = try context.propagationHeaderListWithTraceParentAlloc(allocator);
    return .{
        .headers = .{
            .{
                .name = list.headers[0].name,
                .value = list.headers[0].value,
            },
            .{
                .name = list.headers[1].name,
                .value = list.headers[1].value,
            },
            .{
                .name = list.headers[2].name,
                .value = list.headers[2].value,
            },
        },
        .owned = list,
    };
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

const IncomingState = struct {
    seen: bool = false,
};

fn incomingHandler(context: *http.RequestContext, ctx: ?*anyopaque) anyerror!u16 {
    const state: *IncomingState = @ptrCast(@alignCast(ctx.?));
    state.seen = true;
    context.setTag("handler", "std-http-anyopaque");
    return 204;
}

fn incomingTypedHandler(context: *http.RequestContext, state: *IncomingState) anyerror!u16 {
    state.seen = true;
    context.setTag("handler", "std-http-typed");
    return 205;
}

const OutgoingState = struct {
    saw_headers: bool = false,
};

fn outgoingTypedHandler(context: *http.OutgoingRequestContext, state: *OutgoingState) anyerror!u16 {
    var std_headers = try outgoingStdHeadersAlloc(context, testing.allocator);
    defer std_headers.deinit(testing.allocator);

    const headers = std_headers.slice();
    state.saw_headers = headers.len == 3 and
        std.mem.eql(u8, headers[0].name, "sentry-trace") and
        std.mem.eql(u8, headers[1].name, "baggage") and
        std.mem.eql(u8, headers[2].name, "traceparent");
    context.setTag("handler", "std-http-outgoing-typed");
    return 202;
}

test "std_http runIncomingRequest maps method target and propagation headers" {
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

    const headers = [_]std.http.Header{
        .{
            .name = "traceparent",
            .value = "00-0123456789abcdef0123456789abcdef-89abcdef01234567-01",
        },
        .{
            .name = "baggage",
            .value = "sentry-release=std-http,sentry-environment=test",
        },
    };

    var state = IncomingState{};
    const status_code = try runIncomingRequest(
        testing.allocator,
        client,
        .GET,
        "/orders/42?expand=items",
        &headers,
        .{ .transaction_name = "GET /orders/:id" },
        incomingHandler,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 204), status_code);
    try testing.expect(state.seen);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") == null) continue;
        saw_transaction = true;
        try testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"GET /orders/:id\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"trace_id\":\"0123456789abcdef0123456789abcdef\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"method\":\"GET\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"url\":\"/orders/42\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"query_string\":\"expand=items\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"handler\":\"std-http-anyopaque\"") != null);
    }
    try testing.expect(saw_transaction);
}

test "std_http runIncomingRequestWithCurrentHubTyped requires current hub" {
    _ = Hub.clearCurrent();
    try testing.expect(Hub.current() == null);

    const headers = [_]std.http.Header{};
    var state = IncomingState{};
    try testing.expectError(
        error.NoCurrentHub,
        runIncomingRequestWithCurrentHubTyped(
            testing.allocator,
            .GET,
            "/health",
            &headers,
            .{ .transaction_name = "GET /health" },
            incomingTypedHandler,
            &state,
            .{},
        ),
    );
}

test "std_http runIncomingRequestWithCurrentHubTyped uses typed context" {
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

    const headers = [_]std.http.Header{
        .{
            .name = "sentry-trace",
            .value = "fedcba9876543210fedcba9876543210-0123456789abcdef-1",
        },
    };

    var state = IncomingState{};
    const status_code = try runIncomingRequestWithCurrentHubTyped(
        testing.allocator,
        .POST,
        "/typed/run?mode=fast",
        &headers,
        .{ .transaction_name = "POST /typed/run" },
        incomingTypedHandler,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 205), status_code);
    try testing.expect(state.seen);

    try testing.expect(client.flush(1000));

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") == null) continue;
        saw_transaction = true;
        try testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"POST /typed/run\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"trace_id\":\"fedcba9876543210fedcba9876543210\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"method\":\"POST\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"url\":\"/typed/run\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"query_string\":\"mode=fast\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"handler\":\"std-http-typed\"") != null);
    }
    try testing.expect(saw_transaction);
}

test "std_http parseIncomingHeaderIterator extracts propagation headers" {
    var iterator = std.http.HeaderIterator.init(
        "GET /orders/42 HTTP/1.1\r\n" ++
            "traceparent: 00-0123456789abcdef0123456789abcdef-89abcdef01234567-01\r\n" ++
            "baggage: sentry-release=std-http-it,sentry-environment=test\r\n" ++
            "\r\n",
    );

    const parsed = parseIncomingHeaderIterator(&iterator);
    try testing.expect(parsed.sentry_trace_header == null);
    try testing.expect(parsed.baggage_header != null);
    try testing.expect(parsed.traceparent_header != null);
    try testing.expect(std.mem.startsWith(u8, parsed.traceparent_header.?, "00-"));
}

test "std_http runIncomingRequestFromHeaderIteratorTyped supports default transaction name" {
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

    var iterator = std.http.HeaderIterator.init(
        "GET /orders/42?expand=items HTTP/1.1\r\n" ++
            "traceparent: 00-0123456789abcdef0123456789abcdef-89abcdef01234567-01\r\n" ++
            "\r\n",
    );

    var state = IncomingState{};
    const status_code = try runIncomingRequestFromHeaderIteratorTyped(
        testing.allocator,
        client,
        .GET,
        "/orders/42?expand=items",
        &iterator,
        .{},
        incomingTypedHandler,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 205), status_code);
    try testing.expect(state.seen);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") == null) continue;
        saw_transaction = true;
        try testing.expect(std.mem.indexOf(u8, payload, "\"transaction\":\"/orders/42\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"trace_id\":\"0123456789abcdef0123456789abcdef\"") != null);
    }
    try testing.expect(saw_transaction);
}

test "std_http runOutgoingRequestTyped instruments outgoing span and provides std headers" {
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
        .name = "GET /outgoing-parent",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var state = OutgoingState{};
    const status_code = try runOutgoingRequestTyped(
        .{
            .method = .POST,
            .url = "https://inventory.example.com/reserve",
            .description = "POST reserve",
        },
        outgoingTypedHandler,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 202), status_code);
    try testing.expect(state.saw_headers);

    hub.finishTransaction(&txn);
    hub.setSpan(null);
    try testing.expect(client.flush(1000));

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") == null) continue;
        saw_transaction = true;
        try testing.expect(std.mem.indexOf(u8, payload, "\"description\":\"POST reserve\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"method\":\"POST\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"handler\":\"std-http-outgoing-typed\"") != null);
    }
    try testing.expect(saw_transaction);
}
