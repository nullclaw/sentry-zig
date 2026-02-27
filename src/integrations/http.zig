const std = @import("std");
const testing = std.testing;

const Client = @import("../client.zig").Client;
const Breadcrumb = @import("../event.zig").Breadcrumb;
const Level = @import("../event.zig").Level;
const Hub = @import("../hub.zig").Hub;
const Span = @import("../transaction.zig").Span;
const Transaction = @import("../transaction.zig").Transaction;
const TransactionOpts = @import("../transaction.zig").TransactionOpts;
const TransactionOrSpan = @import("../transaction.zig").TransactionOrSpan;
const SpanStatus = @import("../transaction.zig").SpanStatus;
const PropagationHeader = @import("../propagation.zig").PropagationHeader;
const propagation = @import("../propagation.zig");
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
    add_breadcrumb_on_finish: bool = true,
    breadcrumb_category: []const u8 = "http.server",
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
    txn: *Transaction,
    finished: bool = false,
    active: bool = true,
    response_status_code: ?u16 = null,
    request_method: ?[]const u8 = null,
    request_url: ?[]const u8 = null,
    add_breadcrumb_on_finish: bool = true,
    breadcrumb_category: []const u8 = "http.server",

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
        const txn_ptr = try allocator.create(Transaction);
        errdefer allocator.destroy(txn_ptr);

        txn_ptr.* = if (options.sentry_trace_header != null or options.baggage_header != null)
            try hub_ptr.startTransactionFromPropagationHeaders(
                txn_opts,
                options.sentry_trace_header,
                options.baggage_header,
            )
        else
            hub_ptr.startTransaction(txn_opts);
        errdefer txn_ptr.deinit();

        if (options.origin) |origin| {
            try txn_ptr.setOrigin(origin);
        }

        if (options.method != null or options.url != null or options.query_string != null) {
            try txn_ptr.setRequest(.{
                .method = options.method,
                .url = options.url,
                .query_string = options.query_string,
            });
        }

        if (options.set_scope_transaction_name) {
            try hub_ptr.trySetTransaction(options.name);
        }

        var context: RequestContext = .{
            .allocator = allocator,
            .hub = hub_ptr,
            .previous_hub = previous_hub,
            .txn = txn_ptr,
            .request_method = options.method,
            .request_url = options.url,
            .add_breadcrumb_on_finish = options.add_breadcrumb_on_finish,
            .breadcrumb_category = options.breadcrumb_category,
        };
        context.hub.setSpan(.{ .transaction = context.txn });
        return context;
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
        var sentry_trace_from_traceparent: [51]u8 = undefined;
        if (merged_options.sentry_trace_header == null) {
            if (extracted.sentry_trace_header) |header| {
                merged_options.sentry_trace_header = header;
            } else if (extracted.traceparent_header) |traceparent| {
                if (sentryTraceFromTraceParent(traceparent, &sentry_trace_from_traceparent)) |converted| {
                    merged_options.sentry_trace_header = converted;
                }
            }
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

        if (self.add_breadcrumb_on_finish) {
            addHttpBreadcrumb(
                self.hub,
                self.breadcrumb_category,
                self.request_method,
                self.request_url,
                status_code,
            );
        }

        self.hub.finishTransaction(self.txn);
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
        self.allocator.destroy(self.txn);
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
    add_breadcrumb_on_finish: bool = true,
    breadcrumb_category: []const u8 = "http.client",
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

pub const PropagationHeaderListWithTraceParent = struct {
    headers: [3]PropagationHeader,
    owned: PropagationHeaders,
    traceparent: []u8,

    pub fn deinit(self: *PropagationHeaderListWithTraceParent, allocator: std.mem.Allocator) void {
        self.owned.deinit(allocator);
        allocator.free(self.traceparent);
        self.* = undefined;
    }

    pub fn slice(self: *const PropagationHeaderListWithTraceParent) []const PropagationHeader {
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
    request_method: ?[]const u8 = null,
    request_url: ?[]const u8 = null,
    add_breadcrumb_on_finish: bool = true,
    breadcrumb_category: []const u8 = "http.client",

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
            .request_method = options.method,
            .request_url = options.url,
            .add_breadcrumb_on_finish = options.add_breadcrumb_on_finish,
            .breadcrumb_category = options.breadcrumb_category,
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
        const owner = self.resolveOwnerTransaction() orelse return error.NoOwningTransaction;
        return self.hub.baggageHeader(owner, allocator);
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

    /// Build `traceparent` (W3C Trace Context) header value from current span.
    pub fn traceParentHeaderAlloc(self: *OutgoingRequestContext, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "00-{s}-{s}-{s}",
            .{
                self.span.trace_id[0..],
                self.span.span_id[0..],
                if (self.span.sampled) "01" else "00",
            },
        );
    }

    /// Build standard outgoing header triplet:
    /// `sentry-trace`, `baggage`, and W3C `traceparent`.
    pub fn propagationHeaderListWithTraceParentAlloc(
        self: *OutgoingRequestContext,
        allocator: std.mem.Allocator,
    ) !PropagationHeaderListWithTraceParent {
        var owned = try self.propagationHeadersAlloc(allocator);
        errdefer owned.deinit(allocator);

        const traceparent = try self.traceParentHeaderAlloc(allocator);
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
                .{
                    .name = "traceparent",
                    .value = traceparent,
                },
            },
            .owned = owned,
            .traceparent = traceparent,
        };
    }

    pub fn finish(self: *OutgoingRequestContext, status_code_override: ?u16) void {
        if (self.finished) return;

        const status_code = status_code_override orelse self.response_status_code;
        if (status_code) |code| {
            self.span.setStatus(spanStatusFromHttpStatus(code));
            self.span.setData("status_code", .{ .integer = @as(i64, code) }) catch {};
        }

        if (self.add_breadcrumb_on_finish) {
            addHttpBreadcrumb(
                self.hub,
                self.breadcrumb_category,
                self.request_method,
                self.request_url,
                status_code,
            );
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

    fn resolveOwnerTransaction(self: *const OutgoingRequestContext) ?*const Transaction {
        if (self.span.owner) |owner| return owner;
        return switch (self.previous_span) {
            .transaction => |txn| txn,
            .span => |parent_span| parent_span.owner,
        };
    }
};

pub const IncomingHandlerFn = *const fn (*RequestContext, ?*anyopaque) anyerror!u16;

pub const IncomingRunOptions = struct {
    error_status_code: ?u16 = 500,
    capture_errors: bool = true,
};

pub const IncomingPropagationHeaders = propagation.ParsedPropagationHeaders;

/// Extract `sentry-trace` and `baggage` values from case-insensitive header
/// list representation.
pub fn extractIncomingPropagationHeaders(headers: []const PropagationHeader) IncomingPropagationHeaders {
    return propagation.parsePropagationHeaders(headers);
}

fn sentryTraceFromTraceParent(traceparent: []const u8, output: *[51]u8) ?[]const u8 {
    const parsed = propagation.parseTraceParent(traceparent) orelse return null;
    const sampled: u8 = if (parsed.sampled == true) '1' else '0';

    @memcpy(output[0..32], parsed.trace_id[0..]);
    output[32] = '-';
    @memcpy(output[33..49], parsed.parent_span_id[0..]);
    output[49] = '-';
    output[50] = sampled;
    return output[0..];
}

fn breadcrumbLevelFromStatus(status_code: ?u16) Level {
    const code = status_code orelse return .info;
    if (code >= 500) return .err;
    if (code >= 400) return .warning;
    return .info;
}

fn addHttpBreadcrumb(
    hub: *Hub,
    category: []const u8,
    method: ?[]const u8,
    url: ?[]const u8,
    status_code: ?u16,
) void {
    var message_buf: [512]u8 = undefined;
    const message = if (status_code) |code|
        if (method) |request_method|
            if (url) |request_url|
                std.fmt.bufPrint(&message_buf, "{s} {s} -> {d}", .{ request_method, request_url, code }) catch null
            else
                std.fmt.bufPrint(&message_buf, "{s} -> {d}", .{ request_method, code }) catch null
        else if (url) |request_url|
            std.fmt.bufPrint(&message_buf, "{s} -> {d}", .{ request_url, code }) catch null
        else
            std.fmt.bufPrint(&message_buf, "HTTP {d}", .{code}) catch null
    else if (method) |request_method|
        if (url) |request_url|
            std.fmt.bufPrint(&message_buf, "{s} {s}", .{ request_method, request_url }) catch null
        else
            std.fmt.bufPrint(&message_buf, "{s}", .{request_method}) catch null
    else
        url;

    const crumb: Breadcrumb = .{
        .type = "http",
        .category = category,
        .message = message,
        .level = breadcrumbLevelFromStatus(status_code),
    };
    hub.addBreadcrumb(crumb);
}

fn functionInfoFromCallable(comptime Callable: type, comptime api_name: []const u8) std.builtin.Type.Fn {
    return switch (@typeInfo(Callable)) {
        .@"fn" => |fn_info| fn_info,
        .pointer => |ptr| switch (@typeInfo(ptr.child)) {
            .@"fn" => |fn_info| fn_info,
            else => @compileError(api_name ++ " expects a function or function pointer"),
        },
        else => @compileError(api_name ++ " expects a function or function pointer"),
    };
}

fn assertSinglePointerContext(comptime ContextType: type, comptime api_name: []const u8) void {
    const ptr = switch (@typeInfo(ContextType)) {
        .pointer => |info| info,
        else => @compileError(api_name ++ " requires `handler_ctx` to be a single-item pointer"),
    };
    if (ptr.size != .one) {
        @compileError(api_name ++ " requires `handler_ctx` to be a single-item pointer");
    }
}

fn assertErrorUnionU16Return(comptime ReturnType: type, comptime api_name: []const u8) void {
    switch (@typeInfo(ReturnType)) {
        .error_union => |eu| {
            if (eu.payload != u16) {
                @compileError(api_name ++ " requires handler return type `anyerror!u16`");
            }
        },
        else => @compileError(api_name ++ " requires handler return type `anyerror!u16`"),
    }
}

fn assertIncomingTypedHandler(comptime HandlerType: type, comptime ContextType: type, comptime api_name: []const u8) void {
    const fn_info = functionInfoFromCallable(HandlerType, api_name);
    if (fn_info.params.len != 2) {
        @compileError(api_name ++ " requires handler signature `fn(*RequestContext, <ctx_ptr>) anyerror!u16`");
    }

    const request_param = fn_info.params[0].type orelse
        @compileError(api_name ++ " handler parameters must have concrete types");
    if (request_param != *RequestContext) {
        @compileError(api_name ++ " first handler parameter must be `*RequestContext`");
    }

    const context_param = fn_info.params[1].type orelse
        @compileError(api_name ++ " handler parameters must have concrete types");
    if (context_param != ContextType) {
        @compileError(api_name ++ " second handler parameter must match `handler_ctx` type");
    }

    const return_type = fn_info.return_type orelse
        @compileError(api_name ++ " handler must have return type `anyerror!u16`");
    assertErrorUnionU16Return(return_type, api_name);
}

fn assertOutgoingTypedHandler(comptime HandlerType: type, comptime ContextType: type, comptime api_name: []const u8) void {
    const fn_info = functionInfoFromCallable(HandlerType, api_name);
    if (fn_info.params.len != 2) {
        @compileError(api_name ++ " requires handler signature `fn(*OutgoingRequestContext, <ctx_ptr>) anyerror!u16`");
    }

    const request_param = fn_info.params[0].type orelse
        @compileError(api_name ++ " handler parameters must have concrete types");
    if (request_param != *OutgoingRequestContext) {
        @compileError(api_name ++ " first handler parameter must be `*OutgoingRequestContext`");
    }

    const context_param = fn_info.params[1].type orelse
        @compileError(api_name ++ " handler parameters must have concrete types");
    if (context_param != ContextType) {
        @compileError(api_name ++ " second handler parameter must match `handler_ctx` type");
    }

    const return_type = fn_info.return_type orelse
        @compileError(api_name ++ " handler must have return type `anyerror!u16`");
    assertErrorUnionU16Return(return_type, api_name);
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

/// Typed variant of `runIncomingRequest`.
///
/// It removes `anyopaque` casts from user code by accepting a strongly-typed
/// context pointer and compile-time validating handler signature.
pub fn runIncomingRequestTyped(
    allocator: std.mem.Allocator,
    client: *Client,
    request_options: RequestOptions,
    comptime handler: anytype,
    handler_ctx: anytype,
    run_options: IncomingRunOptions,
) anyerror!u16 {
    const ContextType = @TypeOf(handler_ctx);
    comptime {
        assertSinglePointerContext(ContextType, "runIncomingRequestTyped");
        assertIncomingTypedHandler(@TypeOf(handler), ContextType, "runIncomingRequestTyped");
    }

    const Adapter = struct {
        fn call(request_context: *RequestContext, ctx: ?*anyopaque) anyerror!u16 {
            const typed_ctx: ContextType = @ptrCast(@alignCast(ctx.?));
            return @call(.auto, handler, .{ request_context, typed_ctx });
        }
    };

    return runIncomingRequest(
        allocator,
        client,
        request_options,
        Adapter.call,
        @ptrCast(@constCast(handler_ctx)),
        run_options,
    );
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

/// Typed variant of `runIncomingRequestFromHeaders`.
pub fn runIncomingRequestFromHeadersTyped(
    allocator: std.mem.Allocator,
    client: *Client,
    request_options: RequestOptions,
    headers: []const PropagationHeader,
    comptime handler: anytype,
    handler_ctx: anytype,
    run_options: IncomingRunOptions,
) anyerror!u16 {
    const ContextType = @TypeOf(handler_ctx);
    comptime {
        assertSinglePointerContext(ContextType, "runIncomingRequestFromHeadersTyped");
        assertIncomingTypedHandler(@TypeOf(handler), ContextType, "runIncomingRequestFromHeadersTyped");
    }

    const Adapter = struct {
        fn call(request_context: *RequestContext, ctx: ?*anyopaque) anyerror!u16 {
            const typed_ctx: ContextType = @ptrCast(@alignCast(ctx.?));
            return @call(.auto, handler, .{ request_context, typed_ctx });
        }
    };

    return runIncomingRequestFromHeaders(
        allocator,
        client,
        request_options,
        headers,
        Adapter.call,
        @ptrCast(@constCast(handler_ctx)),
        run_options,
    );
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

/// Typed variant of `runOutgoingRequest`.
pub fn runOutgoingRequestTyped(
    request_options: OutgoingRequestOptions,
    comptime handler: anytype,
    handler_ctx: anytype,
    run_options: OutgoingRunOptions,
) anyerror!u16 {
    const ContextType = @TypeOf(handler_ctx);
    comptime {
        assertSinglePointerContext(ContextType, "runOutgoingRequestTyped");
        assertOutgoingTypedHandler(@TypeOf(handler), ContextType, "runOutgoingRequestTyped");
    }

    const Adapter = struct {
        fn call(request_context: *OutgoingRequestContext, ctx: ?*anyopaque) anyerror!u16 {
            const typed_ctx: ContextType = @ptrCast(@alignCast(ctx.?));
            return @call(.auto, handler, .{ request_context, typed_ctx });
        }
    };

    return runOutgoingRequest(
        request_options,
        Adapter.call,
        @ptrCast(@constCast(handler_ctx)),
        run_options,
    );
}

pub fn spanStatusFromHttpStatus(status_code: u16) SpanStatus {
    if (status_code == 401) return .unauthenticated;
    if (status_code == 403) return .permission_denied;
    if (status_code == 404) return .not_found;
    if (status_code == 409) return .already_exists;
    if (status_code == 429) return .resource_exhausted;
    if (status_code == 501) return .unimplemented;
    if (status_code == 503) return .unavailable;
    if (status_code >= 500 and status_code <= 599) return .internal_error;
    if (status_code >= 400 and status_code <= 499) return .invalid_argument;
    if (status_code >= 200 and status_code <= 399) return .ok;
    return .unknown;
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

test "OutgoingRequestContext traceParentHeaderAlloc produces valid w3c traceparent header" {
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
        .name = "GET /traceparent",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var out = try OutgoingRequestContext.begin(.{
        .method = "GET",
        .url = "https://downstream.example.com/traceparent",
    });
    defer out.deinit();

    const traceparent = try out.traceParentHeaderAlloc(testing.allocator);
    defer testing.allocator.free(traceparent);
    try testing.expect(std.mem.startsWith(u8, traceparent, "00-"));
    try testing.expect(std.mem.indexOf(u8, traceparent, txn.trace_id[0..]) != null);
    try testing.expect(std.mem.indexOf(u8, traceparent, out.span.span_id[0..]) != null);
}

test "OutgoingRequestContext propagationHeaderListWithTraceParentAlloc returns three headers" {
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
        .name = "GET /traceparent-list",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var out = try OutgoingRequestContext.begin(.{
        .method = "GET",
        .url = "https://downstream.example.com/traceparent-list",
    });
    defer out.deinit();

    var list = try out.propagationHeaderListWithTraceParentAlloc(testing.allocator);
    defer list.deinit(testing.allocator);

    const headers = list.slice();
    try testing.expectEqual(@as(usize, 3), headers.len);
    try testing.expectEqualStrings("sentry-trace", headers[0].name);
    try testing.expectEqualStrings("baggage", headers[1].name);
    try testing.expectEqualStrings("traceparent", headers[2].name);
    try testing.expect(std.mem.startsWith(u8, headers[2].value, "00-"));
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

fn incomingTypedHandler(context: *RequestContext, state: *IncomingHandlerSuccessState) anyerror!u16 {
    state.headers_seen = true;
    context.setTag("handler", "incoming-typed");
    return 206;
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

fn outgoingTypedHandler(context: *OutgoingRequestContext, state: *OutgoingHandlerSuccessState) anyerror!u16 {
    var headers = try context.propagationHeadersAlloc(testing.allocator);
    defer headers.deinit(testing.allocator);

    state.saw_trace_header = std.mem.indexOf(u8, headers.sentry_trace, "-") != null;
    state.saw_baggage_header = std.mem.indexOf(u8, headers.baggage, "sentry-trace_id=") != null;
    context.setTag("handler", "outgoing-typed");
    return 207;
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

test "runIncomingRequestTyped validates typed context and captures handler data" {
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
    const status_code = try runIncomingRequestTyped(
        testing.allocator,
        client,
        .{
            .name = "GET /pipeline-typed",
            .method = "GET",
            .url = "https://api.example.com/pipeline-typed",
        },
        incomingTypedHandler,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 206), status_code);
    try testing.expect(state.headers_seen);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") != null) {
            saw_transaction = true;
            try testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"GET /pipeline-typed\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":206") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"handler\":\"incoming-typed\"") != null);
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
        .{
            .name = "TrAcEpArEnT",
            .value = "00-0123456789abcdef0123456789abcdef-89abcdef01234567-01",
        },
    };

    const extracted = extractIncomingPropagationHeaders(&headers);
    try testing.expect(extracted.sentry_trace_header != null);
    try testing.expect(extracted.baggage_header != null);
    try testing.expect(extracted.traceparent_header != null);
    try testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
        extracted.sentry_trace_header.?,
    );
    try testing.expect(std.mem.indexOf(u8, extracted.baggage_header.?, "sentry-trace_id=") != null);
    try testing.expect(std.mem.startsWith(u8, extracted.traceparent_header.?, "00-"));
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

test "runIncomingRequestFromHeadersTyped continues trace using typed handler context" {
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
            .name = "traceparent",
            .value = "00-0123456789abcdef0123456789abcdef-89abcdef01234567-01",
        },
    };

    var state = IncomingHandlerSuccessState{};
    const status_code = try runIncomingRequestFromHeadersTyped(
        testing.allocator,
        client,
        .{
            .name = "GET /typed-headers",
            .method = "GET",
            .url = "https://api.example.com/typed-headers",
        },
        &headers,
        incomingTypedHandler,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 206), status_code);
    try testing.expect(state.headers_seen);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "0123456789abcdef0123456789abcdef") != null);
}

test "runIncomingRequestFromHeaders continues trace from traceparent when sentry-trace is missing" {
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
            .name = "traceparent",
            .value = "00-0123456789abcdef0123456789abcdef-89abcdef01234567-01",
        },
        .{
            .name = "baggage",
            .value = "sentry-trace_id=0123456789abcdef0123456789abcdef,sentry-sampled=true",
        },
    };

    var state = IncomingHandlerSuccessState{};
    const status_code = try runIncomingRequestFromHeaders(
        testing.allocator,
        client,
        .{
            .name = "GET /pipeline-traceparent",
            .method = "GET",
            .url = "https://api.example.com/pipeline-traceparent",
        },
        &headers,
        incomingHandlerSuccess,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 204), status_code);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "0123456789abcdef0123456789abcdef") != null);
}

test "runIncomingRequestFromHeaders accepts future traceparent versions" {
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
            .name = "traceparent",
            .value = "01-0123456789abcdef0123456789abcdef-89abcdef01234567-01-extra",
        },
    };

    var state = IncomingHandlerSuccessState{};
    const status_code = try runIncomingRequestFromHeaders(
        testing.allocator,
        client,
        .{
            .name = "GET /pipeline-traceparent-future",
            .method = "GET",
            .url = "https://api.example.com/pipeline-traceparent-future",
        },
        &headers,
        incomingHandlerSuccess,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 204), status_code);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "0123456789abcdef0123456789abcdef") != null);
}

test "RequestContext finish adds HTTP breadcrumb with request metadata" {
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

    var req = try RequestContext.begin(testing.allocator, client, .{
        .name = "GET /crumbs",
        .method = "GET",
        .url = "https://api.example.com/crumbs",
    });
    defer req.deinit();

    req.finish(503);
    _ = req.hub.captureMessageId("post-request event", .info);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 2);

    var saw_breadcrumb_message = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"event\"") != null and
            std.mem.indexOf(u8, payload, "GET https://api.example.com/crumbs -> 503") != null)
        {
            saw_breadcrumb_message = true;
        }
    }
    try testing.expect(saw_breadcrumb_message);
}

test "OutgoingRequestContext finish adds HTTP breadcrumb with request metadata" {
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
        .name = "GET /outgoing-crumb",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var out = try OutgoingRequestContext.begin(.{
        .method = "POST",
        .url = "https://payments.example.com/v1/charge",
    });
    defer out.deinit();

    out.finish(201);
    _ = hub.captureMessageId("after outgoing call", .info);

    hub.finishTransaction(&txn);
    hub.setSpan(null);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 2);

    var saw_breadcrumb_message = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"event\"") != null and
            std.mem.indexOf(u8, payload, "POST https://payments.example.com/v1/charge -> 201") != null)
        {
            saw_breadcrumb_message = true;
        }
    }
    try testing.expect(saw_breadcrumb_message);
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

test "runOutgoingRequestTyped auto-finishes span with typed handler context" {
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
        .name = "POST /checkout-typed",
        .op = "http.server",
    });
    defer txn.deinit();
    hub.setSpan(.{ .transaction = &txn });

    var state = OutgoingHandlerSuccessState{};
    const status_code = try runOutgoingRequestTyped(
        .{
            .method = "POST",
            .url = "https://payments.example.com/v1/charge-typed",
            .description = "POST payments charge typed",
        },
        outgoingTypedHandler,
        &state,
        .{},
    );
    try testing.expectEqual(@as(u16, 207), status_code);
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
            try testing.expect(std.mem.indexOf(u8, payload, "\"description\":\"POST payments charge typed\"") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"status_code\":207") != null);
            try testing.expect(std.mem.indexOf(u8, payload, "\"handler\":\"outgoing-typed\"") != null);
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
