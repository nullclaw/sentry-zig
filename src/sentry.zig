//! Sentry-Zig: Pure Zig Sentry SDK

const std = @import("std");
const builtin = @import("builtin");

comptime {
    const minimum = std.SemanticVersion{
        .major = 0,
        .minor = 15,
        .patch = 2,
    };
    if (builtin.zig_version.order(minimum) == .lt) {
        @compileError("sentry-zig requires Zig >= 0.15.2");
    }
}

pub const Client = @import("client.zig").Client;
pub const Options = @import("client.zig").Options;
pub const SessionMode = @import("client.zig").SessionMode;
pub const TracesSamplingContext = @import("client.zig").TracesSamplingContext;
pub const TracesSampler = @import("client.zig").TracesSampler;
pub const BeforeSendLog = @import("client.zig").BeforeSendLog;
pub const BeforeSendTransaction = @import("client.zig").BeforeSendTransaction;
pub const TransportConfig = @import("client.zig").TransportConfig;
pub const Integration = @import("client.zig").Integration;
pub const IntegrationSetupFn = @import("client.zig").IntegrationSetupFn;
pub const IntegrationLookupCallback = @import("client.zig").IntegrationLookupCallback;
pub const Event = @import("event.zig").Event;
pub const Level = @import("event.zig").Level;
pub const User = @import("event.zig").User;
pub const Breadcrumb = @import("event.zig").Breadcrumb;
pub const Frame = @import("event.zig").Frame;
pub const Stacktrace = @import("event.zig").Stacktrace;
pub const ExceptionValue = @import("event.zig").ExceptionValue;
pub const Message = @import("event.zig").Message;
pub const Attachment = @import("attachment.zig").Attachment;
pub const Transaction = @import("transaction.zig").Transaction;
pub const TransactionOpts = @import("transaction.zig").TransactionOpts;
pub const ChildSpanOpts = @import("transaction.zig").ChildSpanOpts;
pub const Span = @import("transaction.zig").Span;
pub const SpanStatus = @import("transaction.zig").SpanStatus;
pub const TransactionOrSpan = @import("transaction.zig").TransactionOrSpan;
pub const TraceContext = @import("transaction.zig").TraceContext;
pub const Request = @import("transaction.zig").Request;
pub const MAX_SPANS = @import("transaction.zig").MAX_SPANS;
pub const Session = @import("session.zig").Session;
pub const SessionStatus = @import("session.zig").SessionStatus;
pub const LogEntry = @import("log.zig").LogEntry;
pub const LogLevel = @import("log.zig").LogLevel;
pub const MonitorCheckIn = @import("monitor.zig").MonitorCheckIn;
pub const MonitorCheckInStatus = @import("monitor.zig").MonitorCheckInStatus;
pub const Dsn = @import("dsn.zig").Dsn;
pub const Scope = @import("scope.zig").Scope;
pub const EventProcessor = @import("scope.zig").EventProcessor;
pub const cleanupAppliedToEvent = @import("scope.zig").cleanupAppliedToEvent;
pub const Hub = @import("hub.zig").Hub;
pub const Transport = @import("transport.zig").Transport;
pub const MockTransport = @import("transport.zig").MockTransport;
pub const envelope = @import("envelope.zig");
pub const SentryTrace = @import("propagation.zig").SentryTrace;
pub const DynamicSamplingContext = @import("propagation.zig").DynamicSamplingContext;
pub const ParsedBaggage = @import("propagation.zig").ParsedBaggage;
pub const ParsedBaggageOwned = @import("propagation.zig").ParsedBaggageOwned;
pub const PropagationHeader = @import("propagation.zig").PropagationHeader;
pub const parseSentryTrace = @import("propagation.zig").parseSentryTrace;
pub const parseHeaders = @import("propagation.zig").parseHeaders;
pub const parseBaggage = @import("propagation.zig").parseBaggage;
pub const parseBaggageAlloc = @import("propagation.zig").parseBaggageAlloc;
pub const formatSentryTraceAlloc = @import("propagation.zig").formatSentryTraceAlloc;
pub const formatBaggageAlloc = @import("propagation.zig").formatBaggageAlloc;
pub const mergeBaggageAlloc = @import("propagation.zig").mergeBaggageAlloc;
pub const Uuid = @import("uuid.zig").Uuid;
pub const timestamp = @import("timestamp.zig");
pub const Worker = @import("worker.zig").Worker;
pub const RateLimitCategory = @import("ratelimit.zig").Category;
pub const RateLimitUpdate = @import("ratelimit.zig").Update;
pub const RateLimitState = @import("ratelimit.zig").State;
pub const signal_handler = @import("signal_handler.zig");
pub const integrations = @import("integrations.zig");
pub const testkit = @import("testkit.zig");
pub const @"test" = @import("testkit.zig");

/// Guard returned by `initGlobal`.
///
/// It owns the created `Client` and `Hub` and restores the previous thread-local
/// Hub when deinitialized.
pub const InitGuard = struct {
    allocator: std.mem.Allocator,
    client: *Client,
    hub: *Hub,
    previous_hub: ?*Hub,
    active: bool = true,

    pub fn clientPtr(self: *InitGuard) *Client {
        return self.client;
    }

    pub fn hubPtr(self: *InitGuard) *Hub {
        return self.hub;
    }

    pub fn deinit(self: *InitGuard) void {
        if (!self.active) return;
        self.active = false;

        if (Hub.current()) |current| {
            if (current == self.hub) {
                _ = Hub.clearCurrent();
                if (self.previous_hub) |previous| {
                    _ = Hub.setCurrent(previous);
                }
            }
        }

        self.hub.deinit();
        self.allocator.destroy(self.hub);
        self.client.deinit();
    }
};

/// Initialize a new Sentry client with the given options.
pub fn init(allocator: std.mem.Allocator, options: Options) !*Client {
    return Client.init(allocator, options);
}

/// Initialize a new client, create a Hub, and bind it as the current thread-local Hub.
///
/// Deinitialize the returned guard to restore the previous Hub and release resources.
pub fn initGlobal(allocator: std.mem.Allocator, options: Options) !InitGuard {
    const client = try init(allocator, options);
    errdefer client.deinit();

    const hub = try allocator.create(Hub);
    errdefer allocator.destroy(hub);

    hub.* = try Hub.init(allocator, client);
    errdefer hub.deinit();

    const previous_hub = Hub.setCurrent(hub);
    return .{
        .allocator = allocator,
        .client = client,
        .hub = hub,
        .previous_hub = previous_hub,
    };
}

pub fn setCurrentHub(hub: *Hub) ?*Hub {
    return Hub.setCurrent(hub);
}

pub fn currentHub() ?*Hub {
    return Hub.current();
}

pub fn clearCurrentHub() ?*Hub {
    return Hub.clearCurrent();
}

pub fn startTransaction(opts: TransactionOpts) ?Transaction {
    const hub = Hub.current() orelse return null;
    return hub.startTransaction(opts);
}

pub fn startTransactionWithTimestamp(opts: TransactionOpts, start_timestamp: f64) ?Transaction {
    const hub = Hub.current() orelse return null;
    return hub.startTransactionWithTimestamp(opts, start_timestamp);
}

pub fn startTransactionFromSentryTrace(opts: TransactionOpts, sentry_trace_header: []const u8) ?Transaction {
    const hub = Hub.current() orelse return null;
    return hub.startTransactionFromSentryTrace(opts, sentry_trace_header) catch null;
}

pub fn startTransactionFromHeaders(opts: TransactionOpts, headers: []const PropagationHeader) ?Transaction {
    const hub = Hub.current() orelse return null;
    return hub.startTransactionFromHeaders(opts, headers);
}

pub fn startTransactionFromSpan(opts: TransactionOpts, source: ?TransactionOrSpan) ?Transaction {
    const hub = Hub.current() orelse return null;
    return hub.startTransactionFromSpan(opts, source);
}

pub fn startTransactionFromPropagationHeaders(
    opts: TransactionOpts,
    sentry_trace_header: ?[]const u8,
    baggage_header: ?[]const u8,
) ?Transaction {
    const hub = Hub.current() orelse return null;
    return hub.startTransactionFromPropagationHeaders(opts, sentry_trace_header, baggage_header) catch null;
}

pub fn finishTransaction(txn: *Transaction) bool {
    const hub = Hub.current() orelse return false;
    hub.finishTransaction(txn);
    return true;
}

pub fn sentryTraceHeader(txn: *const Transaction, allocator: std.mem.Allocator) ?[]u8 {
    const hub = Hub.current() orelse return null;
    return hub.sentryTraceHeader(txn, allocator) catch null;
}

pub fn baggageHeader(txn: *const Transaction, allocator: std.mem.Allocator) ?[]u8 {
    const hub = Hub.current() orelse return null;
    return hub.baggageHeader(txn, allocator) catch null;
}

pub fn captureEvent(event: *Event) ?[32]u8 {
    const hub = Hub.current() orelse return null;
    return hub.captureEventId(event);
}

pub fn captureMessage(message: []const u8, level: Level) ?[32]u8 {
    const hub = Hub.current() orelse return null;
    return hub.captureMessageId(message, level);
}

pub fn captureException(exception_type: []const u8, value: []const u8) ?[32]u8 {
    const hub = Hub.current() orelse return null;
    return hub.captureExceptionId(exception_type, value);
}

pub fn captureError(err: anyerror) ?[32]u8 {
    const hub = Hub.current() orelse return null;
    return hub.captureErrorId(err);
}

pub fn captureLog(entry: *const LogEntry) bool {
    const hub = Hub.current() orelse return false;
    hub.captureLog(entry);
    return true;
}

pub fn captureLogMessage(message: []const u8, level: LogLevel) bool {
    const hub = Hub.current() orelse return false;
    hub.captureLogMessage(message, level);
    return true;
}

pub fn captureCheckIn(check_in: *const MonitorCheckIn) bool {
    const hub = Hub.current() orelse return false;
    hub.captureCheckIn(check_in);
    return true;
}

pub fn startSession() bool {
    const hub = Hub.current() orelse return false;
    hub.startSession();
    return true;
}

pub fn endSession(status: SessionStatus) bool {
    const hub = Hub.current() orelse return false;
    hub.endSession(status);
    return true;
}

pub fn flush(timeout_ms: u64) bool {
    const hub = Hub.current() orelse return false;
    return hub.flush(timeout_ms);
}

pub fn close(timeout_ms: ?u64) bool {
    const hub = Hub.current() orelse return false;
    return hub.close(timeout_ms);
}

pub fn lastEventId() ?[32]u8 {
    const hub = Hub.current() orelse return null;
    return hub.lastEventId();
}

pub fn addBreadcrumb(crumbs: anytype) void {
    if (Hub.current()) |hub| {
        hub.addBreadcrumb(crumbs);
    }
}

pub fn clearBreadcrumbs() void {
    if (Hub.current()) |hub| {
        hub.clearBreadcrumbs();
    }
}

pub fn pushScope() bool {
    const hub = Hub.current() orelse return false;
    hub.pushScope() catch return false;
    return true;
}

pub fn popScope() bool {
    const hub = Hub.current() orelse return false;
    return hub.popScope();
}

pub fn setSpan(source: ?TransactionOrSpan) bool {
    const hub = Hub.current() orelse return false;
    hub.setSpan(source);
    return true;
}

pub fn currentSpan() ?TransactionOrSpan {
    const hub = Hub.current() orelse return null;
    return hub.getSpan();
}

pub fn withScope(callback: *const fn (*Hub) void) bool {
    const hub = Hub.current() orelse return false;
    hub.withScope(callback) catch return false;
    return true;
}

pub fn withConfiguredScope(scope_config: *const fn (*Scope) void, callback: *const fn (*Hub) void) bool {
    const hub = Hub.current() orelse return false;
    hub.withConfiguredScope(scope_config, callback) catch return false;
    return true;
}

pub fn withIntegration(setup: IntegrationSetupFn, callback: IntegrationLookupCallback) bool {
    const hub = Hub.current() orelse {
        callback(null);
        return false;
    };
    return hub.withIntegration(setup, callback);
}

pub fn configureScope(callback: *const fn (*Scope) void) bool {
    const hub = Hub.current() orelse return false;
    hub.tryConfigureScope(callback) catch return false;
    return true;
}

fn withScopeSetTag(hub: *Hub) void {
    hub.setTag("scope", "inner");
}

fn configureScopeSetOuter(scope: *Scope) void {
    scope.setTag("which_scope", "scope1") catch {};
    _ = configureScope(configureScopeSetInner);
}

fn configureScopeSetInner(scope: *Scope) void {
    scope.setTag("which_scope", "scope2") catch {};
}

fn withConfiguredScopeSetTag(scope: *Scope) void {
    scope.setTag("scope", "configured") catch {};
}

var with_configured_scope_seen_match: bool = false;

fn observeConfiguredScopeTag(hub: *Hub) void {
    with_configured_scope_seen_match = false;
    const value = hub.currentScope().tags.get("scope") orelse return;
    with_configured_scope_seen_match = std.mem.eql(u8, value, "configured");
}

var global_integration_lookup_called: bool = false;
var global_integration_lookup_received_null: bool = false;
var global_integration_lookup_flag_value: ?bool = null;
var global_breadcrumb_factory_calls: usize = 0;

fn globalBreadcrumbFactory() Breadcrumb {
    global_breadcrumb_factory_calls += 1;
    return .{
        .category = "global",
        .message = "factory-breadcrumb",
        .level = .info,
    };
}

fn testGlobalIntegrationSetup(_: *Client, ctx: ?*anyopaque) void {
    if (ctx) |ptr| {
        const flag: *bool = @ptrCast(@alignCast(ptr));
        flag.* = true;
    }
}

fn inspectGlobalIntegrationLookup(ctx: ?*anyopaque) void {
    global_integration_lookup_called = true;
    global_integration_lookup_received_null = (ctx == null);
    if (ctx) |ptr| {
        const flag: *bool = @ptrCast(@alignCast(ptr));
        global_integration_lookup_flag_value = flag.*;
    } else {
        global_integration_lookup_flag_value = null;
    }
}

test "global wrappers are safe no-op without current hub" {
    global_integration_lookup_called = false;
    global_integration_lookup_received_null = false;
    global_integration_lookup_flag_value = null;
    global_breadcrumb_factory_calls = 0;

    try std.testing.expect(currentHub() == null);
    try std.testing.expect(captureMessage("no-hub", .info) == null);
    try std.testing.expect(captureException("TypeError", "no-hub") == null);
    try std.testing.expect(captureError(error.NoHubErrorParity) == null);
    try std.testing.expect(!captureLogMessage("no-hub", .info));
    var check_in = MonitorCheckIn.init("no-hub", .in_progress);
    try std.testing.expect(!captureCheckIn(&check_in));
    try std.testing.expect(startTransaction(.{ .name = "no-hub" }) == null);
    try std.testing.expect(startTransactionWithTimestamp(.{ .name = "no-hub" }, 1704067200.125) == null);
    try std.testing.expect(startTransactionFromSentryTrace(
        .{ .name = "no-hub" },
        "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
    ) == null);
    const no_hub_headers = [_]PropagationHeader{
        .{ .name = "sentry-trace", .value = "0123456789abcdef0123456789abcdef-89abcdef01234567-1" },
    };
    try std.testing.expect(startTransactionFromHeaders(.{ .name = "no-hub" }, &no_hub_headers) == null);
    try std.testing.expect(startTransactionFromSpan(.{ .name = "no-hub" }, null) == null);
    try std.testing.expect(startTransactionFromPropagationHeaders(
        .{ .name = "no-hub" },
        null,
        "sentry-trace_id=fedcba9876543210fedcba9876543210,sentry-sampled=false",
    ) == null);
    try std.testing.expect(currentSpan() == null);
    try std.testing.expect(!pushScope());
    try std.testing.expect(!popScope());
    try std.testing.expect(!setSpan(null));
    try std.testing.expect(!configureScope(configureScopeSetInner));
    try std.testing.expect(!withIntegration(testGlobalIntegrationSetup, inspectGlobalIntegrationLookup));
    try std.testing.expect(global_integration_lookup_called);
    try std.testing.expect(global_integration_lookup_received_null);
    try std.testing.expect(!startSession());
    try std.testing.expect(!endSession(.exited));
    try std.testing.expect(!flush(1));
    try std.testing.expect(!close(1));
    try std.testing.expect(lastEventId() == null);

    addBreadcrumb(.{ .message = "no-hub" });
    addBreadcrumb(globalBreadcrumbFactory);
    try std.testing.expectEqual(@as(usize, 0), global_breadcrumb_factory_calls);
    clearBreadcrumbs();
    try std.testing.expect(!withScope(withScopeSetTag));
    with_configured_scope_seen_match = false;
    try std.testing.expect(!withConfiguredScope(withConfiguredScopeSetTag, observeConfiguredScopeTag));
    try std.testing.expect(!with_configured_scope_seen_match);
}

test "global wrappers route through current hub" {
    var integration_flag = false;
    const integration = Integration{
        .setup = testGlobalIntegrationSetup,
        .ctx = &integration_flag,
    };
    const client = try Client.init(std.testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .integrations = &.{integration},
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(std.testing.allocator, client);
    defer hub.deinit();
    defer _ = clearCurrentHub();

    _ = setCurrentHub(&hub);
    try std.testing.expect(currentHub().? == &hub);
    global_breadcrumb_factory_calls = 0;

    addBreadcrumb(.{ .message = "global-crumb" });
    addBreadcrumb(globalBreadcrumbFactory);
    try std.testing.expectEqual(@as(usize, 1), global_breadcrumb_factory_calls);
    try std.testing.expectEqual(@as(usize, 2), hub.currentScope().breadcrumbs.count);

    try std.testing.expect(pushScope());
    hub.setTag("scope", "inner");
    try std.testing.expect(popScope());
    try std.testing.expect(hub.currentScope().tags.get("scope") == null);
    try std.testing.expect(setSpan(null));

    try std.testing.expect(withScope(withScopeSetTag));
    try std.testing.expect(hub.currentScope().tags.get("scope") == null);
    with_configured_scope_seen_match = false;
    try std.testing.expect(withConfiguredScope(withConfiguredScopeSetTag, observeConfiguredScopeTag));
    try std.testing.expect(with_configured_scope_seen_match);
    try std.testing.expect(hub.currentScope().tags.get("scope") == null);

    global_integration_lookup_called = false;
    global_integration_lookup_received_null = true;
    global_integration_lookup_flag_value = null;
    try std.testing.expect(withIntegration(testGlobalIntegrationSetup, inspectGlobalIntegrationLookup));
    try std.testing.expect(global_integration_lookup_called);
    try std.testing.expect(!global_integration_lookup_received_null);
    try std.testing.expectEqual(@as(?bool, true), global_integration_lookup_flag_value);

    try std.testing.expect(configureScope(configureScopeSetOuter));
    try std.testing.expectEqualStrings("scope1", hub.currentScope().tags.get("which_scope").?);

    const event_id = captureMessage("global-capture", .warning);
    try std.testing.expect(event_id != null);
    try std.testing.expectEqualSlices(u8, &event_id.?, &client.lastEventId().?);
    try std.testing.expectEqualSlices(u8, &event_id.?, &lastEventId().?);

    const error_event_id = captureError(error.GlobalErrorParity);
    try std.testing.expect(error_event_id != null);
    try std.testing.expectEqualSlices(u8, &error_event_id.?, &client.lastEventId().?);
    try std.testing.expectEqualSlices(u8, &error_event_id.?, &lastEventId().?);

    try std.testing.expect(captureLogMessage("global-log", .warn));
    var check_in = MonitorCheckIn.init("global-check-in", .in_progress);
    try std.testing.expect(captureCheckIn(&check_in));
    try std.testing.expect(startSession());
    try std.testing.expect(endSession(.exited));
    try std.testing.expect(flush(1000));

    var txn = startTransaction(.{ .name = "GET /global", .op = "http.server" }).?;
    defer txn.deinit();
    try std.testing.expect(setSpan(.{ .transaction = &txn }));
    try std.testing.expect(currentSpan() != null);
    const tx_trace_header = sentryTraceHeader(&txn, std.testing.allocator).?;
    defer std.testing.allocator.free(tx_trace_header);
    const tx_baggage = baggageHeader(&txn, std.testing.allocator).?;
    defer std.testing.allocator.free(tx_baggage);
    try std.testing.expect(std.mem.indexOf(u8, tx_trace_header, txn.trace_id[0..]) != null);
    try std.testing.expect(std.mem.indexOf(u8, tx_baggage, "sentry-trace_id=") != null);
    try std.testing.expect(setSpan(null));
    try std.testing.expect(currentSpan() == null);
    try std.testing.expect(finishTransaction(&txn));

    const explicit_start = 1704067200.125;
    var timed_txn = startTransactionWithTimestamp(
        .{ .name = "GET /global-timed", .op = "http.server" },
        explicit_start,
    ).?;
    defer timed_txn.deinit();
    try std.testing.expectEqual(explicit_start, timed_txn.start_timestamp);

    var continued = startTransactionFromSentryTrace(
        .{ .name = "GET /continued-global", .op = "http.server" },
        "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
    ).?;
    defer continued.deinit();
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", continued.trace_id[0..]);

    const headers = [_]PropagationHeader{
        .{ .name = "sentry-trace", .value = "fedcba9876543210fedcba9876543210-0123456789abcdef-0" },
    };
    var continued_from_headers = startTransactionFromHeaders(
        .{ .name = "GET /continued-global-headers", .op = "http.server" },
        &headers,
    ).?;
    defer continued_from_headers.deinit();
    try std.testing.expectEqualStrings("fedcba9876543210fedcba9876543210", continued_from_headers.trace_id[0..]);

    var continued_from_span = startTransactionFromSpan(
        .{ .name = "GET /continued-global-span", .op = "http.server" },
        .{ .transaction = &txn },
    ).?;
    defer continued_from_span.deinit();
    try std.testing.expectEqualStrings(txn.trace_id[0..], continued_from_span.trace_id[0..]);

    var baggage_only = startTransactionFromPropagationHeaders(
        .{ .name = "GET /baggage-global", .op = "http.server" },
        null,
        "sentry-trace_id=fedcba9876543210fedcba9876543210,sentry-sampled=false",
    ).?;
    defer baggage_only.deinit();
    try std.testing.expectEqualStrings("fedcba9876543210fedcba9876543210", baggage_only.trace_id[0..]);

    try std.testing.expect(close(1000));
    try std.testing.expect(captureLogMessage("global-log-after-close", .warn));
    try std.testing.expect(captureMessage("global-capture-after-close", .warning) == null);
}

test "initGlobal binds current hub and clears it on deinit" {
    try std.testing.expect(currentHub() == null);

    var guard = try initGlobal(std.testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    try std.testing.expect(currentHub() != null);
    try std.testing.expect(currentHub().? == guard.hubPtr());
    try std.testing.expect(captureMessage("init-global-message", .info) != null);

    guard.deinit();
    try std.testing.expect(currentHub() == null);
}

test "initGlobal restores previous hub on deinit" {
    const base_client = try Client.init(std.testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer base_client.deinit();

    var base_hub = try Hub.init(std.testing.allocator, base_client);
    defer base_hub.deinit();

    _ = setCurrentHub(&base_hub);
    defer _ = clearCurrentHub();

    var guard = try initGlobal(std.testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    try std.testing.expect(currentHub().? == guard.hubPtr());

    guard.deinit();
    try std.testing.expect(currentHub().? == &base_hub);
}

test {
    std.testing.refAllDecls(@This());
}
