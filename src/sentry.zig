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
pub const TransportConfig = @import("client.zig").TransportConfig;
pub const Integration = @import("client.zig").Integration;
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
pub const parseSentryTrace = @import("propagation.zig").parseSentryTrace;
pub const parseBaggage = @import("propagation.zig").parseBaggage;
pub const parseBaggageAlloc = @import("propagation.zig").parseBaggageAlloc;
pub const formatSentryTraceAlloc = @import("propagation.zig").formatSentryTraceAlloc;
pub const formatBaggageAlloc = @import("propagation.zig").formatBaggageAlloc;
pub const Uuid = @import("uuid.zig").Uuid;
pub const timestamp = @import("timestamp.zig");
pub const Worker = @import("worker.zig").Worker;
pub const RateLimitCategory = @import("ratelimit.zig").Category;
pub const RateLimitUpdate = @import("ratelimit.zig").Update;
pub const RateLimitState = @import("ratelimit.zig").State;
pub const signal_handler = @import("signal_handler.zig");

/// Initialize a new Sentry client with the given options.
pub fn init(allocator: std.mem.Allocator, options: Options) !*Client {
    return Client.init(allocator, options);
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

pub fn startTransactionFromSentryTrace(opts: TransactionOpts, sentry_trace_header: []const u8) ?Transaction {
    const hub = Hub.current() orelse return null;
    return hub.startTransactionFromSentryTrace(opts, sentry_trace_header) catch null;
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

pub fn addBreadcrumb(crumb: Breadcrumb) void {
    if (Hub.current()) |hub| {
        hub.addBreadcrumb(crumb);
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

pub fn withScope(callback: *const fn (*Hub) void) bool {
    const hub = Hub.current() orelse return false;
    hub.withScope(callback) catch return false;
    return true;
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

test "global wrappers are safe no-op without current hub" {
    try std.testing.expect(currentHub() == null);
    try std.testing.expect(captureMessage("no-hub", .info) == null);
    try std.testing.expect(captureException("TypeError", "no-hub") == null);
    try std.testing.expect(!captureLogMessage("no-hub", .info));
    try std.testing.expect(startTransaction(.{ .name = "no-hub" }) == null);
    try std.testing.expect(startTransactionFromSentryTrace(
        .{ .name = "no-hub" },
        "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
    ) == null);
    try std.testing.expect(startTransactionFromPropagationHeaders(
        .{ .name = "no-hub" },
        null,
        "sentry-trace_id=fedcba9876543210fedcba9876543210,sentry-sampled=false",
    ) == null);
    try std.testing.expect(!pushScope());
    try std.testing.expect(!popScope());
    try std.testing.expect(!configureScope(configureScopeSetInner));

    addBreadcrumb(.{ .message = "no-hub" });
    clearBreadcrumbs();
    try std.testing.expect(!withScope(withScopeSetTag));
}

test "global wrappers route through current hub" {
    const client = try Client.init(std.testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(std.testing.allocator, client);
    defer hub.deinit();
    defer _ = clearCurrentHub();

    _ = setCurrentHub(&hub);
    try std.testing.expect(currentHub().? == &hub);

    addBreadcrumb(.{ .message = "global-crumb" });
    try std.testing.expectEqual(@as(usize, 1), hub.currentScope().breadcrumbs.count);

    try std.testing.expect(pushScope());
    hub.setTag("scope", "inner");
    try std.testing.expect(popScope());
    try std.testing.expect(hub.currentScope().tags.get("scope") == null);

    try std.testing.expect(withScope(withScopeSetTag));
    try std.testing.expect(hub.currentScope().tags.get("scope") == null);

    try std.testing.expect(configureScope(configureScopeSetOuter));
    try std.testing.expectEqualStrings("scope1", hub.currentScope().tags.get("which_scope").?);

    const event_id = captureMessage("global-capture", .warning);
    try std.testing.expect(event_id != null);
    try std.testing.expectEqualSlices(u8, &event_id.?, &client.lastEventId().?);

    try std.testing.expect(captureLogMessage("global-log", .warn));

    var txn = startTransaction(.{ .name = "GET /global", .op = "http.server" }).?;
    defer txn.deinit();
    const tx_trace_header = sentryTraceHeader(&txn, std.testing.allocator).?;
    defer std.testing.allocator.free(tx_trace_header);
    const tx_baggage = baggageHeader(&txn, std.testing.allocator).?;
    defer std.testing.allocator.free(tx_baggage);
    try std.testing.expect(std.mem.indexOf(u8, tx_trace_header, txn.trace_id[0..]) != null);
    try std.testing.expect(std.mem.indexOf(u8, tx_baggage, "sentry-trace_id=") != null);
    try std.testing.expect(finishTransaction(&txn));

    var continued = startTransactionFromSentryTrace(
        .{ .name = "GET /continued-global", .op = "http.server" },
        "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
    ).?;
    defer continued.deinit();
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", continued.trace_id[0..]);

    var baggage_only = startTransactionFromPropagationHeaders(
        .{ .name = "GET /baggage-global", .op = "http.server" },
        null,
        "sentry-trace_id=fedcba9876543210fedcba9876543210,sentry-sampled=false",
    ).?;
    defer baggage_only.deinit();
    try std.testing.expectEqualStrings("fedcba9876543210fedcba9876543210", baggage_only.trace_id[0..]);
}

test {
    std.testing.refAllDecls(@This());
}
