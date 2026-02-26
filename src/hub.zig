const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;

const client_mod = @import("client.zig");
const Client = client_mod.Client;
const Integration = client_mod.Integration;
const IntegrationSetupFn = client_mod.IntegrationSetupFn;
const IntegrationLookupCallback = client_mod.IntegrationLookupCallback;
const SendOutcome = @import("worker.zig").SendOutcome;
const Transaction = @import("transaction.zig").Transaction;
const TransactionOpts = @import("transaction.zig").TransactionOpts;
const TransactionOrSpan = @import("transaction.zig").TransactionOrSpan;
const PropagationHeader = @import("propagation.zig").PropagationHeader;
const Event = @import("event.zig").Event;
const Level = @import("event.zig").Level;
const User = @import("event.zig").User;
const Breadcrumb = @import("event.zig").Breadcrumb;
const ExceptionValue = @import("event.zig").ExceptionValue;
const MonitorCheckIn = @import("monitor.zig").MonitorCheckIn;
const Scope = @import("scope.zig").Scope;
const scope_mod = @import("scope.zig");
const Attachment = @import("attachment.zig").Attachment;
const SessionStatus = @import("session.zig").SessionStatus;
const LogEntry = @import("log.zig").LogEntry;
const LogLevel = @import("log.zig").LogLevel;

threadlocal var current_hub_tls: ?*Hub = null;

/// Hub owns a stack of scopes and routes captures through its top scope.
pub const Hub = struct {
    allocator: Allocator,
    client: *Client,
    scopes: std.ArrayListUnmanaged(Scope) = .{},

    pub fn init(allocator: Allocator, client: *Client) !Hub {
        var hub: Hub = .{
            .allocator = allocator,
            .client = client,
        };
        errdefer hub.deinit();

        const base = try client.scope.clone(allocator);
        try hub.scopes.append(allocator, base);
        return hub;
    }

    pub fn deinit(self: *Hub) void {
        if (current_hub_tls == self) {
            current_hub_tls = null;
        }
        for (self.scopes.items) |*scope| {
            scope.deinit();
        }
        self.scopes.deinit(self.allocator);
        self.* = undefined;
    }

    fn topScope(self: *Hub) *Scope {
        std.debug.assert(self.scopes.items.len > 0);
        return &self.scopes.items[self.scopes.items.len - 1];
    }

    pub fn currentScope(self: *Hub) *Scope {
        return self.topScope();
    }

    pub fn pushScope(self: *Hub) !void {
        const cloned = try self.topScope().clone(self.allocator);
        errdefer {
            var owned = cloned;
            owned.deinit();
        }
        try self.scopes.append(self.allocator, cloned);
    }

    /// Pop the current scope. Returns false when trying to pop the base scope.
    pub fn popScope(self: *Hub) bool {
        if (self.scopes.items.len <= 1) return false;
        var popped = self.scopes.pop().?;
        popped.deinit();
        return true;
    }

    /// Run callback with a temporary pushed scope.
    pub fn withScope(self: *Hub, callback: *const fn (*Hub) void) !void {
        try self.pushScope();
        defer _ = self.popScope();
        callback(self);
    }

    /// Run callback with a temporary pushed scope configured before execution.
    pub fn withConfiguredScope(
        self: *Hub,
        scope_config: *const fn (*Scope) void,
        callback: *const fn (*Hub) void,
    ) !void {
        try self.pushScope();
        defer _ = self.popScope();
        scope_config(self.topScope());
        callback(self);
    }

    pub fn withIntegration(
        self: *Hub,
        setup: IntegrationSetupFn,
        callback: IntegrationLookupCallback,
    ) bool {
        return self.client.withIntegration(setup, callback);
    }

    /// Configure current scope by applying callback on a staged copy and
    /// committing atomically.
    pub fn configureScope(self: *Hub, callback: *const fn (*Scope) void) void {
        self.tryConfigureScope(callback) catch {};
    }

    /// Fallible variant of configureScope.
    pub fn tryConfigureScope(self: *Hub, callback: *const fn (*Scope) void) !void {
        var staged = try self.topScope().clone(self.allocator);
        errdefer staged.deinit();

        callback(&staged);

        var top = self.topScope();
        top.deinit();
        top.* = staged;
    }

    // ─── Scope Delegation ────────────────────────────────────────────────

    pub fn setUser(self: *Hub, user: User) void {
        self.topScope().setUser(user);
    }

    pub fn trySetUser(self: *Hub, user: User) !void {
        try self.topScope().trySetUser(user);
    }

    pub fn removeUser(self: *Hub) void {
        self.topScope().setUser(null);
    }

    pub fn setTag(self: *Hub, key: []const u8, value: []const u8) void {
        self.topScope().setTag(key, value) catch {};
    }

    pub fn trySetTag(self: *Hub, key: []const u8, value: []const u8) !void {
        try self.topScope().setTag(key, value);
    }

    pub fn removeTag(self: *Hub, key: []const u8) void {
        self.topScope().removeTag(key);
    }

    pub fn setExtra(self: *Hub, key: []const u8, value: json.Value) void {
        self.topScope().setExtra(key, value) catch {};
    }

    pub fn trySetExtra(self: *Hub, key: []const u8, value: json.Value) !void {
        try self.topScope().setExtra(key, value);
    }

    pub fn removeExtra(self: *Hub, key: []const u8) void {
        self.topScope().removeExtra(key);
    }

    pub fn setContext(self: *Hub, key: []const u8, value: json.Value) void {
        self.topScope().setContext(key, value) catch {};
    }

    pub fn trySetContext(self: *Hub, key: []const u8, value: json.Value) !void {
        try self.topScope().setContext(key, value);
    }

    pub fn removeContext(self: *Hub, key: []const u8) void {
        self.topScope().removeContext(key);
    }

    pub fn setLevel(self: *Hub, level: ?Level) void {
        self.topScope().setLevel(level);
    }

    pub fn setTransaction(self: *Hub, transaction: ?[]const u8) void {
        self.topScope().setTransaction(transaction) catch {};
    }

    pub fn trySetTransaction(self: *Hub, transaction: ?[]const u8) !void {
        try self.topScope().setTransaction(transaction);
    }

    /// Set or clear active span context for trace propagation on the top scope.
    pub fn setSpan(self: *Hub, source: ?TransactionOrSpan) void {
        self.topScope().setSpan(source);
    }

    pub fn getSpan(self: *Hub) ?TransactionOrSpan {
        return self.topScope().getSpan();
    }

    pub fn setFingerprint(self: *Hub, fingerprint: ?[]const []const u8) void {
        self.topScope().setFingerprint(fingerprint) catch {};
    }

    pub fn trySetFingerprint(self: *Hub, fingerprint: ?[]const []const u8) !void {
        try self.topScope().setFingerprint(fingerprint);
    }

    pub fn addBreadcrumb(self: *Hub, crumb: Breadcrumb) void {
        self.tryAddBreadcrumb(crumb) catch {};
    }

    pub fn tryAddBreadcrumb(self: *Hub, crumb: Breadcrumb) !void {
        if (self.client.options.before_breadcrumb) |before_breadcrumb| {
            if (before_breadcrumb(crumb)) |processed| {
                try self.topScope().tryAddBreadcrumb(processed);
            }
            return;
        }
        try self.topScope().tryAddBreadcrumb(crumb);
    }

    pub fn clearBreadcrumbs(self: *Hub) void {
        self.topScope().clearBreadcrumbs();
    }

    pub fn addAttachment(self: *Hub, attachment: Attachment) void {
        self.topScope().addAttachment(attachment);
    }

    pub fn tryAddAttachment(self: *Hub, attachment: Attachment) !void {
        try self.topScope().tryAddAttachment(attachment);
    }

    pub fn clearAttachments(self: *Hub) void {
        self.topScope().clearAttachments();
    }

    pub fn addEventProcessor(self: *Hub, processor: scope_mod.EventProcessor) void {
        self.topScope().addEventProcessor(processor) catch {};
    }

    pub fn tryAddEventProcessor(self: *Hub, processor: scope_mod.EventProcessor) !void {
        try self.topScope().addEventProcessor(processor);
    }

    pub fn clearEventProcessors(self: *Hub) void {
        self.topScope().clearEventProcessors();
    }

    // ─── Capture ─────────────────────────────────────────────────────────

    pub fn captureEvent(self: *Hub, event: *Event) void {
        _ = self.captureEventId(event);
    }

    pub fn captureEventId(self: *Hub, event: *Event) ?[32]u8 {
        return self.client.captureEventIdWithScope(event, self.topScope());
    }

    pub fn captureMessage(self: *Hub, message: []const u8, level: Level) void {
        _ = self.captureMessageId(message, level);
    }

    pub fn captureMessageId(self: *Hub, message: []const u8, level: Level) ?[32]u8 {
        var event = Event.initMessage(message, level);
        return self.captureEventId(&event);
    }

    pub fn captureException(self: *Hub, exception_type: []const u8, value: []const u8) void {
        _ = self.captureExceptionId(exception_type, value);
    }

    pub fn captureExceptionId(self: *Hub, exception_type: []const u8, value: []const u8) ?[32]u8 {
        const values = [_]ExceptionValue{.{
            .type = exception_type,
            .value = value,
        }};
        var event = Event.initException(&values);
        return self.captureEventId(&event);
    }

    pub fn captureCheckIn(self: *Hub, check_in: *const MonitorCheckIn) void {
        self.client.captureCheckIn(check_in);
    }

    pub fn captureLog(self: *Hub, entry: *const LogEntry) void {
        self.client.captureLogWithScope(entry, self.topScope());
    }

    pub fn captureLogMessage(self: *Hub, message: []const u8, level: LogLevel) void {
        self.client.captureLogMessageWithScope(message, level, self.topScope());
    }

    // ─── Client Delegation ───────────────────────────────────────────────

    pub fn startTransaction(self: *Hub, opts: TransactionOpts) Transaction {
        return self.client.startTransaction(opts);
    }

    pub fn startTransactionWithTimestamp(
        self: *Hub,
        opts: TransactionOpts,
        start_timestamp: f64,
    ) Transaction {
        return self.client.startTransactionWithTimestamp(opts, start_timestamp);
    }

    pub fn startTransactionFromSentryTrace(
        self: *Hub,
        opts: TransactionOpts,
        sentry_trace_header: []const u8,
    ) !Transaction {
        return self.client.startTransactionFromSentryTrace(opts, sentry_trace_header);
    }

    pub fn startTransactionFromPropagationHeaders(
        self: *Hub,
        opts: TransactionOpts,
        sentry_trace_header: ?[]const u8,
        baggage_header: ?[]const u8,
    ) !Transaction {
        return self.client.startTransactionFromPropagationHeaders(
            opts,
            sentry_trace_header,
            baggage_header,
        );
    }

    pub fn startTransactionFromHeaders(self: *Hub, opts: TransactionOpts, headers: []const PropagationHeader) Transaction {
        return self.client.startTransactionFromHeaders(opts, headers);
    }

    pub fn startTransactionFromSpan(
        self: *Hub,
        opts: TransactionOpts,
        source: ?TransactionOrSpan,
    ) Transaction {
        return self.client.startTransactionFromSpan(opts, source);
    }

    pub fn finishTransaction(self: *Hub, txn: *Transaction) void {
        self.client.finishTransactionWithScope(txn, self.topScope());
    }

    pub fn sentryTraceHeader(self: *Hub, txn: *const Transaction, allocator: Allocator) ![]u8 {
        return self.client.sentryTraceHeader(txn, allocator);
    }

    pub fn baggageHeader(self: *Hub, txn: *const Transaction, allocator: Allocator) ![]u8 {
        return self.client.baggageHeader(txn, allocator);
    }

    pub fn startSession(self: *Hub) void {
        self.client.startSession();
    }

    pub fn endSession(self: *Hub, status: SessionStatus) void {
        self.client.endSession(status);
    }

    pub fn isEnabled(self: *Hub) bool {
        return self.client.isEnabled();
    }

    pub fn flush(self: *Hub, timeout_ms: u64) bool {
        return self.client.flush(timeout_ms);
    }

    pub fn close(self: *Hub, timeout_ms: ?u64) bool {
        return self.client.close(timeout_ms);
    }

    pub fn lastEventId(self: *Hub) ?[32]u8 {
        return self.client.lastEventId();
    }

    // ─── TLS Current Hub ────────────────────────────────────────────────

    pub fn setCurrent(hub: *Hub) ?*Hub {
        const previous = current_hub_tls;
        current_hub_tls = hub;
        return previous;
    }

    pub fn clearCurrent() ?*Hub {
        const previous = current_hub_tls;
        current_hub_tls = null;
        return previous;
    }

    pub fn current() ?*Hub {
        return current_hub_tls;
    }
};

fn dropEvent(_: *Event) bool {
    return false;
}

fn dropBreadcrumb(_: Breadcrumb) ?Breadcrumb {
    return null;
}

fn withScopeMutateTag(hub: *Hub) void {
    hub.setTag("scope", "inner");
}

fn withConfiguredScopeSetTag(scope: *Scope) void {
    scope.setTag("scope", "configured-temp") catch {};
}

var with_configured_scope_observed_match: bool = false;

fn withConfiguredScopeObserveTag(hub: *Hub) void {
    with_configured_scope_observed_match = false;
    const value = hub.currentScope().tags.get("scope") orelse return;
    with_configured_scope_observed_match = std.mem.eql(u8, value, "configured-temp");
}

fn withScopeCaptureAttachment(hub: *Hub) void {
    var attachment = Attachment.initOwned(
        testing.allocator,
        "with-scope.txt",
        "scope-attachment",
        "text/plain",
        null,
    ) catch return;
    defer attachment.deinit(testing.allocator);

    hub.addAttachment(attachment);
    _ = hub.captureMessageId("with-scope message", .err);
}

fn configureScopeSetTag(scope: *Scope) void {
    scope.setTag("scope", "configured") catch {};
}

fn configureScopeReentrantInner(scope: *Scope) void {
    scope.setTag("which_scope", "inner") catch {};
}

fn configureScopeReentrantOuter(scope: *Scope) void {
    scope.setTag("which_scope", "outer") catch {};
    if (Hub.current()) |hub| {
        hub.configureScope(configureScopeReentrantInner);
    }
}

var hub_integration_lookup_called: bool = false;
var hub_integration_lookup_received_null: bool = false;
var hub_integration_lookup_flag_value: ?bool = null;

fn hubIntegrationSetup(_: *Client, ctx: ?*anyopaque) void {
    if (ctx) |ptr| {
        const flag: *bool = @ptrCast(@alignCast(ptr));
        flag.* = true;
    }
}

fn inspectHubIntegrationLookup(ctx: ?*anyopaque) void {
    hub_integration_lookup_called = true;
    hub_integration_lookup_received_null = (ctx == null);
    if (ctx) |ptr| {
        const flag: *bool = @ptrCast(@alignCast(ptr));
        hub_integration_lookup_flag_value = flag.*;
    } else {
        hub_integration_lookup_flag_value = null;
    }
}

fn otherHubIntegrationSetup(_: *Client, _: ?*anyopaque) void {}

const HubPayloadTransportState = struct {
    allocator: Allocator,
    sent_count: usize = 0,
    last_payload: ?[]u8 = null,

    fn init(allocator: Allocator) HubPayloadTransportState {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *HubPayloadTransportState) void {
        if (self.last_payload) |payload| self.allocator.free(payload);
        self.* = undefined;
    }
};

fn hubPayloadTransportSendFn(data: []const u8, ctx: ?*anyopaque) SendOutcome {
    const state: *HubPayloadTransportState = @ptrCast(@alignCast(ctx.?));
    state.sent_count += 1;
    if (state.last_payload) |payload| state.allocator.free(payload);
    state.last_payload = state.allocator.dupe(u8, data) catch null;
    return .{};
}

test "Hub push/pop scope isolates mutations" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    try hub.trySetTag("scope", "outer");
    try testing.expectEqualStrings("outer", hub.currentScope().tags.get("scope").?);

    try hub.pushScope();
    try hub.trySetTag("scope", "inner");
    try testing.expectEqualStrings("inner", hub.currentScope().tags.get("scope").?);

    try testing.expect(hub.popScope());
    try testing.expectEqualStrings("outer", hub.currentScope().tags.get("scope").?);
    try testing.expect(!hub.popScope());
}

test "Hub capture uses hub scope stack data" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    try hub.tryAddEventProcessor(dropEvent);

    try testing.expect(hub.captureMessageId("dropped-by-hub-scope", .err) == null);
    try testing.expect(client.captureMessageId("accepted-by-client-scope", .err) != null);
}

test "Hub addBreadcrumb applies client before_breadcrumb callback" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_breadcrumb = dropBreadcrumb,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    hub.addBreadcrumb(.{ .message = "should-drop" });
    try testing.expectEqual(@as(usize, 0), hub.currentScope().breadcrumbs.count);
}

test "Hub clearBreadcrumbs clears only current scope breadcrumbs" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    hub.addBreadcrumb(.{ .message = "crumb-1" });
    hub.addBreadcrumb(.{ .message = "crumb-2" });
    try testing.expectEqual(@as(usize, 2), hub.currentScope().breadcrumbs.count);

    hub.clearBreadcrumbs();
    try testing.expectEqual(@as(usize, 0), hub.currentScope().breadcrumbs.count);
}

test "Hub withScope auto pops temporary scope" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    try hub.trySetTag("scope", "outer");
    try hub.withScope(withScopeMutateTag);
    try testing.expectEqualStrings("outer", hub.currentScope().tags.get("scope").?);
}

test "Hub withConfiguredScope applies temporary scope configuration" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    with_configured_scope_observed_match = false;
    try hub.trySetTag("scope", "outer");
    try hub.withConfiguredScope(withConfiguredScopeSetTag, withConfiguredScopeObserveTag);

    try testing.expect(with_configured_scope_observed_match);
    try testing.expectEqualStrings("outer", hub.currentScope().tags.get("scope").?);
}

test "Hub withScope sends scoped attachment and does not leak it to parent scope" {
    var state = HubPayloadTransportState.init(testing.allocator);
    defer state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .transport = .{
            .send_fn = hubPayloadTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    try testing.expectEqual(@as(usize, 0), hub.currentScope().attachments.items.len);

    try hub.withScope(withScopeCaptureAttachment);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 1), state.sent_count);
    try testing.expect(state.last_payload != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"type\":\"attachment\"") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"filename\":\"with-scope.txt\"") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "scope-attachment") != null);

    try testing.expectEqual(@as(usize, 0), hub.currentScope().attachments.items.len);
}

test "Hub configureScope applies staged mutation to current scope" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    try hub.trySetTag("scope", "outer");
    hub.configureScope(configureScopeSetTag);
    try testing.expectEqualStrings("configured", hub.currentScope().tags.get("scope").?);
}

test "Hub configureScope supports reentrant calls and keeps outer mutation" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    const previous_hub = Hub.setCurrent(&hub);
    defer {
        if (previous_hub) |prev| {
            _ = Hub.setCurrent(prev);
        } else {
            _ = Hub.clearCurrent();
        }
    }

    hub.configureScope(configureScopeReentrantOuter);
    try testing.expectEqualStrings("outer", hub.currentScope().tags.get("which_scope").?);
}

test "Hub withIntegration returns configured integration context" {
    hub_integration_lookup_called = false;
    hub_integration_lookup_received_null = false;
    hub_integration_lookup_flag_value = null;

    var integration_flag = false;
    const integration = Integration{
        .setup = hubIntegrationSetup,
        .ctx = &integration_flag,
    };
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .integrations = &.{integration},
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    try testing.expect(hub.withIntegration(hubIntegrationSetup, inspectHubIntegrationLookup));
    try testing.expect(hub_integration_lookup_called);
    try testing.expect(!hub_integration_lookup_received_null);
    try testing.expectEqual(@as(?bool, true), hub_integration_lookup_flag_value);
}

test "Hub withIntegration reports missing integration as null" {
    hub_integration_lookup_called = false;
    hub_integration_lookup_received_null = false;
    hub_integration_lookup_flag_value = null;

    const integration = Integration{
        .setup = hubIntegrationSetup,
        .ctx = null,
    };
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .integrations = &.{integration},
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    try testing.expect(!hub.withIntegration(otherHubIntegrationSetup, inspectHubIntegrationLookup));
    try testing.expect(hub_integration_lookup_called);
    try testing.expect(hub_integration_lookup_received_null);
    try testing.expectEqual(@as(?bool, null), hub_integration_lookup_flag_value);
}

test "Hub startTransactionFromPropagationHeaders continues upstream trace" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    var txn = try hub.startTransactionFromPropagationHeaders(
        .{ .name = "GET /hub-propagation" },
        "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
        null,
    );
    defer txn.deinit();

    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", txn.trace_id[0..]);
    try testing.expect(txn.parent_span_id != null);
    try testing.expectEqualStrings("89abcdef01234567", txn.parent_span_id.?[0..]);
}

test "Hub startTransactionFromHeaders continues upstream trace" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    const headers = [_]PropagationHeader{
        .{ .name = "sentry-trace", .value = "0123456789abcdef0123456789abcdef-89abcdef01234567-1" },
    };
    var txn = hub.startTransactionFromHeaders(.{ .name = "GET /hub-headers" }, &headers);
    defer txn.deinit();

    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", txn.trace_id[0..]);
    try testing.expect(txn.parent_span_id != null);
    try testing.expectEqualStrings("89abcdef01234567", txn.parent_span_id.?[0..]);
}

test "Hub startTransactionFromSpan continues from transaction context" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    var parent = hub.startTransaction(.{
        .name = "GET /parent",
        .op = "http.server",
    });
    defer parent.deinit();

    var child = hub.startTransactionFromSpan(.{
        .name = "GET /continued",
        .op = "http.server",
    }, .{ .transaction = &parent });
    defer child.deinit();

    try testing.expectEqualStrings(parent.trace_id[0..], child.trace_id[0..]);
    try testing.expect(child.parent_span_id != null);
    try testing.expectEqualStrings(parent.span_id[0..], child.parent_span_id.?[0..]);
}

test "Hub startTransactionWithTimestamp applies explicit start timestamp" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    const explicit_start = 1704067200.125;
    var txn = hub.startTransactionWithTimestamp(.{
        .name = "GET /hub-start",
        .op = "http.server",
    }, explicit_start);
    defer txn.deinit();

    try testing.expectEqual(explicit_start, txn.start_timestamp);
}

test "Hub setSpan propagates trace context to captured logs" {
    var state = HubPayloadTransportState.init(testing.allocator);
    defer state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .transport = .{
            .send_fn = hubPayloadTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    var txn = hub.startTransaction(.{
        .name = "GET /hub-span-log",
        .op = "http.server",
    });
    defer txn.deinit();

    hub.setSpan(.{ .transaction = &txn });
    try testing.expect(hub.getSpan() != null);
    hub.captureLogMessage("hub-span-log", .info);
    hub.setSpan(null);
    try testing.expect(hub.getSpan() == null);
    _ = client.flush(1000);

    const expected_trace = try std.fmt.allocPrint(testing.allocator, "\"trace_id\":\"{s}\"", .{txn.trace_id[0..]});
    defer testing.allocator.free(expected_trace);

    try testing.expectEqual(@as(usize, 1), state.sent_count);
    try testing.expect(state.last_payload != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"type\":\"log\"") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, expected_trace) != null);
}

test "Hub finishTransaction applies top scope transaction metadata" {
    var state = HubPayloadTransportState.init(testing.allocator);
    defer state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .transport = .{
            .send_fn = hubPayloadTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    try client.trySetTag("client-only-tag", "client");
    try client.trySetExtra("client-only-extra", .{ .integer = 11 });
    try client.trySetContext("client-only-context", .{ .integer = 12 });
    try client.trySetTransaction("client-name");

    try hub.trySetTag("hub-tag", "hub");
    try hub.trySetExtra("hub-extra", .{ .integer = 21 });
    try hub.trySetContext("hub-context", .{ .integer = 22 });
    try hub.trySetTransaction("hub-name");

    var txn = hub.startTransaction(.{
        .name = "POST /hub-finish-scope",
        .op = "http.server",
    });
    defer txn.deinit();
    try txn.setRequest(.{
        .method = "GET",
        .url = "https://honk.beep",
    });

    hub.finishTransaction(&txn);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 1), state.sent_count);
    try testing.expect(state.last_payload != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"hub-tag\":\"hub\"") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"hub-extra\":21") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"hub-context\":22") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"transaction\":\"hub-name\"") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"url\":\"https://honk.beep\"") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"client-only-tag\":\"client\"") == null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"client-only-extra\":11") == null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"client-only-context\":12") == null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"transaction\":\"client-name\"") == null);
}

test "Hub TLS current set and clear" {
    try testing.expect(Hub.current() == null);

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();
    defer _ = Hub.clearCurrent();

    try testing.expect(Hub.setCurrent(&hub) == null);
    try testing.expect(Hub.current().? == &hub);
    try testing.expect(Hub.clearCurrent().? == &hub);
    try testing.expect(Hub.current() == null);
}

test "Hub deinit clears TLS current pointer for the same hub" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);

    _ = Hub.setCurrent(&hub);
    hub.deinit();

    try testing.expect(Hub.current() == null);
}
