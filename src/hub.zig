const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;

const client_mod = @import("client.zig");
const Client = client_mod.Client;
const Transaction = @import("transaction.zig").Transaction;
const TransactionOpts = @import("transaction.zig").TransactionOpts;
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
        self.client.captureLog(entry);
    }

    pub fn captureLogMessage(self: *Hub, message: []const u8, level: LogLevel) void {
        self.client.captureLogMessage(message, level);
    }

    // ─── Client Delegation ───────────────────────────────────────────────

    pub fn startTransaction(self: *Hub, opts: TransactionOpts) Transaction {
        return self.client.startTransaction(opts);
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

    pub fn finishTransaction(self: *Hub, txn: *Transaction) void {
        self.client.finishTransaction(txn);
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

fn configureScopeSetTag(scope: *Scope) void {
    scope.setTag("scope", "configured") catch {};
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
