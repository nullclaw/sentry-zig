const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;
const Writer = std.io.Writer;

const Dsn = @import("dsn.zig").Dsn;
const Attachment = @import("attachment.zig").Attachment;
const event_mod = @import("event.zig");
const Event = event_mod.Event;
const Level = event_mod.Level;
const User = event_mod.User;
const Breadcrumb = event_mod.Breadcrumb;
const ExceptionValue = event_mod.ExceptionValue;
const ExceptionInterface = event_mod.ExceptionInterface;
const Message = event_mod.Message;
const scope_mod = @import("scope.zig");
const Scope = scope_mod.Scope;
const Session = @import("session.zig").Session;
const SessionStatus = @import("session.zig").SessionStatus;
const Transport = @import("transport.zig").Transport;
const Worker = @import("worker.zig").Worker;
const SendOutcome = @import("worker.zig").SendOutcome;
const signal_handler = @import("signal_handler.zig");
const envelope = @import("envelope.zig");
const MonitorCheckIn = @import("monitor.zig").MonitorCheckIn;
const txn_mod = @import("transaction.zig");
const Transaction = txn_mod.Transaction;
const TransactionOpts = txn_mod.TransactionOpts;

pub const SessionMode = enum {
    application,
    request,
};

pub const TracesSamplingContext = struct {
    transaction_name: []const u8,
    transaction_op: ?[]const u8 = null,
    parent_sampled: ?bool = null,
};

pub const TracesSampler = *const fn (TracesSamplingContext) f64;

/// Configuration options for the Sentry client.
pub const Options = struct {
    dsn: []const u8,
    debug: bool = false,
    release: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    sample_rate: f64 = 1.0,
    traces_sample_rate: f64 = 0.0,
    traces_sampler: ?TracesSampler = null,
    max_breadcrumbs: u32 = 100,
    attach_stacktrace: bool = false,
    send_default_pii: bool = false,
    before_send: ?*const fn (*Event) ?*Event = null, // return same pointer, or null to drop
    before_breadcrumb: ?*const fn (Breadcrumb) ?Breadcrumb = null, // return null to drop
    cache_dir: []const u8 = "/tmp/sentry-zig",
    user_agent: []const u8 = "sentry-zig/0.1.0",
    install_signal_handlers: bool = true,
    auto_session_tracking: bool = false,
    session_mode: SessionMode = .application,
    shutdown_timeout_ms: u64 = 2000,
};

/// The Sentry client, tying together DSN, Scope, Transport, Worker, and Session.
/// Heap-allocated via `init` to avoid self-referential pointer issues.
pub const Client = struct {
    allocator: Allocator,
    dsn: Dsn,
    options: Options,
    scope: Scope,
    transport: Transport,
    worker: Worker,
    session: ?Session = null,
    last_event_id: ?[32]u8 = null,
    mutex: std.Thread.Mutex = .{},

    /// Initialize a new Client. Heap-allocates the Client struct so that
    /// internal pointers (e.g., the Worker's send_ctx) remain stable.
    pub fn init(allocator: Allocator, options: Options) !*Client {
        if (!isValidSampleRate(options.sample_rate)) return error.InvalidSampleRate;
        if (!isValidSampleRate(options.traces_sample_rate)) return error.InvalidTracesSampleRate;

        const self = try allocator.create(Client);
        errdefer allocator.destroy(self);

        const dsn = Dsn.parse(options.dsn) catch return error.InvalidDsn;

        var transport = try Transport.init(allocator, dsn, options.user_agent);
        errdefer transport.deinit();

        var scope = try Scope.init(allocator, options.max_breadcrumbs);
        errdefer scope.deinit();

        self.* = Client{
            .allocator = allocator,
            .dsn = dsn,
            .options = options,
            .scope = scope,
            .transport = transport,
            .worker = Worker.init(allocator, transportSendCallback, @ptrCast(self)),
            .session = null,
            .last_event_id = null,
        };

        try self.worker.start();

        std.fs.cwd().makePath(options.cache_dir) catch {};

        // Install signal handlers if requested
        if (options.install_signal_handlers) {
            signal_handler.install(options.cache_dir);
        }

        // Check for pending crash from previous run
        if (signal_handler.checkPendingCrash(allocator, options.cache_dir)) |signal_num| {
            self.captureCrashEvent(signal_num);
        }

        if (options.auto_session_tracking) {
            self.startSession();
        }

        return self;
    }

    /// Shut down the client, flushing pending events and freeing resources.
    pub fn deinit(self: *Client) void {
        _ = self.close(null);
        self.worker.deinit();

        // Uninstall signal handlers
        if (self.options.install_signal_handlers) {
            signal_handler.uninstall();
        }

        self.transport.deinit();
        self.scope.deinit();

        const allocator = self.allocator;
        allocator.destroy(self);
    }

    // ─── Capture Methods ─────────────────────────────────────────────────

    /// Capture a simple message event at the given level.
    pub fn captureMessage(self: *Client, message: []const u8, level: Level) void {
        _ = self.captureMessageId(message, level);
    }

    /// Capture a simple message event and return its id if accepted.
    pub fn captureMessageId(self: *Client, message: []const u8, level: Level) ?[32]u8 {
        var event = Event.initMessage(message, level);
        return self.captureEventId(&event);
    }

    /// Capture an exception event.
    pub fn captureException(self: *Client, exception_type: []const u8, value: []const u8) void {
        _ = self.captureExceptionId(exception_type, value);
    }

    /// Capture an exception event and return its id if accepted.
    pub fn captureExceptionId(self: *Client, exception_type: []const u8, value: []const u8) ?[32]u8 {
        const values = [_]ExceptionValue{.{
            .type = exception_type,
            .value = value,
        }};
        var event = Event.initException(&values);
        return self.captureEventId(&event);
    }

    /// Capture a monitor check-in envelope.
    pub fn captureCheckIn(self: *Client, check_in: *const MonitorCheckIn) void {
        if (!self.isEnabled()) return;

        var prepared = check_in.*;
        if (prepared.environment == null) {
            prepared.environment = self.options.environment;
        }

        const check_in_json = prepared.toJson(self.allocator) catch return;
        defer self.allocator.free(check_in_json);

        const data = self.serializeCheckInEnvelope(check_in_json) catch return;
        self.worker.submit(data, .any) catch {
            self.allocator.free(data);
        };
    }

    /// Core method: apply defaults, sample, apply scope, run before_send,
    /// serialize to envelope, and submit to the worker queue.
    pub fn captureEvent(self: *Client, event: *Event) void {
        _ = self.captureEventId(event);
    }

    /// Capture an event and return its id if accepted by filters/sampling.
    pub fn captureEventId(self: *Client, event: *Event) ?[32]u8 {
        if (!self.isEnabled()) return null;

        var prepared_event_value = event.*;

        // Apply defaults from options
        if (self.options.release) |release| {
            if (prepared_event_value.release == null) prepared_event_value.release = release;
        }
        if (self.options.environment) |env| {
            if (prepared_event_value.environment == null) prepared_event_value.environment = env;
        }
        if (self.options.server_name) |sn| {
            if (prepared_event_value.server_name == null) prepared_event_value.server_name = sn;
        }

        // Apply scope to event
        const applied = self.scope.applyToEvent(self.allocator, &prepared_event_value) catch return null;
        defer scope_mod.cleanupAppliedToEvent(self.allocator, &prepared_event_value, applied);

        const prepared_event: *Event = &prepared_event_value;

        // Run before_send callback
        if (self.options.before_send) |before_send| {
            if (before_send(prepared_event)) |processed_event| {
                // For memory safety, callbacks must mutate in place and return
                // the same pointer (or null to drop the event).
                if (processed_event != prepared_event) return null;
            } else {
                return null;
            }
        }

        // Update session based on the prepared event before applying sampling.
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.session) |*s| {
                if (prepared_event.level) |level| {
                    if (level == .err or level == .fatal) {
                        s.markErrored();
                    }
                }
                if (s.dirty) {
                    _ = self.sendSessionUpdate(s);
                }
            }
        }

        // Sample rate check
        if (self.options.sample_rate < 1.0) {
            const rand_val = std.crypto.random.float(f64);
            if (rand_val >= self.options.sample_rate) return null;
        }

        const attachments = self.scope.snapshotAttachments(self.allocator) catch return null;
        defer scope_mod.deinitAttachmentSlice(self.allocator, attachments);

        // Serialize event to envelope
        const data = self.serializeEventEnvelope(prepared_event, attachments) catch return null;

        // Envelope contains an error event item (and optionally attachments),
        // so it must obey error-category rate limits.
        self.worker.submit(data, .@"error") catch {
            self.allocator.free(data);
            return null;
        };

        self.mutex.lock();
        self.last_event_id = prepared_event.event_id;
        const accepted_id = self.last_event_id.?;
        self.mutex.unlock();

        return accepted_id;
    }

    // ─── Scope Delegation ────────────────────────────────────────────────

    /// Set the user context.
    pub fn setUser(self: *Client, user: User) void {
        self.scope.setUser(user);
    }

    /// Remove the user context.
    pub fn removeUser(self: *Client) void {
        self.scope.setUser(null);
    }

    /// Set a tag.
    pub fn setTag(self: *Client, key: []const u8, value: []const u8) void {
        self.scope.setTag(key, value) catch {};
    }

    /// Set the default level for events in the current scope.
    pub fn setLevel(self: *Client, level: ?Level) void {
        self.scope.setLevel(level);
    }

    /// Set transaction name override on scope.
    pub fn setTransaction(self: *Client, transaction: ?[]const u8) void {
        self.scope.setTransaction(transaction) catch {};
    }

    /// Set fingerprint override on scope.
    pub fn setFingerprint(self: *Client, fingerprint: ?[]const []const u8) void {
        self.scope.setFingerprint(fingerprint) catch {};
    }

    /// Remove a tag.
    pub fn removeTag(self: *Client, key: []const u8) void {
        self.scope.removeTag(key);
    }

    /// Set an extra value.
    pub fn setExtra(self: *Client, key: []const u8, value: json.Value) void {
        self.scope.setExtra(key, value) catch {};
    }

    /// Set a context value.
    pub fn setContext(self: *Client, key: []const u8, value: json.Value) void {
        self.scope.setContext(key, value) catch {};
    }

    /// Add a breadcrumb.
    pub fn addBreadcrumb(self: *Client, crumb: Breadcrumb) void {
        if (self.options.before_breadcrumb) |before_breadcrumb| {
            if (before_breadcrumb(crumb)) |processed| {
                self.scope.addBreadcrumb(processed);
            }
            return;
        }
        self.scope.addBreadcrumb(crumb);
    }

    /// Add an attachment to the scope for future captured events.
    pub fn addAttachment(self: *Client, attachment: Attachment) void {
        self.scope.addAttachment(attachment);
    }

    /// Clear all attachments from the scope.
    pub fn clearAttachments(self: *Client) void {
        self.scope.clearAttachments();
    }

    /// Add a scope event processor. Returning false drops the event.
    pub fn addEventProcessor(self: *Client, processor: scope_mod.EventProcessor) void {
        self.scope.addEventProcessor(processor) catch {};
    }

    /// Remove all scope event processors.
    pub fn clearEventProcessors(self: *Client) void {
        self.scope.clearEventProcessors();
    }

    /// Remove an extra value.
    pub fn removeExtra(self: *Client, key: []const u8) void {
        self.scope.removeExtra(key);
    }

    /// Remove a context value.
    pub fn removeContext(self: *Client, key: []const u8) void {
        self.scope.removeContext(key);
    }

    // ─── Transaction Methods ─────────────────────────────────────────────

    /// Start a new transaction, applying release/environment from options.
    pub fn startTransaction(self: *Client, opts: TransactionOpts) Transaction {
        var real_opts = opts;

        // Apply defaults from client options
        if (real_opts.release == null) real_opts.release = self.options.release;
        if (real_opts.environment == null) real_opts.environment = self.options.environment;

        const effective_sample_rate: f64 = blk: {
            if (self.options.traces_sampler) |sampler| {
                const sampled_rate = sampler(.{
                    .transaction_name = real_opts.name,
                    .transaction_op = real_opts.op,
                    .parent_sampled = null,
                });
                break :blk if (isValidSampleRate(sampled_rate)) sampled_rate else 0.0;
            }

            if (real_opts.sample_rate == 1.0) {
                break :blk self.options.traces_sample_rate;
            }

            break :blk real_opts.sample_rate;
        };
        real_opts.sample_rate = effective_sample_rate;

        if (real_opts.sampled) {
            if (effective_sample_rate <= 0.0) {
                real_opts.sampled = false;
            } else if (effective_sample_rate < 1.0) {
                const rand_val = std.crypto.random.float(f64);
                real_opts.sampled = rand_val < effective_sample_rate;
            }
        }

        return Transaction.init(self.allocator, real_opts);
    }

    /// Finish a transaction, serialize it, and submit the envelope to the worker.
    pub fn finishTransaction(self: *Client, txn: *Transaction) void {
        if (!self.isEnabled()) return;

        txn.finish();

        if (!txn.sampled) return;

        // Serialize transaction to JSON
        const txn_json = txn.toJson(self.allocator) catch return;
        defer self.allocator.free(txn_json);

        // Create transaction envelope
        const data = self.serializeTransactionEnvelope(txn, txn_json) catch return;

        self.worker.submit(data, .transaction) catch {
            self.allocator.free(data);
        };
    }

    // ─── Session Methods ─────────────────────────────────────────────────

    /// Start a new session.
    pub fn startSession(self: *Client) void {
        if (!self.isEnabled()) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        // Sessions require a configured release.
        const release = self.options.release orelse return;

        // End any existing session first
        if (self.session) |*s| {
            s.end(.exited);
            _ = self.sendSessionUpdate(s);
        }

        const environment = self.options.environment orelse "production";
        self.session = Session.startWithMode(
            release,
            environment,
            self.options.session_mode == .application,
        );
    }

    /// End the current session with the given status.
    pub fn endSession(self: *Client, status: SessionStatus) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.session) |*s| {
            s.end(status);
            _ = self.sendSessionUpdate(s);
            self.session = null;
        }
    }

    // ─── Flush ───────────────────────────────────────────────────────────

    /// Returns true when the client has an active background worker.
    pub fn isEnabled(self: *Client) bool {
        return self.worker.isAccepting();
    }

    /// Flush and shut down the transport worker.
    /// Returns true when the queue was drained before shutdown.
    pub fn close(self: *Client, timeout_ms: ?u64) bool {
        self.endSession(.exited);
        const drained = self.worker.flush(timeout_ms orelse self.options.shutdown_timeout_ms);
        self.worker.shutdown();
        return drained;
    }

    /// Returns the last accepted event id on this client.
    pub fn lastEventId(self: *Client) ?[32]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.last_event_id;
    }

    /// Flush the event queue, waiting up to timeout_ms.
    /// Returns true if the queue was fully drained.
    pub fn flush(self: *Client, timeout_ms: u64) bool {
        return self.worker.flush(timeout_ms);
    }

    // ─── Internal Helpers ────────────────────────────────────────────────

    fn transportSendCallback(data: []const u8, ctx: ?*anyopaque) SendOutcome {
        if (ctx) |ptr| {
            const client: *Client = @ptrCast(@alignCast(ptr));
            const send_result = client.transport.send(data) catch return .{};
            return .{ .rate_limits = send_result.rate_limits };
        }
        return .{};
    }

    fn captureCrashEvent(self: *Client, signal_num: u32) void {
        var event = Event.init();
        event.level = .fatal;

        var msg_buf: [64]u8 = undefined;
        const sig_name: []const u8 = switch (signal_num) {
            11 => "SIGSEGV",
            6 => "SIGABRT",
            7 => "SIGBUS",
            4 => "SIGILL",
            8 => "SIGFPE",
            else => "Unknown",
        };
        const msg = std.fmt.bufPrint(&msg_buf, "Crash: {s} (signal {d})", .{ sig_name, signal_num }) catch "Crash detected from previous run";

        // Use exception interface with stack-local values — safe because captureEvent
        // serializes synchronously before returning
        const values = [_]ExceptionValue{.{
            .type = "NativeCrash",
            .value = msg,
        }};
        event.exception = .{ .values = &values };
        self.captureEvent(&event);
    }

    fn serializeEventEnvelope(self: *Client, event: *const Event, attachments: []const Attachment) ![]u8 {
        var aw: Writer.Allocating = .init(self.allocator);
        errdefer aw.deinit();
        try envelope.serializeEventEnvelopeWithAttachments(
            self.allocator,
            event.*,
            self.dsn,
            attachments,
            &aw.writer,
        );
        return try aw.toOwnedSlice();
    }

    fn serializeTransactionEnvelope(self: *Client, txn: *const Transaction, txn_json: []const u8) ![]u8 {
        var aw: Writer.Allocating = .init(self.allocator);
        errdefer aw.deinit();
        const w = &aw.writer;

        // Envelope header
        try w.writeAll("{\"event_id\":\"");
        try w.writeAll(&txn.event_id);
        try w.writeAll("\",\"dsn\":\"");
        try self.dsn.writeDsn(w);
        try w.writeAll("\",\"sent_at\":\"");
        const ts = @import("timestamp.zig");
        const rfc3339 = ts.nowRfc3339();
        try w.writeAll(&rfc3339);
        try w.writeAll("\",\"sdk\":{\"name\":\"");
        try w.writeAll(envelope.SDK_NAME);
        try w.writeAll("\",\"version\":\"");
        try w.writeAll(envelope.SDK_VERSION);
        try w.writeAll("\"}}");
        try w.writeByte('\n');

        // Item header
        try w.writeAll("{\"type\":\"transaction\",\"length\":");
        try w.print("{d}", .{txn_json.len});
        try w.writeByte('}');
        try w.writeByte('\n');

        // Payload
        try w.writeAll(txn_json);

        return try aw.toOwnedSlice();
    }

    fn serializeCheckInEnvelope(self: *Client, check_in_json: []const u8) ![]u8 {
        var aw: Writer.Allocating = .init(self.allocator);
        errdefer aw.deinit();
        try envelope.serializeCheckInEnvelope(self.dsn, check_in_json, &aw.writer);
        return try aw.toOwnedSlice();
    }

    fn sendSessionUpdate(self: *Client, session: *Session) bool {
        const session_json = session.toJson(self.allocator) catch return false;
        defer self.allocator.free(session_json);

        var aw: Writer.Allocating = .init(self.allocator);

        envelope.serializeSessionEnvelope(self.dsn, session_json, &aw.writer) catch {
            aw.deinit();
            return false;
        };

        const data = aw.toOwnedSlice() catch {
            aw.deinit();
            return false;
        };

        self.worker.submit(data, .session) catch {
            self.allocator.free(data);
            return false;
        };

        session.markSent();
        return true;
    }

    fn isValidSampleRate(rate: f64) bool {
        if (!std.math.isFinite(rate)) return false;
        return rate >= 0.0 and rate <= 1.0;
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test "Options struct has correct defaults" {
    const opts = Options{
        .dsn = "https://key@sentry.io/1",
    };
    try testing.expect(!opts.debug);
    try testing.expectEqual(@as(f64, 1.0), opts.sample_rate);
    try testing.expectEqual(@as(f64, 0.0), opts.traces_sample_rate);
    try testing.expect(opts.traces_sampler == null);
    try testing.expectEqual(@as(u32, 100), opts.max_breadcrumbs);
    try testing.expect(!opts.attach_stacktrace);
    try testing.expect(!opts.send_default_pii);
    try testing.expect(opts.release == null);
    try testing.expect(opts.environment == null);
    try testing.expect(opts.server_name == null);
    try testing.expect(opts.before_send == null);
    try testing.expect(opts.before_breadcrumb == null);
    try testing.expectEqualStrings("sentry-zig/0.1.0", opts.user_agent);
    try testing.expect(opts.install_signal_handlers);
    try testing.expect(!opts.auto_session_tracking);
    try testing.expectEqual(SessionMode.application, opts.session_mode);
    try testing.expectEqual(@as(u64, 2000), opts.shutdown_timeout_ms);
    try testing.expectEqualStrings("/tmp/sentry-zig", opts.cache_dir);
}

test "Client struct size is non-zero" {
    try testing.expect(@sizeOf(Client) > 0);
}

test "Options struct size is non-zero" {
    try testing.expect(@sizeOf(Options) > 0);
}

fn dropBreadcrumb(_: Breadcrumb) ?Breadcrumb {
    return null;
}

var replacement_event_for_test: Event = undefined;

fn replaceEventPointer(_: *Event) ?*Event {
    return &replacement_event_for_test;
}

fn dropEventBeforeSend(_: *Event) ?*Event {
    return null;
}

fn dropEventInScope(_: *Event) bool {
    return false;
}

fn alwaysSampleTraces(_: TracesSamplingContext) f64 {
    return 1.0;
}

fn neverSampleTraces(_: TracesSamplingContext) f64 {
    return 0.0;
}

test "Client addBreadcrumb applies before_breadcrumb callback" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_breadcrumb = dropBreadcrumb,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.addBreadcrumb(.{ .message = "should-drop" });
    try testing.expectEqual(@as(usize, 0), client.scope.breadcrumbs.count);
}

test "Client auto_session_tracking does not start session without release" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .auto_session_tracking = true,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.session == null);
}

test "Client addAttachment stores attachment in scope" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var attachment = try Attachment.initOwned(
        testing.allocator,
        "debug.txt",
        "debug-body",
        "text/plain",
        null,
    );
    defer attachment.deinit(testing.allocator);

    client.addAttachment(attachment);
    try testing.expectEqual(@as(usize, 1), client.scope.attachments.items.len);

    client.clearAttachments();
    try testing.expectEqual(@as(usize, 0), client.scope.attachments.items.len);
}

test "Client serializeCheckInEnvelope writes check_in item type" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const payload =
        "{\"check_in_id\":\"0123456789abcdef0123456789abcdef\",\"monitor_slug\":\"nightly\",\"status\":\"ok\"}";
    const serialized = try client.serializeCheckInEnvelope(payload);
    defer testing.allocator.free(serialized);

    try testing.expect(std.mem.indexOf(u8, serialized, "\"type\":\"check_in\"") != null);
    try testing.expect(std.mem.indexOf(u8, serialized, "\"monitor_slug\":\"nightly\"") != null);
}

test "Client before_send drops replacement pointers for memory safety" {
    replacement_event_for_test = Event.initMessage("replacement", .warning);

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_send = replaceEventPointer,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureMessage("original", .info);
    try testing.expectEqual(@as(usize, 0), client.worker.queueLen());
}

test "Client traces_sampler overrides traces_sample_rate" {
    const always_client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 0.0,
        .traces_sampler = alwaysSampleTraces,
        .install_signal_handlers = false,
    });
    defer always_client.deinit();

    var always_txn = always_client.startTransaction(.{
        .name = "GET /always",
    });
    defer always_txn.deinit();

    try testing.expectEqual(@as(f64, 1.0), always_txn.sample_rate);
    try testing.expect(always_txn.sampled);

    const never_client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .traces_sampler = neverSampleTraces,
        .install_signal_handlers = false,
    });
    defer never_client.deinit();

    var never_txn = never_client.startTransaction(.{
        .name = "GET /never",
    });
    defer never_txn.deinit();

    try testing.expectEqual(@as(f64, 0.0), never_txn.sample_rate);
    try testing.expect(!never_txn.sampled);
}

test "Client captureMessageId stores last event id" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const event_id = client.captureMessageId("with-id", .info);
    try testing.expect(event_id != null);

    const last_id = client.lastEventId();
    try testing.expect(last_id != null);
    try testing.expectEqualSlices(u8, &event_id.?, &last_id.?);
}

test "Client captureMessageId returns null when before_send drops event" {
    replacement_event_for_test = Event.initMessage("replacement", .warning);

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_send = replaceEventPointer,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("drop-me", .info) == null);
    try testing.expect(client.lastEventId() == null);
}

test "Client close shuts down worker and disables client" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.isEnabled());
    _ = client.close(null);
    try testing.expect(!client.isEnabled());
}

test "Client does not accept events after close" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const before_close = client.captureMessageId("before-close", .info);
    try testing.expect(before_close != null);

    _ = client.close(null);
    try testing.expect(!client.isEnabled());

    const after_close = client.captureMessageId("after-close", .info);
    try testing.expect(after_close == null);
}

test "Client does not start session after close" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    _ = client.close(null);
    client.startSession();
    try testing.expect(client.session == null);
}

test "Client request session mode disables duration tracking" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .session_mode = .request,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    try testing.expect(client.session != null);
    try testing.expect(!client.session.?.track_duration);
}

test "Client session counts errors even when events are sampled out" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .sample_rate = 0.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    try testing.expect(client.session != null);

    client.captureException("SampledOutError", "one");
    client.captureException("SampledOutError", "two");
    client.captureException("SampledOutError", "three");

    try testing.expectEqual(@as(u32, 3), client.session.?.errors);
    try testing.expectEqual(SessionStatus.errored, client.session.?.status);
}

test "Client session does not count errors when before_send drops event" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .before_send = dropEventBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    try testing.expect(client.session != null);

    client.captureException("DroppedError", "dropped");

    try testing.expectEqual(@as(u32, 0), client.session.?.errors);
    try testing.expectEqual(SessionStatus.ok, client.session.?.status);
}

test "Client session does not count errors when scope event processor drops event" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    client.addEventProcessor(dropEventInScope);
    try testing.expect(client.session != null);

    client.captureException("DroppedByProcessor", "dropped");

    try testing.expectEqual(@as(u32, 0), client.session.?.errors);
    try testing.expectEqual(SessionStatus.ok, client.session.?.status);
}
