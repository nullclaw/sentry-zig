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
const Uuid = @import("uuid.zig").Uuid;
const log_mod = @import("log.zig");
const LogEntry = log_mod.LogEntry;
const LogLevel = log_mod.LogLevel;

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

        var worker = try Worker.init(allocator, transportSendCallback, @ptrCast(self));
        errdefer worker.deinit();

        self.* = Client{
            .allocator = allocator,
            .dsn = dsn,
            .options = options,
            .scope = scope,
            .transport = transport,
            .worker = worker,
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
        _ = self.worker.submit(data, .any);
    }

    /// Capture a structured log item.
    pub fn captureLog(self: *Client, entry: *const LogEntry) void {
        if (!self.isEnabled()) return;

        var prepared = entry.*;
        if (prepared.trace_id == null) {
            const trace_id = Uuid.v4().toHex();
            prepared.trace_id = trace_id;
        }

        const log_json = prepared.toJson(self.allocator) catch return;
        defer self.allocator.free(log_json);

        const data = self.serializeLogEnvelope(log_json) catch return;
        _ = self.worker.submit(data, .log_item);
    }

    /// Capture a simple structured log message.
    pub fn captureLogMessage(self: *Client, message: []const u8, level: LogLevel) void {
        var entry = LogEntry.init(message, level);
        self.captureLog(&entry);
    }

    /// Core method: apply defaults, sample, apply scope, run before_send,
    /// serialize to envelope, and submit to the worker queue.
    pub fn captureEvent(self: *Client, event: *Event) void {
        _ = self.captureEventId(event);
    }

    /// Capture an event and return its id if accepted by filters/sampling.
    pub fn captureEventId(self: *Client, event: *Event) ?[32]u8 {
        return self.captureEventIdWithScope(event, &self.scope);
    }

    /// Capture an event and return its id using the provided scope.
    pub fn captureEventIdWithScope(self: *Client, event: *Event, source_scope: *Scope) ?[32]u8 {
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
        const applied = source_scope.applyToEvent(self.allocator, &prepared_event_value) catch return null;
        defer scope_mod.cleanupAppliedToEvent(self.allocator, &prepared_event_value, applied);

        const prepared_event: *Event = &prepared_event_value;

        var owned_trace_contexts: ?json.Value = null;
        defer if (owned_trace_contexts) |*contexts| {
            scope_mod.deinitJsonValueDeep(self.allocator, contexts);
            prepared_event.contexts = null;
        };

        if (prepared_event.contexts == null) {
            const contexts = buildDefaultTraceContexts(self.allocator) catch null;
            if (contexts) |value| {
                prepared_event.contexts = value;
                owned_trace_contexts = value;
            }
        }

        var owned_threads: ?json.Value = null;
        defer if (owned_threads) |*threads| {
            scope_mod.deinitJsonValueDeep(self.allocator, threads);
            prepared_event.threads = null;
        };

        if (self.options.attach_stacktrace and prepared_event.threads == null) {
            const threads = buildSyntheticThreads(self.allocator) catch null;
            if (threads) |value| {
                prepared_event.threads = value;
                owned_threads = value;
            }
        }

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

        const attachments = source_scope.snapshotAttachments(self.allocator) catch return null;
        defer scope_mod.deinitAttachmentSlice(self.allocator, attachments);

        // Serialize event to envelope
        const data = self.serializeEventEnvelope(prepared_event, attachments) catch return null;

        // Envelope contains an error event item (and optionally attachments),
        // so it must obey error-category rate limits.
        if (self.worker.submit(data, .@"error") == .dropped_shutdown) {
            return null;
        }

        self.mutex.lock();
        self.last_event_id = prepared_event.event_id;
        const accepted_id = self.last_event_id.?;
        self.mutex.unlock();

        return accepted_id;
    }

    // ─── Scope Delegation ────────────────────────────────────────────────

    /// Set the user context.
    pub fn setUser(self: *Client, user: User) void {
        self.trySetUser(user) catch {};
    }

    /// Set the user context and surface allocation failures.
    pub fn trySetUser(self: *Client, user: User) !void {
        try self.scope.trySetUser(user);
    }

    /// Remove the user context.
    pub fn removeUser(self: *Client) void {
        self.scope.setUser(null);
    }

    /// Set a tag.
    pub fn setTag(self: *Client, key: []const u8, value: []const u8) void {
        self.trySetTag(key, value) catch {};
    }

    /// Set a tag and surface allocation failures.
    pub fn trySetTag(self: *Client, key: []const u8, value: []const u8) !void {
        try self.scope.setTag(key, value);
    }

    /// Set the default level for events in the current scope.
    pub fn setLevel(self: *Client, level: ?Level) void {
        self.scope.setLevel(level);
    }

    /// Set transaction name override on scope.
    pub fn setTransaction(self: *Client, transaction: ?[]const u8) void {
        self.trySetTransaction(transaction) catch {};
    }

    /// Set transaction name override on scope and surface allocation failures.
    pub fn trySetTransaction(self: *Client, transaction: ?[]const u8) !void {
        try self.scope.setTransaction(transaction);
    }

    /// Set fingerprint override on scope.
    pub fn setFingerprint(self: *Client, fingerprint: ?[]const []const u8) void {
        self.trySetFingerprint(fingerprint) catch {};
    }

    /// Set fingerprint override on scope and surface allocation failures.
    pub fn trySetFingerprint(self: *Client, fingerprint: ?[]const []const u8) !void {
        try self.scope.setFingerprint(fingerprint);
    }

    /// Remove a tag.
    pub fn removeTag(self: *Client, key: []const u8) void {
        self.scope.removeTag(key);
    }

    /// Set an extra value.
    pub fn setExtra(self: *Client, key: []const u8, value: json.Value) void {
        self.trySetExtra(key, value) catch {};
    }

    /// Set an extra value and surface allocation failures.
    pub fn trySetExtra(self: *Client, key: []const u8, value: json.Value) !void {
        try self.scope.setExtra(key, value);
    }

    /// Set a context value.
    pub fn setContext(self: *Client, key: []const u8, value: json.Value) void {
        self.trySetContext(key, value) catch {};
    }

    /// Set a context value and surface allocation failures.
    pub fn trySetContext(self: *Client, key: []const u8, value: json.Value) !void {
        try self.scope.setContext(key, value);
    }

    /// Add a breadcrumb.
    pub fn addBreadcrumb(self: *Client, crumb: Breadcrumb) void {
        self.tryAddBreadcrumb(crumb) catch {};
    }

    /// Add a breadcrumb and surface allocation failures.
    pub fn tryAddBreadcrumb(self: *Client, crumb: Breadcrumb) !void {
        if (self.options.before_breadcrumb) |before_breadcrumb| {
            if (before_breadcrumb(crumb)) |processed| {
                try self.scope.tryAddBreadcrumb(processed);
            }
            return;
        }
        try self.scope.tryAddBreadcrumb(crumb);
    }

    /// Clear all breadcrumbs from the scope.
    pub fn clearBreadcrumbs(self: *Client) void {
        self.scope.clearBreadcrumbs();
    }

    /// Add an attachment to the scope for future captured events.
    pub fn addAttachment(self: *Client, attachment: Attachment) void {
        self.tryAddAttachment(attachment) catch {};
    }

    /// Add an attachment to the scope and surface allocation failures.
    pub fn tryAddAttachment(self: *Client, attachment: Attachment) !void {
        try self.scope.tryAddAttachment(attachment);
    }

    /// Clear all attachments from the scope.
    pub fn clearAttachments(self: *Client) void {
        self.scope.clearAttachments();
    }

    /// Add a scope event processor. Returning false drops the event.
    pub fn addEventProcessor(self: *Client, processor: scope_mod.EventProcessor) void {
        self.tryAddEventProcessor(processor) catch {};
    }

    /// Add a scope event processor and surface allocation failures.
    pub fn tryAddEventProcessor(self: *Client, processor: scope_mod.EventProcessor) !void {
        try self.scope.addEventProcessor(processor);
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

        _ = self.worker.submit(data, .transaction);
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

    fn putOwnedJsonEntry(
        allocator: Allocator,
        object: *json.ObjectMap,
        key: []const u8,
        value: json.Value,
    ) !void {
        const key_copy = try allocator.dupe(u8, key);
        errdefer allocator.free(key_copy);
        try object.put(key_copy, value);
    }

    fn putOwnedString(
        allocator: Allocator,
        object: *json.ObjectMap,
        key: []const u8,
        value: []const u8,
    ) !void {
        const value_copy = try allocator.dupe(u8, value);
        errdefer allocator.free(value_copy);
        try putOwnedJsonEntry(allocator, object, key, .{ .string = value_copy });
    }

    fn putOwnedBool(
        allocator: Allocator,
        object: *json.ObjectMap,
        key: []const u8,
        value: bool,
    ) !void {
        try putOwnedJsonEntry(allocator, object, key, .{ .bool = value });
    }

    fn buildDefaultTraceContexts(allocator: Allocator) !json.Value {
        const trace_id = Uuid.v4().toHex();
        const span_id = txn_mod.generateSpanId();

        var trace_object = json.ObjectMap.init(allocator);
        var trace_moved = false;
        errdefer if (!trace_moved) {
            var value: json.Value = .{ .object = trace_object };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        };

        try putOwnedString(allocator, &trace_object, "type", "trace");
        try putOwnedString(allocator, &trace_object, "trace_id", &trace_id);
        try putOwnedString(allocator, &trace_object, "span_id", &span_id);
        try putOwnedBool(allocator, &trace_object, "sampled", false);

        var contexts_object = json.ObjectMap.init(allocator);
        errdefer {
            var value: json.Value = .{ .object = contexts_object };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        }

        try putOwnedJsonEntry(allocator, &contexts_object, "trace", .{ .object = trace_object });
        trace_moved = true;
        return .{ .object = contexts_object };
    }

    fn buildSyntheticThreads(allocator: Allocator) !json.Value {
        var frame_object = json.ObjectMap.init(allocator);
        var frame_moved = false;
        errdefer if (!frame_moved) {
            var value: json.Value = .{ .object = frame_object };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        };

        try putOwnedString(allocator, &frame_object, "function", "capture_event");
        try putOwnedBool(allocator, &frame_object, "in_app", true);

        var frames_array = json.Array.init(allocator);
        var frames_moved = false;
        errdefer if (!frames_moved) {
            var value: json.Value = .{ .array = frames_array };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        };

        try frames_array.append(.{ .object = frame_object });
        frame_moved = true;

        var stacktrace_object = json.ObjectMap.init(allocator);
        var stacktrace_moved = false;
        errdefer if (!stacktrace_moved) {
            var value: json.Value = .{ .object = stacktrace_object };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        };

        try putOwnedJsonEntry(allocator, &stacktrace_object, "frames", .{ .array = frames_array });
        frames_moved = true;

        var thread_object = json.ObjectMap.init(allocator);
        var thread_moved = false;
        errdefer if (!thread_moved) {
            var value: json.Value = .{ .object = thread_object };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        };

        try putOwnedBool(allocator, &thread_object, "current", true);
        try putOwnedJsonEntry(
            allocator,
            &thread_object,
            "stacktrace",
            .{ .object = stacktrace_object },
        );
        stacktrace_moved = true;

        var threads_array = json.Array.init(allocator);
        var threads_array_moved = false;
        errdefer if (!threads_array_moved) {
            var value: json.Value = .{ .array = threads_array };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        };

        try threads_array.append(.{ .object = thread_object });
        thread_moved = true;

        var threads_object = json.ObjectMap.init(allocator);
        errdefer {
            var value: json.Value = .{ .object = threads_object };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        }

        try putOwnedJsonEntry(allocator, &threads_object, "values", .{ .array = threads_array });
        threads_array_moved = true;

        return .{ .object = threads_object };
    }

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
        try envelope.serializeTransactionEnvelopeWithTrace(
            self.dsn,
            txn.event_id,
            txn_json,
            .{
                .trace_id = txn.trace_id,
                .public_key = self.dsn.public_key,
                .sample_rate = txn.sample_rate,
                .sampled = txn.sampled,
            },
            &aw.writer,
        );

        return try aw.toOwnedSlice();
    }

    fn serializeCheckInEnvelope(self: *Client, check_in_json: []const u8) ![]u8 {
        var aw: Writer.Allocating = .init(self.allocator);
        errdefer aw.deinit();
        try envelope.serializeCheckInEnvelope(self.dsn, check_in_json, &aw.writer);
        return try aw.toOwnedSlice();
    }

    fn serializeLogEnvelope(self: *Client, log_json: []const u8) ![]u8 {
        var aw: Writer.Allocating = .init(self.allocator);
        errdefer aw.deinit();
        try envelope.serializeLogEnvelope(self.dsn, log_json, &aw.writer);
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

        if (self.worker.submit(data, .session) == .dropped_shutdown) {
            return false;
        }

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

fn hasTraceContext(event: *const Event) bool {
    if (event.contexts) |contexts| {
        return switch (contexts) {
            .object => |obj| obj.get("trace") != null,
            else => false,
        };
    }
    return false;
}

fn hasThreadStacktrace(event: *const Event) bool {
    if (event.threads) |threads| {
        switch (threads) {
            .object => |obj| {
                const values = obj.get("values") orelse return false;
                return switch (values) {
                    .array => |arr| arr.items.len > 0,
                    else => false,
                };
            },
            else => return false,
        }
    }
    return false;
}

var before_send_saw_trace_context: bool = false;
var before_send_saw_threads: bool = false;

fn inspectTraceContextBeforeSend(event: *Event) ?*Event {
    before_send_saw_trace_context = hasTraceContext(event);
    return event;
}

fn inspectThreadsBeforeSend(event: *Event) ?*Event {
    before_send_saw_threads = hasThreadStacktrace(event);
    return event;
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

test "Client clearBreadcrumbs removes previously added breadcrumbs" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.addBreadcrumb(.{ .message = "crumb-1" });
    client.addBreadcrumb(.{ .message = "crumb-2" });
    try testing.expectEqual(@as(usize, 2), client.scope.breadcrumbs.count);

    client.clearBreadcrumbs();
    try testing.expectEqual(@as(usize, 0), client.scope.breadcrumbs.count);
}

test "Client captureMessage injects default trace context into event" {
    before_send_saw_trace_context = false;

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_send = inspectTraceContextBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("trace-context-message", .info) != null);
    try testing.expect(before_send_saw_trace_context);
}

test "Client attach_stacktrace adds synthetic thread stacktrace data" {
    before_send_saw_threads = false;

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .attach_stacktrace = true,
        .before_send = inspectThreadsBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("stacktrace-message", .warning) != null);
    try testing.expect(before_send_saw_threads);
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

fn keepEventProcessor(_: *Event) bool {
    return true;
}

test "Client try* scope mutators expose fallible API" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try client.trySetUser(.{ .id = "user-42", .email = "u@example.com" });
    try client.trySetTag("region", "us-east-1");
    try client.trySetExtra("attempt", .{ .integer = 3 });
    try client.trySetContext("runtime", .{ .string = "zig" });
    try client.trySetTransaction("GET /checkout");
    try client.trySetFingerprint(&.{ "checkout", "timeout" });
    try client.tryAddBreadcrumb(.{ .message = "checkout-started", .category = "flow" });

    var attachment = try Attachment.initOwned(
        testing.allocator,
        "diag.txt",
        "payload",
        "text/plain",
        null,
    );
    defer attachment.deinit(testing.allocator);
    try client.tryAddAttachment(attachment);
    try client.tryAddEventProcessor(keepEventProcessor);

    try testing.expect(client.scope.user != null);
    try testing.expectEqualStrings("us-east-1", client.scope.tags.get("region").?);
    try testing.expectEqual(@as(usize, 1), client.scope.attachments.items.len);
    try testing.expectEqual(@as(usize, 1), client.scope.event_processors.items.len);
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

test "Client serializeTransactionEnvelope adds dynamic sampling trace header" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "GET /trace-header",
        .op = "http.server",
    });
    defer txn.deinit();

    const payload = try txn.toJson(testing.allocator);
    defer testing.allocator.free(payload);

    const serialized = try client.serializeTransactionEnvelope(&txn, payload);
    defer testing.allocator.free(serialized);

    try testing.expect(std.mem.indexOf(u8, serialized, "\"type\":\"transaction\"") != null);
    try testing.expect(std.mem.indexOf(u8, serialized, "\"trace\":{") != null);
    try testing.expect(std.mem.indexOf(u8, serialized, "\"trace_id\":\"") != null);
    try testing.expect(std.mem.indexOf(u8, serialized, "\"public_key\":\"examplePublicKey\"") != null);
    try testing.expect(std.mem.indexOf(u8, serialized, "\"sample_rate\":1.000000") != null);
    try testing.expect(std.mem.indexOf(u8, serialized, "\"sampled\":true") != null);
}

test "Client serializeLogEnvelope writes log item type" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const payload = "{\"timestamp\":1.0,\"level\":\"info\",\"body\":\"log-entry\"}";
    const serialized = try client.serializeLogEnvelope(payload);
    defer testing.allocator.free(serialized);

    try testing.expect(std.mem.indexOf(u8, serialized, "\"type\":\"log\"") != null);
    try testing.expect(std.mem.indexOf(u8, serialized, "\"body\":\"log-entry\"") != null);
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
