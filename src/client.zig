const std = @import("std");
const builtin = @import("builtin");
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
const Frame = event_mod.Frame;
const Stacktrace = event_mod.Stacktrace;
const ExceptionValue = event_mod.ExceptionValue;
const ExceptionInterface = event_mod.ExceptionInterface;
const Message = event_mod.Message;
const scope_mod = @import("scope.zig");
const Scope = scope_mod.Scope;
const Session = @import("session.zig").Session;
const SessionStatus = @import("session.zig").SessionStatus;
const Transport = @import("transport.zig").Transport;
const TransportOptions = @import("transport.zig").Options;
const Worker = @import("worker.zig").Worker;
const SendOutcome = @import("worker.zig").SendOutcome;
const RateLimitCategory = @import("ratelimit.zig").Category;
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
const propagation = @import("propagation.zig");
const DynamicSamplingContext = propagation.DynamicSamplingContext;

const ExceptionFrameOwnership = struct {
    allocator: Allocator,
    values: []ExceptionValue,
    frames_per_value: []?[]Frame,

    fn deinit(self: *ExceptionFrameOwnership) void {
        for (self.frames_per_value) |maybe_frames| {
            if (maybe_frames) |frames| self.allocator.free(frames);
        }
        self.allocator.free(self.frames_per_value);
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

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
pub const BeforeSendLog = *const fn (*LogEntry) ?*LogEntry;
pub const BeforeSendTransaction = *const fn (*Transaction) ?*Transaction;
pub const TransportSendFn = *const fn ([]const u8, ?*anyopaque) SendOutcome;
pub const Integration = struct {
    setup: *const fn (*Client, ?*anyopaque) void,
    ctx: ?*anyopaque = null,
};
pub const TransportConfig = struct {
    send_fn: TransportSendFn,
    ctx: ?*anyopaque = null,
};

/// Configuration options for the Sentry client.
pub const Options = struct {
    dsn: []const u8,
    debug: bool = false,
    release: ?[]const u8 = null,
    dist: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    sample_rate: f64 = 1.0,
    traces_sample_rate: f64 = 0.0,
    traces_sampler: ?TracesSampler = null,
    max_breadcrumbs: u32 = 100,
    attach_stacktrace: bool = false,
    send_default_pii: bool = false,
    in_app_include: ?[]const []const u8 = null,
    in_app_exclude: ?[]const []const u8 = null,
    default_integrations: bool = true,
    integrations: ?[]const Integration = null,
    before_send: ?*const fn (*Event) ?*Event = null, // return same pointer, or null to drop
    before_breadcrumb: ?*const fn (Breadcrumb) ?Breadcrumb = null, // return null to drop
    before_send_transaction: ?BeforeSendTransaction = null, // return same pointer, or null to drop
    before_send_log: ?BeforeSendLog = null, // return same pointer, or null to drop
    transport: ?TransportConfig = null,
    http_proxy: ?[]const u8 = null,
    https_proxy: ?[]const u8 = null,
    accept_invalid_certs: bool = false,
    max_request_body_size: ?usize = null,
    enable_logs: bool = true,
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
    default_server_name: ?[]u8 = null,
    session_did: ?[]u8 = null,
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

        var transport = try Transport.init(allocator, dsn, options.user_agent, TransportOptions{
            .http_proxy = options.http_proxy,
            .https_proxy = options.https_proxy,
            .accept_invalid_certs = options.accept_invalid_certs,
        });
        errdefer transport.deinit();

        var scope = try Scope.init(allocator, options.max_breadcrumbs);
        errdefer scope.deinit();

        var worker = try Worker.init(allocator, transportSendCallback, @ptrCast(self));
        errdefer worker.deinit();

        var default_server_name: ?[]u8 = null;
        errdefer if (default_server_name) |name| allocator.free(name);
        if (options.default_integrations and options.server_name == null) {
            default_server_name = detectServerNameAlloc(allocator);
        }

        self.* = Client{
            .allocator = allocator,
            .dsn = dsn,
            .options = options,
            .scope = scope,
            .transport = transport,
            .worker = worker,
            .default_server_name = default_server_name,
            .session_did = null,
            .session = null,
            .last_event_id = null,
        };

        if (options.integrations) |integrations| {
            for (integrations) |integration| {
                integration.setup(self, integration.ctx);
            }
        }

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
        if (self.default_server_name) |name| self.allocator.free(name);
        if (self.session_did) |did| self.allocator.free(did);

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
        _ = self.submitEnvelope(data, .check_in);
    }

    /// Capture a structured log item.
    pub fn captureLog(self: *Client, entry: *const LogEntry) void {
        if (!self.isEnabled()) return;
        if (!self.options.enable_logs) return;

        var prepared = entry.*;
        if (prepared.trace_id == null) {
            const trace_id = Uuid.v4().toHex();
            prepared.trace_id = trace_id;
        }

        if (self.options.before_send_log) |before_send_log| {
            if (before_send_log(&prepared)) |processed| {
                // For memory safety, callbacks must mutate in place and return
                // the same pointer (or null to drop the log entry).
                if (processed != &prepared) return;
            } else {
                return;
            }
        }

        const log_json = prepared.toJson(self.allocator) catch return;
        defer self.allocator.free(log_json);

        const data = self.serializeLogEnvelope(log_json) catch return;
        _ = self.submitEnvelope(data, .log_item);
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
        if (self.options.dist) |dist| {
            if (prepared_event_value.dist == null) prepared_event_value.dist = dist;
        }
        if (self.options.environment) |env| {
            if (prepared_event_value.environment == null) prepared_event_value.environment = env;
        }
        if (self.options.server_name orelse self.default_server_name) |sn| {
            if (prepared_event_value.server_name == null) prepared_event_value.server_name = sn;
        }

        // Apply scope to event
        const applied = source_scope.applyToEvent(self.allocator, &prepared_event_value) catch return null;
        defer scope_mod.cleanupAppliedToEvent(self.allocator, &prepared_event_value, applied);

        const prepared_event: *Event = &prepared_event_value;

        var owned_exception_frames: ?ExceptionFrameOwnership = null;
        defer if (owned_exception_frames) |*ownership| {
            ownership.deinit();
            prepared_event.exception = null;
        };

        if (self.options.in_app_include != null or self.options.in_app_exclude != null) {
            if (applyInAppFrameHints(
                self.allocator,
                prepared_event,
                self.options.in_app_include,
                self.options.in_app_exclude,
            ) catch null) |ownership| {
                owned_exception_frames = ownership;
            }
        }

        var owned_trace_contexts: ?json.Value = null;
        defer if (owned_trace_contexts) |*contexts| {
            scope_mod.deinitJsonValueDeep(self.allocator, contexts);
            prepared_event.contexts = null;
        };

        if (prepared_event.contexts == null) {
            const contexts = buildDefaultTraceContexts(self.allocator, self.options.default_integrations) catch null;
            if (contexts) |value| {
                prepared_event.contexts = value;
                owned_trace_contexts = value;
            }
        } else {
            if (mergeDefaultTraceContexts(
                self.allocator,
                prepared_event,
                self.options.default_integrations,
            ) catch null) |value| {
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
        if (!self.submitEnvelope(data, .@"error")) {
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
        if (real_opts.dist == null) real_opts.dist = self.options.dist;
        if (real_opts.environment == null) real_opts.environment = self.options.environment;

        const effective_sample_rate: f64 = blk: {
            if (self.options.traces_sampler) |sampler| {
                const sampled_rate = sampler(.{
                    .transaction_name = real_opts.name,
                    .transaction_op = real_opts.op,
                    .parent_sampled = real_opts.parent_sampled,
                });
                break :blk if (isValidSampleRate(sampled_rate)) sampled_rate else 0.0;
            }

            if (real_opts.sample_rate == 1.0) {
                if (real_opts.parent_sampled) |parent_sampled| {
                    break :blk if (parent_sampled) 1.0 else 0.0;
                }
                break :blk self.options.traces_sample_rate;
            }

            break :blk if (isValidSampleRate(real_opts.sample_rate))
                real_opts.sample_rate
            else
                0.0;
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

    /// Start a new transaction using an explicit start timestamp.
    pub fn startTransactionWithTimestamp(
        self: *Client,
        opts: TransactionOpts,
        start_timestamp: f64,
    ) Transaction {
        var real_opts = opts;
        real_opts.start_timestamp = start_timestamp;
        return self.startTransaction(real_opts);
    }

    /// Start a transaction using upstream `sentry-trace` header context.
    pub fn startTransactionFromSentryTrace(
        self: *Client,
        opts: TransactionOpts,
        sentry_trace_header: []const u8,
    ) !Transaction {
        const parsed = propagation.parseSentryTrace(sentry_trace_header) orelse return error.InvalidSentryTrace;

        var real_opts = opts;
        real_opts.parent_trace_id = parsed.trace_id;
        real_opts.parent_span_id = parsed.span_id;
        real_opts.parent_sampled = parsed.sampled;
        return self.startTransaction(real_opts);
    }

    /// Start a transaction using propagation headers (`sentry-trace` and optional `baggage`).
    pub fn startTransactionFromPropagationHeaders(
        self: *Client,
        opts: TransactionOpts,
        sentry_trace_header: ?[]const u8,
        baggage_header: ?[]const u8,
    ) !Transaction {
        var real_opts = opts;

        if (sentry_trace_header) |trace_header| {
            const parsed_trace = propagation.parseSentryTrace(trace_header) orelse return error.InvalidSentryTrace;
            real_opts.parent_trace_id = parsed_trace.trace_id;
            real_opts.parent_span_id = parsed_trace.span_id;
            real_opts.parent_sampled = parsed_trace.sampled;
        }

        if (baggage_header) |baggage| {
            const parsed_baggage = propagation.parseBaggage(baggage);
            if (real_opts.parent_trace_id == null and parsed_baggage.trace_id != null) {
                real_opts.parent_trace_id = parsed_baggage.trace_id;
            }
            if (real_opts.parent_sampled == null and parsed_baggage.sampled != null) {
                real_opts.parent_sampled = parsed_baggage.sampled;
            }
            if (real_opts.sample_rate == 1.0) {
                if (parsed_baggage.sample_rate) |sample_rate| {
                    if (isValidSampleRate(sample_rate)) {
                        real_opts.sample_rate = sample_rate;
                    }
                }
            }
        }

        var txn = self.startTransaction(real_opts);
        if (baggage_header) |baggage| {
            txn.incoming_baggage = try self.allocator.dupe(u8, baggage);
        }
        return txn;
    }

    /// Build `sentry-trace` header value for an outgoing downstream request.
    pub fn sentryTraceHeader(self: *const Client, txn: *const Transaction, allocator: Allocator) ![]u8 {
        _ = self;
        return propagation.formatSentryTraceAlloc(allocator, .{
            .trace_id = txn.trace_id,
            .span_id = txn.span_id,
            .sampled = txn.sampled,
        });
    }

    /// Build `baggage` header value for an outgoing downstream request.
    pub fn baggageHeader(self: *const Client, txn: *const Transaction, allocator: Allocator) ![]u8 {
        const dsc: DynamicSamplingContext = .{
            .trace_id = txn.trace_id,
            .public_key = self.dsn.public_key,
            .release = txn.release,
            .environment = txn.environment,
            .transaction = txn.name,
            .sample_rate = txn.sample_rate,
            .sampled = txn.sampled,
        };
        return propagation.mergeBaggageAlloc(allocator, txn.incoming_baggage, dsc);
    }

    /// Finish a transaction, serialize it, and submit the envelope to the worker.
    pub fn finishTransaction(self: *Client, txn: *Transaction) void {
        if (!self.isEnabled()) return;

        txn.finish();

        if (!txn.sampled) return;

        var prepared_txn = txn;
        if (self.options.before_send_transaction) |before_send_transaction| {
            if (before_send_transaction(prepared_txn)) |processed_txn| {
                // For memory safety, callbacks must mutate in place and return
                // the same pointer. Returning a different pointer drops the transaction.
                if (processed_txn != prepared_txn) return;
                prepared_txn = processed_txn;
            } else {
                return;
            }
        }

        // Serialize transaction to JSON
        const txn_json = prepared_txn.toJson(self.allocator) catch return;
        defer self.allocator.free(txn_json);

        // Create transaction envelope
        const data = self.serializeTransactionEnvelope(prepared_txn, txn_json) catch return;

        _ = self.submitEnvelope(data, .transaction);
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
            self.session = null;
        }
        if (self.session_did) |did| {
            self.allocator.free(did);
            self.session_did = null;
        }

        const environment = self.options.environment orelse "production";
        self.session_did = self.resolveSessionDistinctIdAlloc();
        self.session = Session.startWithMode(
            release,
            environment,
            self.options.session_mode == .application,
        );
        if (self.session) |*s| {
            s.did = self.session_did;
        }
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
        if (self.session_did) |did| {
            self.allocator.free(did);
            self.session_did = null;
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

    fn applyInAppFrameHints(
        allocator: Allocator,
        event: *Event,
        in_app_include: ?[]const []const u8,
        in_app_exclude: ?[]const []const u8,
    ) !?ExceptionFrameOwnership {
        const exception = event.exception orelse return null;
        if (exception.values.len == 0) return null;

        const values_copy = try allocator.alloc(ExceptionValue, exception.values.len);
        errdefer allocator.free(values_copy);
        @memcpy(values_copy, exception.values);

        const frames_per_value = try allocator.alloc(?[]Frame, exception.values.len);
        errdefer {
            for (frames_per_value) |maybe_frames| {
                if (maybe_frames) |frames| allocator.free(frames);
            }
            allocator.free(frames_per_value);
        }
        @memset(frames_per_value, null);

        var any_modified = false;
        var i: usize = 0;
        while (i < exception.values.len) : (i += 1) {
            const value = exception.values[i];
            if (value.stacktrace) |stacktrace| {
                const frames_copy = try allocator.alloc(Frame, stacktrace.frames.len);
                @memcpy(frames_copy, stacktrace.frames);

                for (frames_copy) |*frame| {
                    if (frame.in_app == null) {
                        if (inferInApp(frame.*, in_app_include, in_app_exclude)) |in_app| {
                            frame.in_app = in_app;
                            any_modified = true;
                        }
                    }
                }

                values_copy[i].stacktrace = .{ .frames = frames_copy };
                frames_per_value[i] = frames_copy;
            }
        }

        if (!any_modified) {
            for (frames_per_value) |maybe_frames| {
                if (maybe_frames) |frames| allocator.free(frames);
            }
            allocator.free(frames_per_value);
            allocator.free(values_copy);
            return null;
        }

        event.exception = .{ .values = values_copy };
        return ExceptionFrameOwnership{
            .allocator = allocator,
            .values = values_copy,
            .frames_per_value = frames_per_value,
        };
    }

    fn inferInApp(
        frame: Frame,
        in_app_include: ?[]const []const u8,
        in_app_exclude: ?[]const []const u8,
    ) ?bool {
        if (in_app_include) |include_patterns| {
            if (matchFramePatterns(frame, include_patterns)) return true;
        }
        if (in_app_exclude) |exclude_patterns| {
            if (matchFramePatterns(frame, exclude_patterns)) return false;
        }
        return null;
    }

    fn matchFramePatterns(frame: Frame, patterns: []const []const u8) bool {
        for (patterns) |pattern| {
            if (pattern.len == 0) continue;
            if (frameFieldMatches(frame.filename, pattern)) return true;
            if (frameFieldMatches(frame.function, pattern)) return true;
            if (frameFieldMatches(frame.module, pattern)) return true;
            if (frameFieldMatches(frame.abs_path, pattern)) return true;
        }
        return false;
    }

    fn frameFieldMatches(field: ?[]const u8, pattern: []const u8) bool {
        if (field) |value| {
            return std.mem.indexOf(u8, value, pattern) != null;
        }
        return false;
    }

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

    fn buildDefaultTraceContexts(allocator: Allocator, include_runtime_os: bool) !json.Value {
        const trace_id = Uuid.v4().toHex();
        const span_id = txn_mod.generateSpanId();
        var runtime_version_buf: [64]u8 = undefined;
        const runtime_version = try std.fmt.bufPrint(
            &runtime_version_buf,
            "{d}.{d}.{d}",
            .{
                builtin.zig_version.major,
                builtin.zig_version.minor,
                builtin.zig_version.patch,
            },
        );

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

        var runtime_object: json.ObjectMap = undefined;
        var runtime_moved = true;
        if (include_runtime_os) {
            runtime_object = json.ObjectMap.init(allocator);
            runtime_moved = false;
            errdefer if (!runtime_moved) {
                var value: json.Value = .{ .object = runtime_object };
                scope_mod.deinitJsonValueDeep(allocator, &value);
            };
            try putOwnedString(allocator, &runtime_object, "name", "zig");
            try putOwnedString(allocator, &runtime_object, "version", runtime_version);
        }

        var os_object: json.ObjectMap = undefined;
        var os_moved = true;
        if (include_runtime_os) {
            os_object = json.ObjectMap.init(allocator);
            os_moved = false;
            errdefer if (!os_moved) {
                var value: json.Value = .{ .object = os_object };
                scope_mod.deinitJsonValueDeep(allocator, &value);
            };
            try putOwnedString(allocator, &os_object, "name", @tagName(builtin.os.tag));
            try putOwnedString(allocator, &os_object, "arch", @tagName(builtin.cpu.arch));
        }

        var contexts_object = json.ObjectMap.init(allocator);
        errdefer {
            var value: json.Value = .{ .object = contexts_object };
            scope_mod.deinitJsonValueDeep(allocator, &value);
        }

        try putOwnedJsonEntry(allocator, &contexts_object, "trace", .{ .object = trace_object });
        trace_moved = true;
        if (include_runtime_os) {
            try putOwnedJsonEntry(allocator, &contexts_object, "runtime", .{ .object = runtime_object });
            runtime_moved = true;
            try putOwnedJsonEntry(allocator, &contexts_object, "os", .{ .object = os_object });
            os_moved = true;
        }
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

    fn mergeDefaultTraceContexts(
        allocator: Allocator,
        event: *Event,
        include_runtime_os: bool,
    ) !?json.Value {
        const contexts = event.contexts orelse return null;
        if (contexts != .object) return null;

        const existing = contexts.object;
        const need_trace = existing.get("trace") == null;
        const need_runtime = include_runtime_os and existing.get("runtime") == null;
        const need_os = include_runtime_os and existing.get("os") == null;
        if (!need_trace and !need_runtime and !need_os) return null;

        var merged = try scope_mod.cloneJsonValue(allocator, contexts);
        errdefer scope_mod.deinitJsonValueDeep(allocator, &merged);
        if (merged != .object) return null;

        const defaults = try buildDefaultTraceContexts(allocator, include_runtime_os);
        defer {
            var defaults_owned = defaults;
            scope_mod.deinitJsonValueDeep(allocator, &defaults_owned);
        }
        if (defaults != .object) return null;

        const merged_object = &merged.object;
        const default_object = defaults.object;

        if (need_trace) {
            if (default_object.get("trace")) |trace_value| {
                var trace_copy = try scope_mod.cloneJsonValue(allocator, trace_value);
                errdefer scope_mod.deinitJsonValueDeep(allocator, &trace_copy);
                try putOwnedJsonEntry(allocator, merged_object, "trace", trace_copy);
            }
        }
        if (need_runtime) {
            if (default_object.get("runtime")) |runtime_value| {
                var runtime_copy = try scope_mod.cloneJsonValue(allocator, runtime_value);
                errdefer scope_mod.deinitJsonValueDeep(allocator, &runtime_copy);
                try putOwnedJsonEntry(allocator, merged_object, "runtime", runtime_copy);
            }
        }
        if (need_os) {
            if (default_object.get("os")) |os_value| {
                var os_copy = try scope_mod.cloneJsonValue(allocator, os_value);
                errdefer scope_mod.deinitJsonValueDeep(allocator, &os_copy);
                try putOwnedJsonEntry(allocator, merged_object, "os", os_copy);
            }
        }

        return merged;
    }

    fn transportSendCallback(data: []const u8, ctx: ?*anyopaque) SendOutcome {
        if (ctx) |ptr| {
            const client: *Client = @ptrCast(@alignCast(ptr));
            if (client.options.transport) |custom_transport| {
                return custom_transport.send_fn(data, custom_transport.ctx);
            }
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
        self.ensureSessionDistinctId(session);

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

        if (!self.submitEnvelope(data, .session)) {
            return false;
        }

        session.markSent();
        return true;
    }

    fn isValidSampleRate(rate: f64) bool {
        if (!std.math.isFinite(rate)) return false;
        return rate >= 0.0 and rate <= 1.0;
    }

    fn detectServerNameAlloc(allocator: Allocator) ?[]u8 {
        if (!builtin.link_libc and builtin.os.tag != .linux) return null;
        var host_buffer: [std.posix.HOST_NAME_MAX]u8 = undefined;
        const host_name = std.posix.gethostname(&host_buffer) catch return null;
        if (host_name.len == 0) return null;
        return allocator.dupe(u8, host_name) catch null;
    }

    fn resolveSessionDistinctIdAlloc(self: *Client) ?[]u8 {
        self.scope.mutex.lock();
        defer self.scope.mutex.unlock();

        const user = self.scope.user orelse return null;
        const candidate = user.id orelse user.email orelse user.username orelse return null;
        return self.allocator.dupe(u8, candidate) catch null;
    }

    fn ensureSessionDistinctId(self: *Client, session: *Session) void {
        if (session.did != null) return;
        if (self.session_did == null) {
            self.session_did = self.resolveSessionDistinctIdAlloc();
        }
        session.did = self.session_did;
    }

    fn submitEnvelope(self: *Client, data: []u8, category: RateLimitCategory) bool {
        if (self.options.max_request_body_size) |max_size| {
            if (data.len > max_size) {
                self.allocator.free(data);
                return false;
            }
        }
        return self.worker.submit(data, category) == .accepted;
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
    try testing.expect(opts.in_app_include == null);
    try testing.expect(opts.in_app_exclude == null);
    try testing.expect(opts.default_integrations);
    try testing.expect(opts.integrations == null);
    try testing.expect(opts.release == null);
    try testing.expect(opts.dist == null);
    try testing.expect(opts.environment == null);
    try testing.expect(opts.server_name == null);
    try testing.expect(opts.before_send == null);
    try testing.expect(opts.before_breadcrumb == null);
    try testing.expect(opts.before_send_transaction == null);
    try testing.expect(opts.before_send_log == null);
    try testing.expect(opts.transport == null);
    try testing.expect(opts.http_proxy == null);
    try testing.expect(opts.https_proxy == null);
    try testing.expect(!opts.accept_invalid_certs);
    try testing.expect(opts.max_request_body_size == null);
    try testing.expect(opts.enable_logs);
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

test "Client init fails for invalid proxy URL" {
    try testing.expectError(
        error.InvalidProxyUrl,
        Client.init(testing.allocator, .{
            .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
            .http_proxy = "://invalid-proxy",
            .install_signal_handlers = false,
        }),
    );
}

test "Client runs configured integration setup callbacks on init" {
    var called = false;
    const integration = Integration{
        .setup = testIntegrationSetup,
        .ctx = &called,
    };

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .integrations = &.{integration},
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(called);
}

fn dropBreadcrumb(_: Breadcrumb) ?Breadcrumb {
    return null;
}

var replacement_event_for_test: Event = undefined;
var replacement_txn_for_test: Transaction = undefined;
var replacement_log_for_test: LogEntry = undefined;

fn replaceEventPointer(_: *Event) ?*Event {
    return &replacement_event_for_test;
}

fn replaceLogPointer(_: *LogEntry) ?*LogEntry {
    return &replacement_log_for_test;
}

fn replaceTransactionPointer(_: *Transaction) ?*Transaction {
    return &replacement_txn_for_test;
}

fn dropEventBeforeSend(_: *Event) ?*Event {
    return null;
}

fn dropTransactionBeforeSend(_: *Transaction) ?*Transaction {
    return null;
}

fn dropLogBeforeSend(_: *LogEntry) ?*LogEntry {
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

const CustomTransportState = struct {
    sent_count: usize = 0,
};

fn customTransportSendFn(_: []const u8, ctx: ?*anyopaque) SendOutcome {
    const state: *CustomTransportState = @ptrCast(@alignCast(ctx.?));
    state.sent_count += 1;
    return .{};
}

const PayloadTransportState = struct {
    allocator: Allocator,
    sent_count: usize = 0,
    last_payload: ?[]u8 = null,

    fn init(allocator: Allocator) PayloadTransportState {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *PayloadTransportState) void {
        if (self.last_payload) |payload| self.allocator.free(payload);
        self.* = undefined;
    }
};

fn payloadTransportSendFn(data: []const u8, ctx: ?*anyopaque) SendOutcome {
    const state: *PayloadTransportState = @ptrCast(@alignCast(ctx.?));
    state.sent_count += 1;
    if (state.last_payload) |payload| state.allocator.free(payload);
    state.last_payload = state.allocator.dupe(u8, data) catch null;
    return .{};
}

var before_send_transaction_saw_expected_name: bool = false;

fn inspectTransactionBeforeSend(txn: *Transaction) ?*Transaction {
    before_send_transaction_saw_expected_name = std.mem.eql(u8, txn.name, "POST /checkout");
    txn.op = "http.server.processed";
    return txn;
}

fn testIntegrationSetup(_: *Client, ctx: ?*anyopaque) void {
    const called: *bool = @ptrCast(@alignCast(ctx.?));
    called.* = true;
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

fn hasNamedContext(event: *const Event, name: []const u8) bool {
    if (event.contexts) |contexts| {
        return switch (contexts) {
            .object => |obj| obj.get(name) != null,
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
var before_send_saw_runtime_context: bool = false;
var before_send_saw_os_context: bool = false;
var before_send_saw_threads: bool = false;
var before_send_first_frame_in_app: ?bool = null;
var before_send_observed_server_name: ?[]const u8 = null;
var before_send_observed_dist: ?[]const u8 = null;

fn inspectTraceContextBeforeSend(event: *Event) ?*Event {
    before_send_saw_trace_context = hasTraceContext(event);
    before_send_saw_runtime_context = hasNamedContext(event, "runtime");
    before_send_saw_os_context = hasNamedContext(event, "os");
    return event;
}

fn inspectThreadsBeforeSend(event: *Event) ?*Event {
    before_send_saw_threads = hasThreadStacktrace(event);
    return event;
}

fn inspectInAppBeforeSend(event: *Event) ?*Event {
    before_send_first_frame_in_app = null;
    if (event.exception) |exception| {
        if (exception.values.len > 0) {
            if (exception.values[0].stacktrace) |stacktrace| {
                if (stacktrace.frames.len > 0) {
                    before_send_first_frame_in_app = stacktrace.frames[0].in_app;
                }
            }
        }
    }
    return event;
}

fn inspectServerNameBeforeSend(event: *Event) ?*Event {
    before_send_observed_server_name = event.server_name;
    return event;
}

fn inspectDistBeforeSend(event: *Event) ?*Event {
    before_send_observed_dist = event.dist;
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
    before_send_saw_runtime_context = false;
    before_send_saw_os_context = false;

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_send = inspectTraceContextBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("trace-context-message", .info) != null);
    try testing.expect(before_send_saw_trace_context);
    try testing.expect(before_send_saw_runtime_context);
    try testing.expect(before_send_saw_os_context);
}

test "Client default_integrations false injects trace context without runtime or os" {
    before_send_saw_trace_context = false;
    before_send_saw_runtime_context = false;
    before_send_saw_os_context = false;

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .default_integrations = false,
        .before_send = inspectTraceContextBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("trace-only-context-message", .info) != null);
    try testing.expect(before_send_saw_trace_context);
    try testing.expect(!before_send_saw_runtime_context);
    try testing.expect(!before_send_saw_os_context);
}

test "Client merges default trace contexts into existing custom event contexts" {
    before_send_saw_trace_context = false;
    before_send_saw_runtime_context = false;
    before_send_saw_os_context = false;

    var contexts_object = json.ObjectMap.init(testing.allocator);
    defer {
        var contexts_value: json.Value = .{ .object = contexts_object };
        scope_mod.deinitJsonValueDeep(testing.allocator, &contexts_value);
    }
    const custom_key = try testing.allocator.dupe(u8, "custom");
    const custom_value = try testing.allocator.dupe(u8, "value");
    try contexts_object.put(custom_key, .{ .string = custom_value });

    var event = Event.initMessage("custom-contexts", .info);
    event.contexts = .{ .object = contexts_object };

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_send = inspectTraceContextBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureEventId(&event) != null);
    try testing.expect(before_send_saw_trace_context);
    try testing.expect(before_send_saw_runtime_context);
    try testing.expect(before_send_saw_os_context);
    try testing.expect(contexts_object.get("trace") == null);
    try testing.expect(contexts_object.get("runtime") == null);
    try testing.expect(contexts_object.get("os") == null);
}

test "Client fallback server_name is applied when option is unset" {
    before_send_observed_server_name = null;

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .default_integrations = false,
        .before_send = inspectServerNameBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.default_server_name == null);
    client.default_server_name = try testing.allocator.dupe(u8, "detected-host");

    try testing.expect(client.captureMessageId("server-name-fallback", .info) != null);
    try testing.expect(before_send_observed_server_name != null);
    try testing.expectEqualStrings("detected-host", before_send_observed_server_name.?);
}

test "Client explicit server_name takes precedence over fallback server_name" {
    before_send_observed_server_name = null;

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .server_name = "explicit-host",
        .default_integrations = false,
        .before_send = inspectServerNameBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.default_server_name == null);
    client.default_server_name = try testing.allocator.dupe(u8, "detected-host");

    try testing.expect(client.captureMessageId("server-name-explicit", .info) != null);
    try testing.expect(before_send_observed_server_name != null);
    try testing.expectEqualStrings("explicit-host", before_send_observed_server_name.?);
}

test "Client default dist is applied to events when unset" {
    before_send_observed_dist = null;

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .dist = "42",
        .before_send = inspectDistBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("default-dist", .info) != null);
    try testing.expect(before_send_observed_dist != null);
    try testing.expectEqualStrings("42", before_send_observed_dist.?);
}

test "Client explicit event dist takes precedence over option dist" {
    before_send_observed_dist = null;

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .dist = "42",
        .before_send = inspectDistBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var event = Event.initMessage("custom-dist", .info);
    event.dist = "custom";
    try testing.expect(client.captureEventId(&event) != null);
    try testing.expect(before_send_observed_dist != null);
    try testing.expectEqualStrings("custom", before_send_observed_dist.?);
}

test "Client in_app_include marks matching exception frames as in_app=true" {
    before_send_first_frame_in_app = null;

    const include_patterns = [_][]const u8{"my.app"};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .in_app_include = &include_patterns,
        .before_send = inspectInAppBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const frames = [_]Frame{.{
        .module = "my.app.checkout",
        .function = "process_order",
    }};
    const values = [_]ExceptionValue{.{
        .type = "CheckoutError",
        .value = "declined",
        .stacktrace = Stacktrace{ .frames = &frames },
    }};
    var event = Event.initException(&values);

    try testing.expect(client.captureEventId(&event) != null);
    try testing.expectEqual(@as(?bool, true), before_send_first_frame_in_app);
}

test "Client in_app_exclude marks matching exception frames as in_app=false" {
    before_send_first_frame_in_app = null;

    const exclude_patterns = [_][]const u8{"vendor.lib"};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .in_app_exclude = &exclude_patterns,
        .before_send = inspectInAppBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const frames = [_]Frame{.{
        .module = "vendor.lib.payment",
        .function = "execute",
    }};
    const values = [_]ExceptionValue{.{
        .type = "VendorError",
        .value = "timeout",
        .stacktrace = Stacktrace{ .frames = &frames },
    }};
    var event = Event.initException(&values);

    try testing.expect(client.captureEventId(&event) != null);
    try testing.expectEqual(@as(?bool, false), before_send_first_frame_in_app);
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

test "Client default dist is applied to transactions when unset" {
    var state = PayloadTransportState.init(testing.allocator);
    defer state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .dist = "42",
        .traces_sample_rate = 1.0,
        .transport = .{
            .send_fn = payloadTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "GET /dist-default",
        .op = "http.server",
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 1), state.sent_count);
    try testing.expect(state.last_payload != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"dist\":\"42\"") != null);
}

test "Client explicit transaction dist takes precedence over option dist" {
    var state = PayloadTransportState.init(testing.allocator);
    defer state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .dist = "42",
        .traces_sample_rate = 1.0,
        .transport = .{
            .send_fn = payloadTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "GET /dist-override",
        .op = "http.server",
        .dist = "custom",
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 1), state.sent_count);
    try testing.expect(state.last_payload != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"dist\":\"custom\"") != null);
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

test "Client before_send_log drops replacement pointers for memory safety" {
    replacement_log_for_test = LogEntry.init("replacement", .info);

    var state = CustomTransportState{};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_send_log = replaceLogPointer,
        .transport = .{
            .send_fn = customTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureLogMessage("original-log", .warn);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 0), state.sent_count);
}

test "Client before_send_log can drop log entries" {
    var state = CustomTransportState{};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .before_send_log = dropLogBeforeSend,
        .transport = .{
            .send_fn = customTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureLogMessage("drop-log", .debug);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 0), state.sent_count);
}

test "Client enable_logs false disables log submissions" {
    var state = CustomTransportState{};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .enable_logs = false,
        .transport = .{
            .send_fn = customTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureLogMessage("disabled-log", .info);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 0), state.sent_count);
}

test "Client max_request_body_size drops oversized envelopes" {
    var state = CustomTransportState{};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .max_request_body_size = 1,
        .transport = .{
            .send_fn = customTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("too-large", .err) == null);
    client.captureLogMessage("too-large-log", .err);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 0), state.sent_count);
}

test "Client custom transport receives submitted envelopes" {
    var state = CustomTransportState{};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .transport = .{
            .send_fn = customTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("custom-transport", .warning) != null);
    _ = client.flush(1000);
    try testing.expectEqual(@as(usize, 1), state.sent_count);
}

test "Client before_send_transaction drops replacement pointers for memory safety" {
    replacement_txn_for_test = Transaction.init(testing.allocator, .{
        .name = "replacement",
    });
    defer replacement_txn_for_test.deinit();

    var state = CustomTransportState{};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .before_send_transaction = replaceTransactionPointer,
        .transport = .{
            .send_fn = customTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "original",
        .op = "http.server",
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 0), state.sent_count);
}

test "Client before_send_transaction can drop transaction events" {
    var state = CustomTransportState{};
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .before_send_transaction = dropTransactionBeforeSend,
        .transport = .{
            .send_fn = customTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "drop-txn",
        .op = "http.server",
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 0), state.sent_count);
}

test "Client before_send_transaction can mutate in place" {
    before_send_transaction_saw_expected_name = false;

    var state = PayloadTransportState.init(testing.allocator);
    defer state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .before_send_transaction = inspectTransactionBeforeSend,
        .transport = .{
            .send_fn = payloadTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "POST /checkout",
        .op = "http.server",
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    _ = client.flush(1000);

    try testing.expect(before_send_transaction_saw_expected_name);
    try testing.expectEqual(@as(usize, 1), state.sent_count);
    try testing.expect(state.last_payload != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"op\":\"http.server.processed\"") != null);
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

test "Client startTransactionWithTimestamp applies explicit start timestamp" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const explicit_start = 1704067200.125;
    var txn = client.startTransactionWithTimestamp(.{
        .name = "GET /with-start",
        .op = "http.server",
    }, explicit_start);
    defer txn.deinit();

    try testing.expectEqual(explicit_start, txn.start_timestamp);
}

test "Client startTransaction normalizes invalid explicit sample rates" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var too_high = client.startTransaction(.{
        .name = "GET /invalid-rate-high",
        .sample_rate = 1.5,
    });
    defer too_high.deinit();

    try testing.expectEqual(@as(f64, 0.0), too_high.sample_rate);
    try testing.expect(!too_high.sampled);

    var too_low = client.startTransaction(.{
        .name = "GET /invalid-rate-low",
        .sample_rate = -0.1,
    });
    defer too_low.deinit();

    try testing.expectEqual(@as(f64, 0.0), too_low.sample_rate);
    try testing.expect(!too_low.sampled);
}

test "Client startTransactionFromSentryTrace continues upstream trace context" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = try client.startTransactionFromSentryTrace(
        .{ .name = "GET /continued" },
        "0123456789abcdef0123456789abcdef-89abcdef01234567-0",
    );
    defer txn.deinit();

    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", txn.trace_id[0..]);
    try testing.expect(txn.parent_span_id != null);
    try testing.expectEqualStrings("89abcdef01234567", txn.parent_span_id.?[0..]);
    try testing.expectEqual(@as(?bool, false), txn.parent_sampled);
    try testing.expectEqual(@as(f64, 0.0), txn.sample_rate);
    try testing.expect(!txn.sampled);
}

test "Client startTransactionFromPropagationHeaders reads baggage sampled fallback" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = try client.startTransactionFromPropagationHeaders(
        .{ .name = "GET /baggage-only" },
        null,
        "sentry-trace_id=fedcba9876543210fedcba9876543210,sentry-sampled=false",
    );
    defer txn.deinit();

    try testing.expectEqualStrings("fedcba9876543210fedcba9876543210", txn.trace_id[0..]);
    try testing.expectEqual(@as(?bool, false), txn.parent_sampled);
    try testing.expectEqual(@as(f64, 0.0), txn.sample_rate);
    try testing.expect(!txn.sampled);
}

test "Client startTransactionFromPropagationHeaders applies baggage sample_rate" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = try client.startTransactionFromPropagationHeaders(
        .{ .name = "GET /baggage-sample-rate" },
        null,
        "sentry-trace_id=fedcba9876543210fedcba9876543210,sentry-sample_rate=0.000000",
    );
    defer txn.deinit();

    try testing.expectEqualStrings("fedcba9876543210fedcba9876543210", txn.trace_id[0..]);
    try testing.expectEqual(@as(f64, 0.0), txn.sample_rate);
    try testing.expect(!txn.sampled);
}

test "Client sentryTraceHeader and baggageHeader include expected values" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .environment = "staging",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "POST /checkout",
        .op = "http.server",
    });
    defer txn.deinit();

    const sentry_trace = try client.sentryTraceHeader(&txn, testing.allocator);
    defer testing.allocator.free(sentry_trace);
    try testing.expect(std.mem.indexOf(u8, sentry_trace, txn.trace_id[0..]) != null);
    try testing.expect(std.mem.indexOf(u8, sentry_trace, txn.span_id[0..]) != null);

    const baggage = try client.baggageHeader(&txn, testing.allocator);
    defer testing.allocator.free(baggage);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-trace_id=") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-public_key=examplePublicKey") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-release=my-app%401.0.0") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-environment=staging") != null);
}

test "Client baggageHeader preserves third-party incoming baggage members" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = try client.startTransactionFromPropagationHeaders(
        .{ .name = "GET /merged-baggage", .op = "http.server" },
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-89abcdef01234567-1",
        "vendor=one,foo=bar,sentry-trace_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,sentry-public_key=oldkey,sentry-release=legacy",
    );
    defer txn.deinit();

    const baggage = try client.baggageHeader(&txn, testing.allocator);
    defer testing.allocator.free(baggage);

    const expected_trace = try std.fmt.allocPrint(testing.allocator, "sentry-trace_id={s}", .{txn.trace_id[0..]});
    defer testing.allocator.free(expected_trace);

    try testing.expect(std.mem.indexOf(u8, baggage, "vendor=one") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "foo=bar") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, expected_trace) != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-public_key=examplePublicKey") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-release=legacy") == null);
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

test "Client request session mode serializes session updates without duration" {
    var state = PayloadTransportState.init(testing.allocator);
    defer state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .session_mode = .request,
        .transport = .{
            .send_fn = payloadTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    client.endSession(.exited);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 1), state.sent_count);
    try testing.expect(state.last_payload != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"type\":\"session\"") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"status\":\"exited\"") != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"duration\"") == null);
}

test "Client session distinct id uses scope user id" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.setUser(.{
        .id = "user-42",
        .email = "test@example.com",
    });
    client.startSession();

    try testing.expect(client.session != null);
    try testing.expect(client.session.?.did != null);
    try testing.expectEqualStrings("user-42", client.session.?.did.?);
}

test "Client session distinct id falls back to email then username" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.setUser(.{
        .email = "mail@example.com",
        .username = "fallback-user",
    });
    client.startSession();

    try testing.expect(client.session != null);
    try testing.expect(client.session.?.did != null);
    try testing.expectEqualStrings("mail@example.com", client.session.?.did.?);

    client.endSession(.exited);

    client.setUser(.{
        .username = "fallback-user",
    });
    client.startSession();

    try testing.expect(client.session != null);
    try testing.expect(client.session.?.did != null);
    try testing.expectEqualStrings("fallback-user", client.session.?.did.?);
}

test "Client session distinct id can be populated after session start" {
    var state = PayloadTransportState.init(testing.allocator);
    defer state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .release = "my-app@1.0.0",
        .transport = .{
            .send_fn = payloadTransportSendFn,
            .ctx = &state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    try testing.expect(client.session != null);
    try testing.expect(client.session.?.did == null);

    client.setUser(.{ .id = "late-user" });
    client.endSession(.exited);
    _ = client.flush(1000);

    try testing.expectEqual(@as(usize, 1), state.sent_count);
    try testing.expect(state.last_payload != null);
    try testing.expect(std.mem.indexOf(u8, state.last_payload.?, "\"did\":\"late-user\"") != null);
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
