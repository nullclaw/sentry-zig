const std = @import("std");
const testing = std.testing;

const Client = @import("../client.zig").Client;
const Integration = @import("../client.zig").Integration;
const Options = @import("../client.zig").Options;
const Hub = @import("../hub.zig").Hub;
const SendOutcome = @import("../worker.zig").SendOutcome;
const http = @import("http.zig");
const log = @import("log.zig");
const panic_integration = @import("panic.zig");

const DEFAULTS = [_]Integration{
    .{ .setup = log.setup },
    .{ .setup = panic_integration.setup },
};

/// Returns a static slice of built-in setup integrations intended for
/// `Options.integrations`.
///
/// This preset installs default runtime behavior for:
/// - std.log capture (`integrations.log`)
/// - panic capture (`integrations.panic`)
pub fn defaults() []const Integration {
    return &DEFAULTS;
}

/// Convenience std options for applications that want Sentry log capture with
/// minimal boilerplate.
pub fn stdOptions() std.Options {
    return .{
        .logFn = log.logFn,
    };
}

/// Convenience panic handler alias for application root declaration:
///
/// `pub const panic = sentry.integrations.auto.panicHandler;`
pub const panicHandler = std.debug.FullPanic(panic_integration.captureAndForward);

pub const RuntimeInstallOptions = struct {
    log: log.Config = .{},
    panic: panic_integration.Config = .{},
};

/// Install default runtime integration configs in one call.
pub fn installRuntime(options: RuntimeInstallOptions) void {
    log.install(options.log);
    panic_integration.install(options.panic);
}

/// Initialize a client with built-in integration defaults prepended to any
/// user-provided `Options.integrations`.
pub fn initWithDefaults(allocator: std.mem.Allocator, options: Options) !*Client {
    var merged: std.ArrayListUnmanaged(Integration) = .{};
    defer merged.deinit(allocator);

    try merged.appendSlice(allocator, defaults());
    if (options.integrations) |user_integrations| {
        try merged.appendSlice(allocator, user_integrations);
    }

    var effective_options = options;
    effective_options.integrations = merged.items;
    return Client.init(allocator, effective_options);
}

/// Guard returned by `initGlobalWithDefaults`.
///
/// It owns the created client and detached hub and restores previous TLS hub
/// on deinitialization.
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

/// Initialize client with default integrations, create Hub, and bind it as
/// current TLS hub.
pub fn initGlobalWithDefaults(allocator: std.mem.Allocator, options: Options) !InitGuard {
    const client = try initWithDefaults(allocator, options);
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

/// Install runtime config and initialize client with default integrations.
pub fn initWithDefaultsAndRuntime(
    allocator: std.mem.Allocator,
    options: Options,
    runtime_options: RuntimeInstallOptions,
) !*Client {
    installRuntime(runtime_options);
    return initWithDefaults(allocator, options);
}

/// Install runtime config and initialize global hub with default integrations.
pub fn initGlobalWithDefaultsAndRuntime(
    allocator: std.mem.Allocator,
    options: Options,
    runtime_options: RuntimeInstallOptions,
) !InitGuard {
    installRuntime(runtime_options);
    return initGlobalWithDefaults(allocator, options);
}

/// Run incoming HTTP handler using client from current hub.
pub fn runIncomingRequestWithCurrentHub(
    allocator: std.mem.Allocator,
    request_options: http.RequestOptions,
    handler: http.IncomingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    const hub = Hub.current() orelse return error.NoCurrentHub;
    return http.runIncomingRequest(
        allocator,
        hub.clientPtr(),
        request_options,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Same as `runIncomingRequestWithCurrentHub`, with propagation headers auto-extracted from raw headers.
pub fn runIncomingRequestFromHeadersWithCurrentHub(
    allocator: std.mem.Allocator,
    request_options: http.RequestOptions,
    headers: []const @import("../propagation.zig").PropagationHeader,
    handler: http.IncomingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: http.IncomingRunOptions,
) anyerror!u16 {
    const hub = Hub.current() orelse return error.NoCurrentHub;
    return http.runIncomingRequestFromHeaders(
        allocator,
        hub.clientPtr(),
        request_options,
        headers,
        handler,
        handler_ctx,
        run_options,
    );
}

/// Run outgoing HTTP operation requiring an already active current hub/span context.
pub fn runOutgoingRequestWithCurrentHub(
    request_options: http.OutgoingRequestOptions,
    handler: http.OutgoingHandlerFn,
    handler_ctx: ?*anyopaque,
    run_options: http.OutgoingRunOptions,
) anyerror!u16 {
    if (Hub.current() == null) return error.NoCurrentHub;
    return http.runOutgoingRequest(request_options, handler, handler_ctx, run_options);
}

var lookup_called: bool = false;
var lookup_received_null: bool = false;

fn inspectLookup(ctx: ?*anyopaque) void {
    lookup_called = true;
    lookup_received_null = ctx == null;
}

fn testUserIntegrationSetup(_: *Client, ctx: ?*anyopaque) void {
    const called: *bool = @ptrCast(@alignCast(ctx.?));
    called.* = true;
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

fn incomingOkHandler(_: *http.RequestContext, _: ?*anyopaque) anyerror!u16 {
    return 204;
}

fn outgoingOkHandler(_: *http.OutgoingRequestContext, _: ?*anyopaque) anyerror!u16 {
    return 200;
}

test "auto defaults expose log and panic setup callbacks" {
    const values = defaults();
    try testing.expectEqual(@as(usize, 2), values.len);
    try testing.expect(values[0].setup == log.setup);
    try testing.expect(values[1].setup == panic_integration.setup);
    try testing.expect(values[0].ctx == null);
    try testing.expect(values[1].ctx == null);
}

test "initWithDefaults prepends built-ins and keeps user integration callbacks" {
    var called = false;
    const integration = Integration{
        .setup = testUserIntegrationSetup,
        .ctx = &called,
    };

    const client = try initWithDefaults(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .integrations = &.{integration},
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(called);

    lookup_called = false;
    lookup_received_null = false;
    try testing.expect(client.withIntegration(log.setup, inspectLookup));
    try testing.expect(lookup_called);
    try testing.expect(lookup_received_null);

    lookup_called = false;
    lookup_received_null = true;
    try testing.expect(client.withIntegration(panic_integration.setup, inspectLookup));
    try testing.expect(lookup_called);
    try testing.expect(lookup_received_null);
}

test "initGlobalWithDefaults binds and restores TLS hub" {
    try testing.expect(Hub.current() == null);

    var guard = try initGlobalWithDefaults(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    try testing.expect(Hub.current() != null);
    try testing.expect(Hub.current().? == guard.hubPtr());

    guard.deinit();
    try testing.expect(Hub.current() == null);
}

test "stdOptions wires logFn integration function" {
    const options = stdOptions();
    try testing.expect(options.logFn == log.logFn);
}

test "installRuntime updates log and panic integration configs" {
    log.reset();
    panic_integration.reset();
    defer {
        log.reset();
        panic_integration.reset();
    }

    installRuntime(.{
        .log = .{
            .min_level = .info,
            .include_scope_prefix = false,
            .forward_to_default_logger = false,
            .max_message_bytes = 64,
        },
        .panic = .{
            .exception_type = "AutoRuntimePanic",
            .flush_timeout_ms = 321,
        },
    });

    const log_config = log.currentConfig();
    try testing.expectEqual(std.log.Level.info, log_config.min_level);
    try testing.expect(!log_config.include_scope_prefix);
    try testing.expect(!log_config.forward_to_default_logger);
    try testing.expectEqual(@as(usize, 64), log_config.max_message_bytes);

    const panic_config = panic_integration.currentConfig();
    try testing.expectEqualStrings("AutoRuntimePanic", panic_config.exception_type);
    try testing.expectEqual(@as(u64, 321), panic_config.flush_timeout_ms);
}

test "initWithDefaultsAndRuntime applies runtime config and integration defaults" {
    log.reset();
    panic_integration.reset();
    defer {
        log.reset();
        panic_integration.reset();
    }

    const client = try initWithDefaultsAndRuntime(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    }, .{
        .log = .{
            .min_level = .warn,
            .forward_to_default_logger = false,
        },
        .panic = .{
            .exception_type = "AutoInitPanic",
        },
    });
    defer client.deinit();

    const log_config = log.currentConfig();
    try testing.expectEqual(std.log.Level.warn, log_config.min_level);
    try testing.expect(!log_config.forward_to_default_logger);
    try testing.expect(client.withIntegration(log.setup, inspectLookup));
    try testing.expect(client.withIntegration(panic_integration.setup, inspectLookup));

    const panic_config = panic_integration.currentConfig();
    try testing.expectEqualStrings("AutoInitPanic", panic_config.exception_type);
}

test "runIncomingRequestWithCurrentHub uses current hub client" {
    var payload_state = PayloadState{ .allocator = testing.allocator };
    defer payload_state.deinit();

    const client = try initWithDefaults(testing.allocator, .{
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

    const status_code = try runIncomingRequestWithCurrentHub(
        testing.allocator,
        .{
            .name = "GET /auto/current",
            .method = "GET",
            .url = "https://api.example.com/auto/current",
        },
        incomingOkHandler,
        null,
        .{},
    );
    try testing.expectEqual(@as(u16, 204), status_code);

    try testing.expect(client.flush(1000));

    var saw_transaction = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") == null) continue;
        saw_transaction = true;
        try testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"GET /auto/current\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"op\":\"http.server\"") != null);
        try testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"ok\"") != null);
    }
    try testing.expect(saw_transaction);
}

test "runIncomingRequestWithCurrentHub requires current hub" {
    _ = Hub.clearCurrent();
    try testing.expect(Hub.current() == null);

    try testing.expectError(
        error.NoCurrentHub,
        runIncomingRequestWithCurrentHub(
            testing.allocator,
            .{ .name = "GET /auto/no-hub" },
            incomingOkHandler,
            null,
            .{},
        ),
    );
}

test "runIncomingRequestFromHeadersWithCurrentHub continues trace from extracted headers" {
    var payload_state = PayloadState{ .allocator = testing.allocator };
    defer payload_state.deinit();

    const client = try initWithDefaults(testing.allocator, .{
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

    const headers = [_]@import("../propagation.zig").PropagationHeader{
        .{
            .name = "traceparent",
            .value = "00-0123456789abcdef0123456789abcdef-89abcdef01234567-01",
        },
        .{
            .name = "baggage",
            .value = "sentry-release=edge,sentry-environment=prod",
        },
    };

    const status_code = try runIncomingRequestFromHeadersWithCurrentHub(
        testing.allocator,
        .{
            .name = "GET /auto/headers",
            .method = "GET",
            .url = "https://api.example.com/auto/headers",
        },
        &headers,
        incomingOkHandler,
        null,
        .{},
    );
    try testing.expectEqual(@as(u16, 204), status_code);

    try testing.expect(client.flush(1000));

    var saw_trace = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"transaction\"") == null) continue;
        if (std.mem.indexOf(u8, payload, "\"trace_id\":\"0123456789abcdef0123456789abcdef\"") != null) {
            saw_trace = true;
        }
    }
    try testing.expect(saw_trace);
}

test "runOutgoingRequestWithCurrentHub requires current hub" {
    _ = Hub.clearCurrent();
    try testing.expect(Hub.current() == null);

    try testing.expectError(
        error.NoCurrentHub,
        runOutgoingRequestWithCurrentHub(
            .{
                .method = "GET",
                .url = "https://api.example.com/no-hub",
            },
            outgoingOkHandler,
            null,
            .{},
        ),
    );
}
