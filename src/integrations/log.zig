const std = @import("std");
const testing = std.testing;

const Hub = @import("../hub.zig").Hub;
const LogLevel = @import("../log.zig").LogLevel;
const Client = @import("../client.zig").Client;
const SendOutcome = @import("../worker.zig").SendOutcome;

pub const Config = struct {
    /// Minimum std.log level to capture (`.info` captures `.err/.warn/.info`).
    min_level: std.log.Level = .debug,
    /// Prefix captured log body with `[scope]` when scope is not `default`.
    include_scope_prefix: bool = true,
    /// Forward to Zig default logger in addition to Sentry capture.
    forward_to_default_logger: bool = true,
    /// Maximum bytes in a captured log body.
    max_message_bytes: usize = 2048,
};

var config_mutex: std.Thread.Mutex = .{};
var config: Config = .{};
threadlocal var in_capture: bool = false;

pub fn install(new_config: Config) void {
    config_mutex.lock();
    defer config_mutex.unlock();
    config = new_config;
}

pub fn reset() void {
    install(.{});
}

pub fn currentConfig() Config {
    config_mutex.lock();
    defer config_mutex.unlock();
    return config;
}

pub fn setup(_: *Client, ctx: ?*anyopaque) void {
    if (ctx) |ptr| {
        const cfg: *const Config = @ptrCast(@alignCast(ptr));
        install(cfg.*);
    } else {
        install(.{});
    }
}

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const cfg = currentConfig();
    if (cfg.forward_to_default_logger) {
        std.log.defaultLog(level, scope, format, args);
    }

    if (!isCapturedLevel(level, cfg.min_level)) return;
    if (cfg.max_message_bytes == 0) return;
    if (in_capture) return;

    in_capture = true;
    defer in_capture = false;

    var formatted_buf: [4096]u8 = undefined;
    const formatted = std.fmt.bufPrint(&formatted_buf, format, args) catch "log message exceeded formatter buffer";

    var scoped_buf: [4096]u8 = undefined;
    const message_with_scope = if (cfg.include_scope_prefix and !std.mem.eql(u8, @tagName(scope), "default"))
        std.fmt.bufPrint(&scoped_buf, "[{s}] {s}", .{ @tagName(scope), formatted }) catch formatted
    else
        formatted;

    const final_message = if (message_with_scope.len > cfg.max_message_bytes)
        message_with_scope[0..cfg.max_message_bytes]
    else
        message_with_scope;

    if (Hub.current()) |hub| {
        hub.captureLogMessage(final_message, toSentryLogLevel(level));
    }
}

fn isCapturedLevel(level: std.log.Level, min_level: std.log.Level) bool {
    return levelPriority(level) <= levelPriority(min_level);
}

fn levelPriority(level: std.log.Level) u8 {
    return switch (level) {
        .err => 0,
        .warn => 1,
        .info => 2,
        .debug => 3,
    };
}

fn toSentryLogLevel(level: std.log.Level) LogLevel {
    return switch (level) {
        .err => .err,
        .warn => .warn,
        .info => .info,
        .debug => .debug,
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

test "log integration level filtering uses min_level threshold" {
    try testing.expect(isCapturedLevel(.err, .info));
    try testing.expect(isCapturedLevel(.warn, .info));
    try testing.expect(isCapturedLevel(.info, .info));
    try testing.expect(!isCapturedLevel(.debug, .info));
}

test "log integration captures via current hub with scope prefix" {
    var payload_state = PayloadState{ .allocator = testing.allocator };
    defer payload_state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .transport = .{
            .send_fn = payloadSendFn,
            .ctx = &payload_state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();
    defer _ = Hub.clearCurrent();
    _ = Hub.setCurrent(&hub);

    install(.{
        .min_level = .info,
        .include_scope_prefix = true,
        .forward_to_default_logger = false,
        .max_message_bytes = 256,
    });
    defer reset();

    logFn(.debug, .checkout, "ignored {d}", .{1});
    logFn(.warn, .checkout, "payment timeout {d}", .{42});

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var found_checkout_log = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"log\"") != null and
            std.mem.indexOf(u8, payload, "[checkout] payment timeout 42") != null)
        {
            found_checkout_log = true;
        }
        try testing.expect(std.mem.indexOf(u8, payload, "ignored 1") == null);
    }
    try testing.expect(found_checkout_log);
}
