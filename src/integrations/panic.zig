const std = @import("std");
const testing = std.testing;

const Hub = @import("../hub.zig").Hub;
const Client = @import("../client.zig").Client;
const SendOutcome = @import("../worker.zig").SendOutcome;

pub const Config = struct {
    exception_type: []const u8 = "Panic",
    flush_timeout_ms: u64 = 2000,
};

var config_mutex: std.Thread.Mutex = .{};
var config: Config = .{};
threadlocal var in_panic_capture: bool = false;

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

/// Capture panic text and then forward to Zig's default panic printer/abort path.
///
/// Usage:
///
/// ```zig
/// pub const panic = std.debug.FullPanic(sentry.integrations.panic.captureAndForward);
/// ```
pub fn captureAndForward(msg: []const u8, return_address: ?usize) noreturn {
    capture(msg);
    std.debug.defaultPanic(msg, return_address);
}

fn capture(msg: []const u8) void {
    if (in_panic_capture) return;
    in_panic_capture = true;
    defer in_panic_capture = false;

    const cfg = currentConfig();
    if (Hub.current()) |hub| {
        _ = hub.captureExceptionId(cfg.exception_type, msg);
        _ = hub.flush(cfg.flush_timeout_ms);
    }
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

test "panic integration captures panic message through current hub" {
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
        .exception_type = "ZigPanic",
        .flush_timeout_ms = 1000,
    });
    defer reset();

    capture("panic parity test");

    try testing.expect(payload_state.payloads.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "\"type\":\"event\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "\"ZigPanic\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "panic parity test") != null);
}
