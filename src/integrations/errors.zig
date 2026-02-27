const std = @import("std");
const testing = std.testing;

const Hub = @import("../hub.zig").Hub;
const Client = @import("../client.zig").Client;
const SendOutcome = @import("../worker.zig").SendOutcome;

fn assertErrorUnion(comptime T: type) void {
    switch (@typeInfo(T)) {
        .error_union => {},
        else => @compileError("errors integration helpers require an error union type"),
    }
}

/// Capture returned error (if any) through current Hub and forward the original result unchanged.
pub fn captureResult(result: anytype) @TypeOf(result) {
    const ReturnType = @TypeOf(result);
    comptime assertErrorUnion(ReturnType);

    return result catch |err| {
        if (Hub.current()) |hub| {
            _ = hub.captureErrorId(err);
        }
        return err;
    };
}

/// Same as `captureResult`, but reports a custom exception type instead of `ZigError`.
pub fn captureResultAs(result: anytype, exception_type: []const u8) @TypeOf(result) {
    const ReturnType = @TypeOf(result);
    comptime assertErrorUnion(ReturnType);

    return result catch |err| {
        if (Hub.current()) |hub| {
            _ = hub.captureExceptionId(exception_type, @errorName(err));
        }
        return err;
    };
}

/// Run a fallible function and auto-capture returned errors through current Hub.
pub fn runAndCapture(func: anytype, args: anytype) @TypeOf(@call(.auto, func, args)) {
    const ReturnType = @TypeOf(@call(.auto, func, args));
    comptime assertErrorUnion(ReturnType);
    return captureResult(@call(.auto, func, args));
}

/// Run a fallible function and auto-capture returned errors with custom exception type.
pub fn runAndCaptureAs(
    func: anytype,
    args: anytype,
    exception_type: []const u8,
) @TypeOf(@call(.auto, func, args)) {
    const ReturnType = @TypeOf(@call(.auto, func, args));
    comptime assertErrorUnion(ReturnType);
    return captureResultAs(@call(.auto, func, args), exception_type);
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

const DemoError = error{
    Timeout,
    InvalidInput,
};

fn failingOperation(_: usize) DemoError!usize {
    return error.Timeout;
}

fn successfulOperation(value: usize) DemoError!usize {
    return value + 1;
}

test "errors integration captures returned errors and preserves success value" {
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

    const ok_value = try captureResult(successfulOperation(41));
    try testing.expectEqual(@as(usize, 42), ok_value);

    try testing.expectError(error.Timeout, captureResult(failingOperation(1)));
    try testing.expectError(error.Timeout, runAndCapture(failingOperation, .{2}));
    try testing.expectError(error.Timeout, runAndCaptureAs(failingOperation, .{3}, "DomainFailure"));

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 3);

    var saw_default_error = false;
    var saw_custom_error = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"event\"") == null) continue;
        if (std.mem.indexOf(u8, payload, "\"type\":\"ZigError\"") != null and
            std.mem.indexOf(u8, payload, "\"value\":\"Timeout\"") != null)
        {
            saw_default_error = true;
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"DomainFailure\"") != null and
            std.mem.indexOf(u8, payload, "\"value\":\"Timeout\"") != null)
        {
            saw_custom_error = true;
        }
    }
    try testing.expect(saw_default_error);
    try testing.expect(saw_custom_error);
}
