const std = @import("std");
const Uuid = @import("uuid.zig").Uuid;
const ts = @import("timestamp.zig");
const testing = std.testing;
const json = std.json;

/// Sentry event severity level.
pub const Level = enum {
    debug,
    info,
    warning,
    err,
    fatal,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .debug => "debug",
            .info => "info",
            .warning => "warning",
            .err => "error",
            .fatal => "fatal",
        };
    }

    /// Custom JSON serialization: emit as string.
    pub fn jsonStringify(self: Level, jw: anytype) !void {
        try jw.write(self.toString());
    }
};

/// Sentry user context.
pub const User = struct {
    id: ?[]const u8 = null,
    email: ?[]const u8 = null,
    username: ?[]const u8 = null,
    ip_address: ?[]const u8 = null,
    segment: ?[]const u8 = null,
};

/// A single stack frame.
pub const Frame = struct {
    filename: ?[]const u8 = null,
    function: ?[]const u8 = null,
    module: ?[]const u8 = null,
    lineno: ?u32 = null,
    colno: ?u32 = null,
    abs_path: ?[]const u8 = null,
    instruction_addr: ?[]const u8 = null,
    in_app: ?bool = null,
};

/// Stack trace containing ordered frames.
pub const Stacktrace = struct {
    frames: []const Frame = &.{},
};

/// A single exception value.
pub const ExceptionValue = struct {
    type: ?[]const u8 = null,
    value: ?[]const u8 = null,
    module: ?[]const u8 = null,
    stacktrace: ?Stacktrace = null,
};

/// Exception interface containing one or more exception values.
pub const ExceptionInterface = struct {
    values: []const ExceptionValue = &.{},
};

/// Formatted message interface.
pub const Message = struct {
    formatted: ?[]const u8 = null,
    message: ?[]const u8 = null,
    params: ?[]const []const u8 = null,
};

/// A breadcrumb recording an event that happened before the main event.
pub const Breadcrumb = struct {
    timestamp: ?f64 = null,
    type: ?[]const u8 = null,
    category: ?[]const u8 = null,
    message: ?[]const u8 = null,
    level: ?Level = null,
    data: ?json.Value = null,
};

/// The main Sentry event structure.
pub const Event = struct {
    event_id: [32]u8,
    timestamp: f64,
    platform: []const u8 = "zig",
    level: ?Level = null,
    logger: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    release: ?[]const u8 = null,
    dist: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    transaction: ?[]const u8 = null,
    message: ?Message = null,
    exception: ?ExceptionInterface = null,
    threads: ?json.Value = null,
    tags: ?json.Value = null,
    extra: ?json.Value = null,
    user: ?User = null,
    contexts: ?json.Value = null,
    breadcrumbs: ?[]const Breadcrumb = null,
    fingerprint: ?[]const []const u8 = null,

    /// Create a new event with a generated UUID and current timestamp.
    pub fn init() Event {
        const uuid = Uuid.v4();
        return Event{
            .event_id = uuid.toHex(),
            .timestamp = ts.now(),
        };
    }

    /// Create a new event with a message and level.
    pub fn initMessage(msg: []const u8, level: Level) Event {
        var event = Event.init();
        event.level = level;
        event.message = Message{
            .formatted = msg,
        };
        return event;
    }

    /// Create a new event with an exception.
    /// The caller must ensure that `values` outlives the returned Event.
    pub fn initException(values: []const ExceptionValue) Event {
        var event = Event.init();
        event.level = .err;
        event.exception = ExceptionInterface{
            .values = values,
        };
        return event;
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test "Event.init generates valid 32-char hex event_id" {
    const event = Event.init();
    try testing.expectEqual(@as(usize, 32), event.event_id.len);
    for (event.event_id) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "Event.init sets timestamp > 1704067200.0" {
    const event = Event.init();
    try testing.expect(event.timestamp > 1704067200.0);
}

test "Event.initMessage sets message correctly" {
    const event = Event.initMessage("test message", .info);
    try testing.expectEqual(Level.info, event.level.?);
    try testing.expectEqualStrings("test message", event.message.?.formatted.?);
}

test "Event.initException sets exception" {
    const values = [_]ExceptionValue{.{
        .type = "TypeError",
        .value = "null is not an object",
    }};
    const event = Event.initException(&values);
    try testing.expectEqual(Level.err, event.level.?);
    try testing.expectEqual(@as(usize, 1), event.exception.?.values.len);
    try testing.expectEqualStrings("TypeError", event.exception.?.values[0].type.?);
    try testing.expectEqualStrings("null is not an object", event.exception.?.values[0].value.?);
}

test "Level.toString maps correctly" {
    try testing.expectEqualStrings("debug", Level.debug.toString());
    try testing.expectEqualStrings("info", Level.info.toString());
    try testing.expectEqualStrings("warning", Level.warning.toString());
    try testing.expectEqualStrings("error", Level.err.toString());
    try testing.expectEqualStrings("fatal", Level.fatal.toString());
}

test "Event serializes to JSON containing event_id, message, level" {
    const event = Event.initMessage("hello world", .warning);

    const json_str = try json.Stringify.valueAlloc(
        testing.allocator,
        event,
        .{ .emit_null_optional_fields = false },
    );
    defer testing.allocator.free(json_str);

    // Verify event_id is present
    try testing.expect(std.mem.indexOf(u8, json_str, "\"event_id\"") != null);
    // Verify message is present
    try testing.expect(std.mem.indexOf(u8, json_str, "\"hello world\"") != null);
    // Verify level serializes as string "warning"
    try testing.expect(std.mem.indexOf(u8, json_str, "\"warning\"") != null);
    // Verify platform is present
    try testing.expect(std.mem.indexOf(u8, json_str, "\"zig\"") != null);
}
