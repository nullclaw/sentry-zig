const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.io.Writer;
const testing = std.testing;
const json = std.json;

const ts = @import("timestamp.zig");

pub const LogLevel = enum {
    trace,
    debug,
    info,
    warn,
    err,
    fatal,

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .trace => "trace",
            .debug => "debug",
            .info => "info",
            .warn => "warn",
            .err => "error",
            .fatal => "fatal",
        };
    }

    pub fn jsonStringify(self: LogLevel, jw: anytype) !void {
        try jw.write(self.toString());
    }
};

pub const LogEntry = struct {
    timestamp: f64,
    level: LogLevel = .info,
    body: []const u8,
    trace_id: ?[32]u8 = null,
    attributes: ?json.Value = null,

    pub fn init(body: []const u8, level: LogLevel) LogEntry {
        return .{
            .timestamp = ts.now(),
            .level = level,
            .body = body,
        };
    }

    pub fn toJson(self: *const LogEntry, allocator: Allocator) ![]u8 {
        var aw: Writer.Allocating = .init(allocator);
        errdefer aw.deinit();
        const w = &aw.writer;

        try w.writeAll("{\"timestamp\":");
        try w.print("{d:.3}", .{self.timestamp});
        try w.writeAll(",\"level\":\"");
        try w.writeAll(self.level.toString());
        try w.writeAll("\",\"body\":");
        try json.Stringify.value(self.body, .{}, w);

        if (self.trace_id) |trace_id| {
            try w.writeAll(",\"trace_id\":\"");
            try w.writeAll(&trace_id);
            try w.writeByte('"');
        }

        if (self.attributes) |attributes| {
            try w.writeAll(",\"attributes\":");
            try json.Stringify.value(attributes, .{}, w);
        }

        try w.writeByte('}');
        return try aw.toOwnedSlice();
    }
};

test "LogLevel.toString maps correctly" {
    try testing.expectEqualStrings("trace", LogLevel.trace.toString());
    try testing.expectEqualStrings("debug", LogLevel.debug.toString());
    try testing.expectEqualStrings("info", LogLevel.info.toString());
    try testing.expectEqualStrings("warn", LogLevel.warn.toString());
    try testing.expectEqualStrings("error", LogLevel.err.toString());
    try testing.expectEqualStrings("fatal", LogLevel.fatal.toString());
}

test "LogEntry.init sets body level and timestamp" {
    const entry = LogEntry.init("checkout-log", .warn);
    try testing.expectEqualStrings("checkout-log", entry.body);
    try testing.expectEqual(LogLevel.warn, entry.level);
    try testing.expect(entry.timestamp > 1704067200.0);
}

test "LogEntry.toJson includes trace_id and attributes when set" {
    var attributes = json.ObjectMap.init(testing.allocator);
    defer {
        var value: json.Value = .{ .object = attributes };
        @import("scope.zig").deinitJsonValueDeep(testing.allocator, &value);
    }
    try attributes.put(try testing.allocator.dupe(u8, "service"), .{ .string = try testing.allocator.dupe(u8, "checkout") });

    var entry = LogEntry.init("log body", .info);
    entry.trace_id = [_]u8{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };
    entry.attributes = .{ .object = attributes };

    const payload = try entry.toJson(testing.allocator);
    defer testing.allocator.free(payload);

    try testing.expect(std.mem.indexOf(u8, payload, "\"level\":\"info\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"body\":\"log body\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"trace_id\":\"0123456789abcdef0123456789abcdef\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"attributes\":{\"service\":\"checkout\"}") != null);
}
