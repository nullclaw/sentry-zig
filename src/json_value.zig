const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;

pub fn deinitJsonValueDeep(allocator: Allocator, value: *json.Value) void {
    switch (value.*) {
        .number_string => |s| allocator.free(@constCast(s)),
        .string => |s| allocator.free(@constCast(s)),
        .array => |*arr| {
            for (arr.items) |*item| {
                deinitJsonValueDeep(allocator, item);
            }
            arr.deinit();
        },
        .object => |*obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                allocator.free(@constCast(entry.key_ptr.*));
                deinitJsonValueDeep(allocator, entry.value_ptr);
            }
            obj.deinit();
        },
        else => {},
    }
    value.* = .null;
}

pub fn cloneJsonValue(allocator: Allocator, value: json.Value) !json.Value {
    return switch (value) {
        .null => .null,
        .bool => |v| .{ .bool = v },
        .integer => |v| .{ .integer = v },
        .float => |v| .{ .float = v },
        .number_string => |v| .{ .number_string = try allocator.dupe(u8, v) },
        .string => |v| .{ .string = try allocator.dupe(u8, v) },
        .array => |arr| blk: {
            var copy = json.Array.init(allocator);
            errdefer {
                for (copy.items) |*item| {
                    deinitJsonValueDeep(allocator, item);
                }
                copy.deinit();
            }

            for (arr.items) |item| {
                try copy.append(try cloneJsonValue(allocator, item));
            }
            break :blk .{ .array = copy };
        },
        .object => |obj| blk: {
            var copy = json.ObjectMap.init(allocator);
            errdefer {
                var value_copy: json.Value = .{ .object = copy };
                deinitJsonValueDeep(allocator, &value_copy);
            }

            var it = obj.iterator();
            while (it.next()) |entry| {
                const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(key_copy);

                var item_copy = try cloneJsonValue(allocator, entry.value_ptr.*);
                errdefer deinitJsonValueDeep(allocator, &item_copy);

                try copy.put(key_copy, item_copy);
            }
            break :blk .{ .object = copy };
        },
    };
}

test "cloneJsonValue deep clones nested object and array values" {
    var object = json.ObjectMap.init(testing.allocator);
    defer {
        var owned: json.Value = .{ .object = object };
        deinitJsonValueDeep(testing.allocator, &owned);
    }

    const key = try testing.allocator.dupe(u8, "root");
    var nested = json.ObjectMap.init(testing.allocator);
    try nested.put(
        try testing.allocator.dupe(u8, "child"),
        .{ .string = try testing.allocator.dupe(u8, "value") },
    );
    try object.put(key, .{ .object = nested });

    const cloned = try cloneJsonValue(testing.allocator, .{ .object = object });
    defer {
        var owned = cloned;
        deinitJsonValueDeep(testing.allocator, &owned);
    }

    try testing.expect(cloned == .object);
    try testing.expect(cloned.object.get("root") != null);
    try testing.expect(cloned.object.get("root").? == .object);
    try testing.expect(cloned.object.get("root").?.object.get("child") != null);
    try testing.expectEqualStrings("value", cloned.object.get("root").?.object.get("child").?.string);
}
