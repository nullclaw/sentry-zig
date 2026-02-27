const std = @import("std");
const builtin = @import("builtin");
const json = std.json;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Event = @import("event.zig").Event;
const scope_mod = @import("scope.zig");

pub fn ensureDefaultTraceContexts(
    allocator: Allocator,
    event: *Event,
    include_runtime_os: bool,
    propagation_context: scope_mod.PropagationContext,
) !?json.Value {
    if (event.contexts == null) {
        return try buildDefaultTraceContexts(allocator, include_runtime_os, propagation_context);
    }
    return try mergeDefaultTraceContexts(allocator, event, include_runtime_os, propagation_context);
}

pub fn buildSyntheticThreads(allocator: Allocator) !json.Value {
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

fn buildDefaultTraceContexts(
    allocator: Allocator,
    include_runtime_os: bool,
    propagation_context: scope_mod.PropagationContext,
) !json.Value {
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
    try putOwnedString(allocator, &trace_object, "trace_id", &propagation_context.trace_id);
    try putOwnedString(allocator, &trace_object, "span_id", &propagation_context.span_id);
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

fn mergeDefaultTraceContexts(
    allocator: Allocator,
    event: *Event,
    include_runtime_os: bool,
    propagation_context: scope_mod.PropagationContext,
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

    const defaults = try buildDefaultTraceContexts(
        allocator,
        include_runtime_os,
        propagation_context,
    );
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

test "ensureDefaultTraceContexts creates trace runtime and os when absent" {
    var event = Event.init();
    const propagation_context: scope_mod.PropagationContext = .{
        .trace_id = "0123456789abcdef0123456789abcdef".*,
        .span_id = "0123456789abcdef".*,
    };

    const enriched = try ensureDefaultTraceContexts(
        testing.allocator,
        &event,
        true,
        propagation_context,
    );
    defer if (enriched) |value| {
        var owned = value;
        scope_mod.deinitJsonValueDeep(testing.allocator, &owned);
    };

    try testing.expect(enriched != null);
    try testing.expect(enriched.? == .object);

    const contexts = enriched.?.object;
    const trace = contexts.get("trace") orelse return error.TestUnexpectedResult;
    const runtime = contexts.get("runtime") orelse return error.TestUnexpectedResult;
    const os = contexts.get("os") orelse return error.TestUnexpectedResult;

    try testing.expect(trace == .object);
    try testing.expect(runtime == .object);
    try testing.expect(os == .object);

    const trace_obj = trace.object;
    try testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef",
        trace_obj.get("trace_id").?.string,
    );
    try testing.expectEqualStrings("0123456789abcdef", trace_obj.get("span_id").?.string);
}

test "ensureDefaultTraceContexts only fills missing defaults" {
    var event = Event.init();
    var trace_object = json.ObjectMap.init(testing.allocator);
    var trace_moved = false;
    errdefer if (!trace_moved) {
        var value: json.Value = .{ .object = trace_object };
        scope_mod.deinitJsonValueDeep(testing.allocator, &value);
    };

    try putOwnedString(testing.allocator, &trace_object, "type", "trace");
    try putOwnedString(
        testing.allocator,
        &trace_object,
        "trace_id",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    try putOwnedString(testing.allocator, &trace_object, "span_id", "bbbbbbbbbbbbbbbb");

    var contexts_object = json.ObjectMap.init(testing.allocator);
    errdefer {
        var value: json.Value = .{ .object = contexts_object };
        scope_mod.deinitJsonValueDeep(testing.allocator, &value);
    }
    try putOwnedJsonEntry(testing.allocator, &contexts_object, "trace", .{ .object = trace_object });
    trace_moved = true;

    var contexts_value: json.Value = .{ .object = contexts_object };
    defer scope_mod.deinitJsonValueDeep(testing.allocator, &contexts_value);
    event.contexts = contexts_value;

    const propagation_context: scope_mod.PropagationContext = .{
        .trace_id = "0123456789abcdef0123456789abcdef".*,
        .span_id = "0123456789abcdef".*,
    };
    const enriched = try ensureDefaultTraceContexts(
        testing.allocator,
        &event,
        true,
        propagation_context,
    );
    defer if (enriched) |value| {
        var owned = value;
        scope_mod.deinitJsonValueDeep(testing.allocator, &owned);
    };

    try testing.expect(enriched != null);
    try testing.expect(enriched.? == .object);

    const merged = enriched.?.object;
    const trace = merged.get("trace") orelse return error.TestUnexpectedResult;
    try testing.expect(trace == .object);
    try testing.expectEqualStrings(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        trace.object.get("trace_id").?.string,
    );
    try testing.expect(merged.get("runtime") != null);
    try testing.expect(merged.get("os") != null);
}

test "ensureDefaultTraceContexts returns null when defaults already present" {
    var event = Event.init();
    const propagation_context: scope_mod.PropagationContext = .{
        .trace_id = "0123456789abcdef0123456789abcdef".*,
        .span_id = "0123456789abcdef".*,
    };

    var contexts = try buildDefaultTraceContexts(testing.allocator, true, propagation_context);
    defer scope_mod.deinitJsonValueDeep(testing.allocator, &contexts);
    event.contexts = contexts;

    const enriched = try ensureDefaultTraceContexts(
        testing.allocator,
        &event,
        true,
        propagation_context,
    );
    try testing.expect(enriched == null);
}

test "buildSyntheticThreads produces one current thread with capture_event frame" {
    var threads = try buildSyntheticThreads(testing.allocator);
    defer scope_mod.deinitJsonValueDeep(testing.allocator, &threads);

    try testing.expect(threads == .object);
    const values = threads.object.get("values") orelse return error.TestUnexpectedResult;
    try testing.expect(values == .array);
    try testing.expectEqual(@as(usize, 1), values.array.items.len);

    const thread = values.array.items[0];
    try testing.expect(thread == .object);
    try testing.expect(thread.object.get("current").?.bool);

    const stacktrace = thread.object.get("stacktrace") orelse return error.TestUnexpectedResult;
    try testing.expect(stacktrace == .object);
    const frames = stacktrace.object.get("frames") orelse return error.TestUnexpectedResult;
    try testing.expect(frames == .array);
    try testing.expectEqual(@as(usize, 1), frames.array.items.len);

    const frame = frames.array.items[0];
    try testing.expect(frame == .object);
    try testing.expectEqualStrings("capture_event", frame.object.get("function").?.string);
    try testing.expect(frame.object.get("in_app").?.bool);
}
