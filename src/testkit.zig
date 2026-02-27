const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const client_mod = @import("client.zig");
const Client = client_mod.Client;
const Options = client_mod.Options;
const SendOutcome = @import("worker.zig").SendOutcome;

pub const DEFAULT_TEST_DSN = "https://public@sentry.invalid/1";

/// Owned payload collection returned from test capture helpers.
pub const CapturedPayloads = struct {
    allocator: Allocator,
    items: [][]u8,

    pub fn deinit(self: *CapturedPayloads) void {
        for (self.items) |item| self.allocator.free(item);
        self.allocator.free(self.items);
        self.* = undefined;
    }
};

/// In-memory transport for tests.
///
/// Use `send` as a `TransportConfig.send_fn` callback and pass `ctx = &transport`.
pub const TestTransport = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    payloads: std.ArrayListUnmanaged([]u8) = .{},

    pub fn init(allocator: Allocator) TestTransport {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TestTransport) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.freeAllPayloadsLocked();
        self.payloads.deinit(self.allocator);
    }

    pub fn sentCount(self: *TestTransport) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.payloads.items.len;
    }

    pub fn send(envelope_data: []const u8, ctx: ?*anyopaque) SendOutcome {
        const self: *TestTransport = @ptrCast(@alignCast(ctx.?));
        const copied = self.allocator.dupe(u8, envelope_data) catch return .{};

        self.mutex.lock();
        defer self.mutex.unlock();

        self.payloads.append(self.allocator, copied) catch {
            self.allocator.free(copied);
        };
        return .{};
    }

    /// Returns copies of captured envelopes and clears the internal buffer.
    pub fn fetchAndClearEnvelopesAlloc(self: *TestTransport, allocator: Allocator) !CapturedPayloads {
        self.mutex.lock();
        defer self.mutex.unlock();

        var copied = try allocator.alloc([]u8, self.payloads.items.len);
        errdefer allocator.free(copied);

        var copied_count: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < copied_count) : (i += 1) allocator.free(copied[i]);
        }

        for (self.payloads.items, 0..) |payload, i| {
            copied[i] = try allocator.dupe(u8, payload);
            copied_count += 1;
        }

        self.freeAllPayloadsLocked();
        return .{
            .allocator = allocator,
            .items = copied,
        };
    }

    /// Returns copies of captured payloads for a specific envelope item type
    /// (for example, `"event"`), then clears internal envelopes.
    pub fn fetchAndClearItemPayloadsAlloc(
        self: *TestTransport,
        allocator: Allocator,
        item_type: []const u8,
    ) !CapturedPayloads {
        var envelopes = try self.fetchAndClearEnvelopesAlloc(allocator);
        defer envelopes.deinit();

        return try extractItemPayloadsAlloc(allocator, envelopes.items, item_type);
    }

    fn freeAllPayloadsLocked(self: *TestTransport) void {
        for (self.payloads.items) |payload| self.allocator.free(payload);
        self.payloads.clearRetainingCapacity();
    }
};

const CaptureFn = *const fn (*Client, ?*anyopaque) anyerror!void;

/// Runs callback code with a client wired to an in-memory capture transport
/// and returns captured raw envelopes.
///
/// This helper forces `install_signal_handlers=false` to avoid process-global
/// test side effects and overrides `options.transport`.
pub fn withCapturedEnvelopesOptions(
    allocator: Allocator,
    options: Options,
    callback: CaptureFn,
    callback_ctx: ?*anyopaque,
) !CapturedPayloads {
    var transport = TestTransport.init(allocator);
    defer transport.deinit();

    var effective = options;
    effective.install_signal_handlers = false;
    effective.transport = .{
        .send_fn = TestTransport.send,
        .ctx = &transport,
    };

    const client = try Client.init(allocator, effective);
    defer client.deinit();

    try callback(client, callback_ctx);
    _ = client.flush(effective.shutdown_timeout_ms);

    return try transport.fetchAndClearEnvelopesAlloc(allocator);
}

/// Runs callback code with default test options and returns raw captured envelopes.
pub fn withCapturedEnvelopes(
    allocator: Allocator,
    callback: CaptureFn,
    callback_ctx: ?*anyopaque,
) !CapturedPayloads {
    return withCapturedEnvelopesOptions(
        allocator,
        .{
            .dsn = DEFAULT_TEST_DSN,
            .install_signal_handlers = false,
        },
        callback,
        callback_ctx,
    );
}

/// Runs callback code and returns captured `"event"` payloads.
pub fn withCapturedEventsOptions(
    allocator: Allocator,
    options: Options,
    callback: CaptureFn,
    callback_ctx: ?*anyopaque,
) !CapturedPayloads {
    var envelopes = try withCapturedEnvelopesOptions(allocator, options, callback, callback_ctx);
    defer envelopes.deinit();
    return try extractItemPayloadsAlloc(allocator, envelopes.items, "event");
}

/// Runs callback code and returns captured `"event"` payloads using default test options.
pub fn withCapturedEvents(
    allocator: Allocator,
    callback: CaptureFn,
    callback_ctx: ?*anyopaque,
) !CapturedPayloads {
    var envelopes = try withCapturedEnvelopes(allocator, callback, callback_ctx);
    defer envelopes.deinit();
    return try extractItemPayloadsAlloc(allocator, envelopes.items, "event");
}

fn ItemHeaderParseResult(comptime T: type) type {
    return struct {
        item_type: T,
        length: usize,
    };
}

fn parseItemHeader(line: []const u8) ?ItemHeaderParseResult([]const u8) {
    const type_key = "\"type\":\"";
    const length_key = "\"length\":";

    const type_start = std.mem.indexOf(u8, line, type_key) orelse return null;
    const type_value_start = type_start + type_key.len;
    const type_value_end = std.mem.indexOfScalarPos(u8, line, type_value_start, '"') orelse return null;

    const length_start = std.mem.indexOf(u8, line, length_key) orelse return null;
    const cursor = length_start + length_key.len;
    var digits_end = cursor;
    while (digits_end < line.len and std.ascii.isDigit(line[digits_end])) : (digits_end += 1) {}
    if (digits_end == cursor) return null;

    const payload_len = std.fmt.parseInt(usize, line[cursor..digits_end], 10) catch return null;
    return .{
        .item_type = line[type_value_start..type_value_end],
        .length = payload_len,
    };
}

fn extractItemPayloadsAlloc(
    allocator: Allocator,
    envelopes: []const []const u8,
    wanted_type: []const u8,
) !CapturedPayloads {
    var collected: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (collected.items) |payload| allocator.free(payload);
        collected.deinit(allocator);
    }

    for (envelopes) |envelope| {
        const first_newline = std.mem.indexOfScalar(u8, envelope, '\n') orelse continue;
        var cursor: usize = first_newline + 1;

        while (cursor < envelope.len) {
            const header_end = std.mem.indexOfScalarPos(u8, envelope, cursor, '\n') orelse break;
            const header_line = envelope[cursor..header_end];
            const header = parseItemHeader(header_line) orelse break;

            const payload_start = header_end + 1;
            const payload_end = payload_start + header.length;
            if (payload_end > envelope.len) break;

            if (std.mem.eql(u8, header.item_type, wanted_type)) {
                const copied = try allocator.dupe(u8, envelope[payload_start..payload_end]);
                try collected.append(allocator, copied);
            }

            cursor = payload_end;
            if (cursor < envelope.len and envelope[cursor] == '\n') cursor += 1;
        }
    }

    const copied_items = try allocator.alloc([]u8, collected.items.len);
    @memcpy(copied_items, collected.items);
    collected.deinit(allocator);
    return .{
        .allocator = allocator,
        .items = copied_items,
    };
}

fn captureMessageForTest(client: *Client, _: ?*anyopaque) !void {
    _ = client.captureMessageId("testkit-message", .warning);
}

fn captureMessageAndCheckInForTest(client: *Client, _: ?*anyopaque) !void {
    _ = client.captureMessageId("testkit-event", .info);
    var check_in = @import("monitor.zig").MonitorCheckIn.init("testkit-cron", .in_progress);
    client.captureCheckIn(&check_in);
}

test "TestTransport captures and clears envelopes" {
    var transport = TestTransport.init(testing.allocator);
    defer transport.deinit();

    _ = TestTransport.send("envelope-one", &transport);
    _ = TestTransport.send("envelope-two", &transport);
    try testing.expectEqual(@as(usize, 2), transport.sentCount());

    var captured = try transport.fetchAndClearEnvelopesAlloc(testing.allocator);
    defer captured.deinit();

    try testing.expectEqual(@as(usize, 2), captured.items.len);
    try testing.expectEqualStrings("envelope-one", captured.items[0]);
    try testing.expectEqualStrings("envelope-two", captured.items[1]);
    try testing.expectEqual(@as(usize, 0), transport.sentCount());
}

test "withCapturedEnvelopesOptions captures envelopes with overridden transport" {
    var captured = try withCapturedEnvelopesOptions(
        testing.allocator,
        .{
            .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
            .install_signal_handlers = true, // helper forces this off internally
        },
        captureMessageForTest,
        null,
    );
    defer captured.deinit();

    try testing.expect(captured.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, captured.items[0], "\"type\":\"event\"") != null);
    try testing.expect(std.mem.indexOf(u8, captured.items[0], "\"testkit-message\"") != null);
}

test "withCapturedEvents extracts only event payloads" {
    var payloads = try withCapturedEvents(
        testing.allocator,
        captureMessageAndCheckInForTest,
        null,
    );
    defer payloads.deinit();

    try testing.expectEqual(@as(usize, 1), payloads.items.len);
    try testing.expect(std.mem.indexOf(u8, payloads.items[0], "\"testkit-event\"") != null);
    try testing.expect(std.mem.indexOf(u8, payloads.items[0], "\"check_in\"") == null);
}
