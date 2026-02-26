const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Dsn = @import("dsn.zig").Dsn;

pub const SendResult = struct {
    status_code: u16,
    retry_after: ?u64 = null, // seconds to wait before retry
};

fn parseRetryAfterHeader(header_value: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, header_value, " \t");
    if (trimmed.len == 0) return null;

    if (std.fmt.parseInt(u64, trimmed, 10)) |seconds| {
        return seconds;
    } else |_| {}

    if (std.fmt.parseFloat(f64, trimmed)) |seconds_float| {
        if (!std.math.isFinite(seconds_float) or seconds_float < 0) return null;
        return @intFromFloat(std.math.ceil(seconds_float));
    } else |_| {}

    return null;
}

fn parseSentryRateLimitsHeader(header_value: []const u8) ?u64 {
    var max_retry_after: ?u64 = null;
    var groups = std.mem.splitScalar(u8, header_value, ',');
    while (groups.next()) |group| {
        const trimmed_group = std.mem.trim(u8, group, " \t");
        if (trimmed_group.len == 0) continue;

        const sep_idx = std.mem.indexOfScalar(u8, trimmed_group, ':') orelse continue;
        const seconds_str = trimmed_group[0..sep_idx];
        const seconds = parseRetryAfterHeader(seconds_str) orelse continue;

        if (max_retry_after) |current| {
            if (seconds > current) max_retry_after = seconds;
        } else {
            max_retry_after = seconds;
        }
    }

    return max_retry_after;
}

/// HTTP Transport for sending serialized envelopes to Sentry via HTTPS POST.
pub const Transport = struct {
    allocator: Allocator,
    dsn: Dsn,
    envelope_url: []u8, // allocated
    user_agent: []u8, // allocated
    http_client: std.http.Client,

    /// Initialize a Transport from a parsed Dsn.
    pub fn init(allocator: Allocator, dsn: Dsn, user_agent: []const u8) !Transport {
        const base_url = try dsn.getEnvelopeUrl(allocator);
        defer allocator.free(base_url);
        const envelope_url = try std.fmt.allocPrint(allocator, "{s}?sentry_key={s}", .{ base_url, dsn.public_key });
        errdefer allocator.free(envelope_url);

        const user_agent_copy = try allocator.dupe(u8, user_agent);
        return Transport{
            .allocator = allocator,
            .dsn = dsn,
            .envelope_url = envelope_url,
            .user_agent = user_agent_copy,
            .http_client = .{ .allocator = allocator },
        };
    }

    /// Free allocated resources.
    pub fn deinit(self: *Transport) void {
        self.http_client.deinit();
        self.allocator.free(self.envelope_url);
        self.allocator.free(self.user_agent);
        self.* = undefined;
    }

    /// Send envelope data to the Sentry endpoint via HTTP POST.
    pub fn send(self: *Transport, envelope_data: []const u8) !SendResult {
        const uri = try std.Uri.parse(self.envelope_url);
        var req = try self.http_client.request(.POST, uri, .{
            .redirect_behavior = .unhandled,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/x-sentry-envelope" },
                .{ .name = "User-Agent", .value = self.user_agent },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = envelope_data.len };
        var body = try req.sendBodyUnflushed(&.{});
        try body.writer.writeAll(envelope_data);
        try body.end();
        try req.connection.?.flush();

        var response = try req.receiveHead(&.{});
        const status_code: u16 = @intFromEnum(response.head.status);

        var retry_after: ?u64 = null;
        var header_it = response.head.iterateHeaders();
        while (header_it.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "retry-after")) {
                if (parseRetryAfterHeader(header.value)) |seconds| {
                    if (retry_after) |current| {
                        if (seconds > current) retry_after = seconds;
                    } else {
                        retry_after = seconds;
                    }
                }
            } else if (std.ascii.eqlIgnoreCase(header.name, "x-sentry-rate-limits")) {
                if (parseSentryRateLimitsHeader(header.value)) |seconds| {
                    if (retry_after) |current| {
                        if (seconds > current) retry_after = seconds;
                    } else {
                        retry_after = seconds;
                    }
                }
            }
        }

        var transfer_buffer: [256]u8 = undefined;
        const reader = response.reader(&transfer_buffer);
        _ = reader.discardRemaining() catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
        };

        if (retry_after == null and status_code == 429) {
            // Default to 60s retry-after for rate-limited responses
            retry_after = 60;
        }

        return SendResult{
            .status_code = status_code,
            .retry_after = retry_after,
        };
    }
};

/// MockTransport records sent envelopes for testing purposes.
pub const MockTransport = struct {
    sent: std.ArrayListUnmanaged([]u8) = .{},
    allocator: Allocator,
    response_status: u16 = 200,

    pub fn init(allocator: Allocator) MockTransport {
        return MockTransport{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MockTransport) void {
        for (self.sent.items) |item| {
            self.allocator.free(item);
        }
        self.sent.deinit(self.allocator);
        self.* = undefined;
    }

    /// Record a copy of the envelope data and return configured status.
    pub fn send(self: *MockTransport, envelope_data: []const u8) !SendResult {
        const copy = try self.allocator.dupe(u8, envelope_data);
        try self.sent.append(self.allocator, copy);

        var retry_after: ?u64 = null;
        if (self.response_status == 429) {
            retry_after = 60;
        }

        return SendResult{
            .status_code = self.response_status,
            .retry_after = retry_after,
        };
    }

    /// Return the last sent envelope data, or null if none sent.
    pub fn lastSent(self: *const MockTransport) ?[]const u8 {
        if (self.sent.items.len == 0) return null;
        return self.sent.items[self.sent.items.len - 1];
    }

    /// Return how many envelopes have been sent.
    pub fn sentCount(self: *const MockTransport) usize {
        return self.sent.items.len;
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test "MockTransport records sent envelopes" {
    var mock = MockTransport.init(testing.allocator);
    defer mock.deinit();

    _ = try mock.send("envelope-1");
    _ = try mock.send("envelope-2");

    try testing.expectEqual(@as(usize, 2), mock.sentCount());
}

test "MockTransport returns configured status code" {
    var mock = MockTransport.init(testing.allocator);
    defer mock.deinit();
    mock.response_status = 429;

    const result = try mock.send("test data");

    try testing.expectEqual(@as(u16, 429), result.status_code);
    try testing.expect(result.retry_after != null);
    try testing.expectEqual(@as(u64, 60), result.retry_after.?);
}

test "MockTransport.lastSent returns last sent item" {
    var mock = MockTransport.init(testing.allocator);
    defer mock.deinit();

    try testing.expect(mock.lastSent() == null);

    _ = try mock.send("first");
    _ = try mock.send("second");

    try testing.expectEqualStrings("second", mock.lastSent().?);
}

test "Transport init and deinit" {
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    var transport = try Transport.init(testing.allocator, dsn, "sentry-zig/0.1.0");
    defer transport.deinit();

    try testing.expectEqualStrings("https://o0.ingest.sentry.io/api/1234567/envelope/?sentry_key=examplePublicKey", transport.envelope_url);
    try testing.expectEqualStrings("sentry-zig/0.1.0", transport.user_agent);
}

test "Transport stores custom user agent" {
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    var transport = try Transport.init(testing.allocator, dsn, "my-sdk/9.9.9");
    defer transport.deinit();

    try testing.expectEqualStrings("my-sdk/9.9.9", transport.user_agent);
}

test "parseRetryAfterHeader parses integer and float values" {
    try testing.expectEqual(@as(?u64, 60), parseRetryAfterHeader("60"));
    try testing.expectEqual(@as(?u64, 61), parseRetryAfterHeader("60.1"));
    try testing.expectEqual(@as(?u64, 0), parseRetryAfterHeader("0"));
}

test "parseRetryAfterHeader rejects invalid values" {
    try testing.expectEqual(@as(?u64, null), parseRetryAfterHeader(""));
    try testing.expectEqual(@as(?u64, null), parseRetryAfterHeader("abc"));
    try testing.expectEqual(@as(?u64, null), parseRetryAfterHeader("-1"));
}

test "parseSentryRateLimitsHeader returns max group duration" {
    const header = "120:error:project:reason, 60:session:foo, 240::organization";
    try testing.expectEqual(@as(?u64, 240), parseSentryRateLimitsHeader(header));
}
