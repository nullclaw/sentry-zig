const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Dsn = @import("dsn.zig").Dsn;
const ratelimit = @import("ratelimit.zig");
const RateLimitUpdate = ratelimit.Update;

pub const SendResult = struct {
    status_code: u16,
    retry_after: ?u64 = null, // seconds to wait before retry
    rate_limits: RateLimitUpdate = .{},
};

/// HTTP Transport for sending serialized envelopes to Sentry via HTTPS POST.
pub const Transport = struct {
    allocator: Allocator,
    dsn: Dsn,
    envelope_url: []u8, // allocated
    envelope_uri: std.Uri,
    user_agent: []u8, // allocated
    http_client: std.http.Client,

    /// Initialize a Transport from a parsed Dsn.
    pub fn init(allocator: Allocator, dsn: Dsn, user_agent: []const u8) !Transport {
        const base_url = try dsn.getEnvelopeUrl(allocator);
        defer allocator.free(base_url);
        const envelope_url = try std.fmt.allocPrint(allocator, "{s}?sentry_key={s}", .{ base_url, dsn.public_key });
        errdefer allocator.free(envelope_url);
        const envelope_uri = try std.Uri.parse(envelope_url);

        const user_agent_copy = try allocator.dupe(u8, user_agent);
        return Transport{
            .allocator = allocator,
            .dsn = dsn,
            .envelope_url = envelope_url,
            .envelope_uri = envelope_uri,
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
        var req = try self.http_client.request(.POST, self.envelope_uri, .{
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

        var rate_limits: RateLimitUpdate = .{};
        var header_it = response.head.iterateHeaders();
        while (header_it.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "retry-after")) {
                if (ratelimit.parseRetryAfterHeader(header.value)) |seconds| {
                    rate_limits.setMax(.any, seconds);
                }
            } else if (std.ascii.eqlIgnoreCase(header.name, "x-sentry-rate-limits")) {
                rate_limits.merge(ratelimit.parseSentryRateLimitsHeader(header.value));
            }
        }

        var transfer_buffer: [256]u8 = undefined;
        const reader = response.reader(&transfer_buffer);
        _ = reader.discardRemaining() catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
        };

        if (rate_limits.isEmpty() and status_code == 429) {
            // Default to 60s retry-after for rate-limited responses
            rate_limits.setMax(.any, 60);
        }

        return SendResult{
            .status_code = status_code,
            .retry_after = rate_limits.any,
            .rate_limits = rate_limits,
        };
    }
};

/// MockTransport records sent envelopes for testing purposes.
pub const MockTransport = struct {
    sent: std.ArrayListUnmanaged([]u8) = .{},
    allocator: Allocator,
    response_status: u16 = 200,
    response_rate_limits: RateLimitUpdate = .{},

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

        var rate_limits = self.response_rate_limits;
        if (rate_limits.isEmpty() and self.response_status == 429) {
            rate_limits.setMax(.any, 60);
        }

        return SendResult{
            .status_code = self.response_status,
            .retry_after = rate_limits.any,
            .rate_limits = rate_limits,
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

test "MockTransport exposes configured rate limits" {
    var mock = MockTransport.init(testing.allocator);
    defer mock.deinit();
    mock.response_rate_limits.setMax(.transaction, 45);

    const result = try mock.send("data");
    try testing.expectEqual(@as(?u64, 45), result.rate_limits.transaction);
    try testing.expectEqual(@as(?u64, null), result.retry_after);
}
