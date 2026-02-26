const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Dsn = @import("dsn.zig").Dsn;

pub const SendResult = struct {
    status_code: u16,
    retry_after: ?u64 = null, // seconds to wait before retry
};

/// HTTP Transport for sending serialized envelopes to Sentry via HTTPS POST.
pub const Transport = struct {
    allocator: Allocator,
    dsn: Dsn,
    envelope_url: []u8, // allocated
    user_agent: []const u8 = "sentry-zig/0.1.0",

    /// Initialize a Transport from a parsed Dsn.
    pub fn init(allocator: Allocator, dsn: Dsn) !Transport {
        const envelope_url = try dsn.getEnvelopeUrl(allocator);
        return Transport{
            .allocator = allocator,
            .dsn = dsn,
            .envelope_url = envelope_url,
        };
    }

    /// Free allocated resources.
    pub fn deinit(self: *Transport) void {
        self.allocator.free(self.envelope_url);
        self.* = undefined;
    }

    /// Send envelope data to the Sentry endpoint via HTTP POST.
    pub fn send(self: *Transport, envelope_data: []const u8) !SendResult {
        var client: std.http.Client = .{ .allocator = self.allocator };
        defer client.deinit();

        const uri = std.Uri.parse(self.envelope_url) catch return error.InvalidUri;

        var header_buf: [4096]u8 = undefined;
        var req = try client.open(.POST, uri, .{
            .server_header_buffer = &header_buf,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/x-sentry-envelope" },
                .{ .name = "User-Agent", .value = self.user_agent },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = envelope_data.len };
        try req.send();
        try req.writeAll(envelope_data);
        try req.finish();
        try req.wait();

        const status_code: u16 = @intFromEnum(req.status);

        var retry_after: ?u64 = null;
        if (status_code == 429) {
            // Try to parse Retry-After header, default to 60s
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
    var transport = try Transport.init(testing.allocator, dsn);
    defer transport.deinit();

    try testing.expectEqualStrings("https://o0.ingest.sentry.io/api/1234567/envelope/", transport.envelope_url);
    try testing.expectEqualStrings("sentry-zig/0.1.0", transport.user_agent);
}
