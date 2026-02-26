const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Dsn = @import("dsn.zig").Dsn;
const ratelimit = @import("ratelimit.zig");
const RateLimitUpdate = ratelimit.Update;

pub const Options = struct {
    http_proxy: ?[]const u8 = null,
    https_proxy: ?[]const u8 = null,
    accept_invalid_certs: bool = false,
};

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
    proxy_arena: std.heap.ArenaAllocator,
    accept_invalid_certs: bool,
    http_client: std.http.Client,

    /// Initialize a Transport from a parsed Dsn.
    pub fn init(allocator: Allocator, dsn: Dsn, user_agent: []const u8, options: Options) !Transport {
        const base_url = try dsn.getEnvelopeUrl(allocator);
        defer allocator.free(base_url);
        const envelope_url = try std.fmt.allocPrint(allocator, "{s}?sentry_key={s}", .{ base_url, dsn.public_key });
        errdefer allocator.free(envelope_url);
        const envelope_uri = try std.Uri.parse(envelope_url);

        const user_agent_copy = try allocator.dupe(u8, user_agent);
        errdefer allocator.free(user_agent_copy);

        var proxy_arena = std.heap.ArenaAllocator.init(allocator);
        errdefer proxy_arena.deinit();

        var transport = Transport{
            .allocator = allocator,
            .dsn = dsn,
            .envelope_url = envelope_url,
            .envelope_uri = envelope_uri,
            .user_agent = user_agent_copy,
            .proxy_arena = proxy_arena,
            .accept_invalid_certs = options.accept_invalid_certs,
            .http_client = .{ .allocator = allocator },
        };
        errdefer transport.http_client.deinit();

        try transport.configureProxies(options);
        return transport;
    }

    /// Free allocated resources.
    pub fn deinit(self: *Transport) void {
        self.http_client.deinit();
        self.proxy_arena.deinit();
        self.allocator.free(self.envelope_url);
        self.allocator.free(self.user_agent);
        self.* = undefined;
    }

    fn configureProxies(self: *Transport, options: Options) !void {
        const arena = self.proxy_arena.allocator();

        if (options.http_proxy) |raw_http_proxy| {
            self.http_client.http_proxy = try parseProxy(arena, raw_http_proxy);
        }
        if (options.https_proxy) |raw_https_proxy| {
            self.http_client.https_proxy = try parseProxy(arena, raw_https_proxy);
        }

        // Fill remaining values from standard proxy env vars.
        self.http_client.initDefaultProxies(arena) catch {};
    }

    fn parseProxy(arena: Allocator, raw_proxy_url: []const u8) !*std.http.Client.Proxy {
        const uri = std.Uri.parse(raw_proxy_url) catch try std.Uri.parseAfterScheme("http", raw_proxy_url);
        const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.InvalidProxyUrl;
        const host = try uri.getHostAlloc(arena);

        const authorization: ?[]const u8 = if (uri.user != null or uri.password != null) auth: {
            const value_len = std.http.Client.basic_authorization.valueLengthFromUri(uri);
            const value = try arena.alloc(u8, value_len);
            std.debug.assert(std.http.Client.basic_authorization.value(uri, value).len == value.len);
            break :auth value;
        } else null;

        const proxy = try arena.create(std.http.Client.Proxy);
        proxy.* = .{
            .protocol = protocol,
            .host = host,
            .authorization = authorization,
            .port = uri.port orelse switch (protocol) {
                .plain => 80,
                .tls => 443,
            },
            .supports_connect = true,
        };
        return proxy;
    }

    /// Send envelope data to the Sentry endpoint via HTTP POST.
    pub fn send(self: *Transport, envelope_data: []const u8) !SendResult {
        if (self.accept_invalid_certs and std.mem.eql(u8, self.envelope_uri.scheme, "https")) {
            if (self.http_client.https_proxy != null or self.http_client.http_proxy != null) {
                return error.InsecureTlsWithProxyUnsupported;
            }
            return self.sendInsecureTls(envelope_data);
        }

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

    fn sendInsecureTls(self: *Transport, envelope_data: []const u8) !SendResult {
        var host_buf: [std.Uri.host_name_max]u8 = undefined;
        const host = try self.envelope_uri.getHost(&host_buf);
        const port = self.envelope_uri.port orelse 443;

        var stream = try std.net.tcpConnectToHost(self.allocator, host, port);
        defer stream.close();

        var socket_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
        var tls_read_buf: [std.crypto.tls.Client.min_buffer_len + 16384]u8 = undefined;
        var tls_stream_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
        var tls_app_write_buf: [16384]u8 = undefined;

        var stream_reader = stream.reader(&socket_read_buf);
        var stream_writer = stream.writer(&tls_stream_write_buf);

        var tls_client = try std.crypto.tls.Client.init(
            stream_reader.interface(),
            &stream_writer.interface,
            .{
                .host = .no_verification,
                .ca = .no_verification,
                .read_buffer = &tls_read_buf,
                .write_buffer = &tls_app_write_buf,
                .allow_truncation_attacks = true,
            },
        );
        defer _ = tls_client.end() catch {};

        const writer = &tls_client.writer;
        try writer.writeAll("POST ");
        try self.envelope_uri.writeToStream(writer, .{
            .path = true,
            .query = true,
        });
        try writer.writeAll(" HTTP/1.1\r\nHost: ");
        try writer.writeAll(host);
        if (self.envelope_uri.port != null and port != 443) {
            try writer.print(":{d}", .{port});
        }
        try writer.writeAll("\r\nContent-Type: application/x-sentry-envelope\r\nUser-Agent: ");
        try writer.writeAll(self.user_agent);
        try writer.print("\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{envelope_data.len});
        try writer.writeAll(envelope_data);
        try writer.flush();

        const reader = &tls_client.reader;
        const status_line_raw = reader.takeDelimiterExclusive('\n') catch return error.InvalidHttpResponse;
        const status_line = std.mem.trimRight(u8, status_line_raw, "\r");
        const status_code = parseHttpStatusCode(status_line) orelse return error.InvalidHttpResponse;

        var rate_limits: RateLimitUpdate = .{};
        while (true) {
            const header_line_raw = reader.takeDelimiterExclusive('\n') catch return error.InvalidHttpResponse;
            const header_line = std.mem.trimRight(u8, header_line_raw, "\r");
            if (header_line.len == 0) break;

            const colon = std.mem.indexOfScalar(u8, header_line, ':') orelse continue;
            const name = std.mem.trim(u8, header_line[0..colon], " \t");
            const value = std.mem.trim(u8, header_line[colon + 1 ..], " \t");

            if (std.ascii.eqlIgnoreCase(name, "retry-after")) {
                if (ratelimit.parseRetryAfterHeader(value)) |seconds| {
                    rate_limits.setMax(.any, seconds);
                }
            } else if (std.ascii.eqlIgnoreCase(name, "x-sentry-rate-limits")) {
                rate_limits.merge(ratelimit.parseSentryRateLimitsHeader(value));
            }
        }

        _ = reader.discardRemaining() catch {};

        if (rate_limits.isEmpty() and status_code == 429) {
            rate_limits.setMax(.any, 60);
        }

        return SendResult{
            .status_code = status_code,
            .retry_after = rate_limits.any,
            .rate_limits = rate_limits,
        };
    }
};

fn parseHttpStatusCode(status_line: []const u8) ?u16 {
    var parts = std.mem.tokenizeScalar(u8, status_line, ' ');
    _ = parts.next() orelse return null;
    const code_text = parts.next() orelse return null;
    return std.fmt.parseInt(u16, code_text, 10) catch null;
}

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
    var transport = try Transport.init(testing.allocator, dsn, "sentry-zig/0.1.0", .{});
    defer transport.deinit();

    try testing.expectEqualStrings("https://o0.ingest.sentry.io/api/1234567/envelope/?sentry_key=examplePublicKey", transport.envelope_url);
    try testing.expectEqualStrings("sentry-zig/0.1.0", transport.user_agent);
}

test "Transport stores custom user agent" {
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    var transport = try Transport.init(testing.allocator, dsn, "my-sdk/9.9.9", .{});
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

test "Transport parses explicit http/https proxies" {
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    var transport = try Transport.init(testing.allocator, dsn, "sentry-zig/0.1.0", .{
        .http_proxy = "http://proxy-http.local:8080",
        .https_proxy = "http://user:pass@proxy-https.local:8443",
    });
    defer transport.deinit();

    try testing.expect(transport.http_client.http_proxy != null);
    try testing.expect(transport.http_client.https_proxy != null);
    try testing.expectEqualStrings("proxy-http.local", transport.http_client.http_proxy.?.host);
    try testing.expectEqual(@as(u16, 8080), transport.http_client.http_proxy.?.port);
    try testing.expectEqualStrings("proxy-https.local", transport.http_client.https_proxy.?.host);
    try testing.expectEqual(@as(u16, 8443), transport.http_client.https_proxy.?.port);
    try testing.expect(transport.http_client.https_proxy.?.authorization != null);
}

test "Transport stores accept_invalid_certs option" {
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    var transport = try Transport.init(testing.allocator, dsn, "sentry-zig/0.1.0", .{
        .accept_invalid_certs = true,
    });
    defer transport.deinit();

    try testing.expect(transport.accept_invalid_certs);
}

test "Transport send rejects insecure TLS mode when proxies are configured" {
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    var transport = try Transport.init(testing.allocator, dsn, "sentry-zig/0.1.0", .{
        .accept_invalid_certs = true,
        .https_proxy = "http://proxy.local:8080",
    });
    defer transport.deinit();

    try testing.expectError(error.InsecureTlsWithProxyUnsupported, transport.send("test"));
}

test "Transport init fails for invalid proxy URL" {
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    try testing.expectError(
        error.InvalidProxyUrl,
        Transport.init(testing.allocator, dsn, "sentry-zig/0.1.0", .{
            .http_proxy = "://invalid-proxy",
        }),
    );
}
