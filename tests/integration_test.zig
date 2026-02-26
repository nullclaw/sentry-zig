//! Integration tests for the Sentry-Zig SDK.
//!
//! These tests exercise the PUBLIC API exported by `sentry-zig` and verify
//! end-to-end flows without any network access.

const std = @import("std");
const testing = std.testing;
const sentry = @import("sentry-zig");

fn dropEventProcessor(_: *sentry.Event) bool {
    return false;
}

fn applyCheckoutIntegration(client: *sentry.Client, _: ?*anyopaque) void {
    client.setTag("integration", "checkout");
    client.addBreadcrumb(.{
        .category = "integration",
        .message = "checkout integration setup",
        .level = .info,
    });
}

fn dropTransactionBeforeSend(_: *sentry.Transaction) ?*sentry.Transaction {
    return null;
}

fn rewriteTransactionBeforeSend(txn: *sentry.Transaction) ?*sentry.Transaction {
    txn.op = "http.server.processed";
    txn.name = "POST /checkout-processed";
    return txn;
}

const CaptureRelay = struct {
    allocator: std.mem.Allocator,
    server: std.net.Server,
    thread: ?std.Thread = null,
    response_headers: []const std.http.Header,
    response_status: std.http.Status = .ok,
    mutex: std.Thread.Mutex = .{},
    condition: std.Thread.Condition = .{},
    captured_bodies: std.ArrayListUnmanaged([]u8) = .{},
    failed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        response_headers: []const std.http.Header,
    ) !CaptureRelay {
        const listen_address = try std.net.Address.parseIp("127.0.0.1", 0);
        return .{
            .allocator = allocator,
            .server = try listen_address.listen(.{ .reuse_address = true }),
            .response_headers = response_headers,
        };
    }

    pub fn start(self: *CaptureRelay) !void {
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    pub fn deinit(self: *CaptureRelay) void {
        self.server.deinit();
        if (self.thread) |thread| thread.join();

        for (self.captured_bodies.items) |body| {
            self.allocator.free(body);
        }
        self.captured_bodies.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn port(self: *const CaptureRelay) u16 {
        return self.server.listen_address.getPort();
    }

    pub fn waitForAtLeast(self: *CaptureRelay, min_requests: usize, timeout_ms: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const timeout_ns: i128 = @as(i128, @intCast(timeout_ms)) * std.time.ns_per_ms;
        const deadline = std.time.nanoTimestamp() + timeout_ns;

        while (!self.failed and self.captured_bodies.items.len < min_requests) {
            const now = std.time.nanoTimestamp();
            if (now >= deadline) return false;
            const remaining: u64 = @intCast(deadline - now);
            self.condition.timedWait(&self.mutex, remaining) catch {};
        }

        return !self.failed and self.captured_bodies.items.len >= min_requests;
    }

    pub fn requestCount(self: *CaptureRelay) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.captured_bodies.items.len;
    }

    pub fn containsInAny(self: *CaptureRelay, needle: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.captured_bodies.items) |body| {
            if (std.mem.indexOf(u8, body, needle) != null) return true;
        }
        return false;
    }

    fn markFailed(self: *CaptureRelay) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.failed = true;
        self.condition.broadcast();
    }

    fn serve(self: *CaptureRelay) void {
        while (true) {
            const connection = self.server.accept() catch return;
            self.handleConnection(connection);
        }
    }

    fn handleConnection(self: *CaptureRelay, connection: std.net.Server.Connection) void {
        defer connection.stream.close();

        var send_buffer: [8192]u8 = undefined;
        var recv_buffer: [8192]u8 = undefined;
        var connection_reader = connection.stream.reader(&recv_buffer);
        var connection_writer = connection.stream.writer(&send_buffer);
        var http_server: std.http.Server = .init(connection_reader.interface(), &connection_writer.interface);

        var request = http_server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => return,
            else => {
                self.markFailed();
                return;
            },
        };

        var body_read_buffer: [2048]u8 = undefined;
        const body_reader = request.readerExpectContinue(&body_read_buffer) catch {
            self.markFailed();
            return;
        };
        const content_length = request.head.content_length orelse 0;
        const body = body_reader.readAlloc(self.allocator, @intCast(content_length)) catch {
            self.markFailed();
            return;
        };

        self.mutex.lock();
        if (self.captured_bodies.append(self.allocator, body)) |_| {
            self.condition.broadcast();
        } else |_| {
            self.allocator.free(body);
            self.failed = true;
            self.condition.broadcast();
            self.mutex.unlock();
            return;
        }
        self.mutex.unlock();

        request.respond("ok", .{
            .status = self.response_status,
            .keep_alive = false,
            .extra_headers = self.response_headers,
        }) catch {
            self.markFailed();
            return;
        };
    }
};

fn makeLocalDsn(allocator: std.mem.Allocator, port: u16) ![]u8 {
    return std.fmt.allocPrint(allocator, "http://testkey@127.0.0.1:{d}/99999", .{port});
}

// ─── 1. DSN Parsing and Envelope URL ────────────────────────────────────────

test "DSN parsing and envelope URL" {
    const dsn = try sentry.Dsn.parse("https://abc123@o0.ingest.sentry.io/5678");

    try testing.expectEqualStrings("https", dsn.scheme);
    try testing.expectEqualStrings("abc123", dsn.public_key);
    try testing.expectEqualStrings("o0.ingest.sentry.io", dsn.host);
    try testing.expect(dsn.port == null);
    try testing.expectEqualStrings("5678", dsn.project_id);

    const url = try dsn.getEnvelopeUrl(testing.allocator);
    defer testing.allocator.free(url);

    try testing.expectEqualStrings("https://o0.ingest.sentry.io/api/5678/envelope/", url);

    // Verify the URL starts with the DSN scheme and host
    try testing.expect(std.mem.startsWith(u8, url, "https://o0.ingest.sentry.io/"));
    // Verify it ends with /envelope/
    try testing.expect(std.mem.endsWith(u8, url, "/envelope/"));
}

test "DSN parsing with port" {
    const dsn = try sentry.Dsn.parse("https://mykey@sentry.example.com:9000/42");

    try testing.expectEqualStrings("mykey", dsn.public_key);
    try testing.expectEqualStrings("sentry.example.com", dsn.host);
    try testing.expectEqual(@as(u16, 9000), dsn.port.?);
    try testing.expectEqualStrings("42", dsn.project_id);

    const url = try dsn.getEnvelopeUrl(testing.allocator);
    defer testing.allocator.free(url);

    try testing.expectEqualStrings("https://sentry.example.com:9000/api/42/envelope/", url);
}

// ─── 2. Event Creation and JSON Serialization ───────────────────────────────

test "Event creation and JSON serialization" {
    const event = sentry.Event.initMessage("integration test message", .warning);

    // Verify the event has a valid 32-char hex event_id
    try testing.expectEqual(@as(usize, 32), event.event_id.len);
    for (event.event_id) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }

    // Verify the level is set
    try testing.expectEqual(sentry.Level.warning, event.level.?);

    // Verify the message is set
    try testing.expectEqualStrings("integration test message", event.message.?.formatted.?);

    // Verify platform defaults to "zig"
    try testing.expectEqualStrings("zig", event.platform);

    // Serialize to JSON
    const json_str = try std.json.Stringify.valueAlloc(
        testing.allocator,
        event,
        .{ .emit_null_optional_fields = false },
    );
    defer testing.allocator.free(json_str);

    // Verify JSON contains expected fields
    try testing.expect(std.mem.indexOf(u8, json_str, "\"event_id\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"integration test message\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"warning\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"zig\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"timestamp\"") != null);
}

test "Exception event creation and serialization" {
    const values = [_]sentry.ExceptionValue{.{
        .type = "RuntimeError",
        .value = "something went wrong",
    }};
    const event = sentry.Event.initException(&values);

    try testing.expectEqual(sentry.Level.err, event.level.?);
    try testing.expect(event.exception != null);
    try testing.expectEqual(@as(usize, 1), event.exception.?.values.len);

    const json_str = try std.json.Stringify.valueAlloc(
        testing.allocator,
        event,
        .{ .emit_null_optional_fields = false },
    );
    defer testing.allocator.free(json_str);

    try testing.expect(std.mem.indexOf(u8, json_str, "\"RuntimeError\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"something went wrong\"") != null);
}

// ─── 3. Scope Enriches Events ───────────────────────────────────────────────

test "Scope enriches events with user, tags, and breadcrumbs" {
    var scope = try sentry.Scope.init(testing.allocator, 50);
    defer scope.deinit();

    // Set user
    scope.setUser(.{
        .id = "user-42",
        .email = "test@example.com",
        .username = "testuser",
    });

    // Set tags
    try scope.setTag("environment", "test");
    try scope.setTag("release", "1.0.0");

    // Add breadcrumbs
    scope.addBreadcrumb(.{
        .message = "User clicked button",
        .category = "ui.click",
        .level = .info,
    });
    scope.addBreadcrumb(.{
        .message = "API call made",
        .category = "http",
        .level = .debug,
    });

    // Create an event and apply scope
    var event = sentry.Event.init();
    const applied = try scope.applyToEvent(testing.allocator, &event);
    defer sentry.cleanupAppliedToEvent(testing.allocator, &event, applied);

    // Verify user was applied
    try testing.expect(event.user != null);
    try testing.expectEqualStrings("user-42", event.user.?.id.?);
    try testing.expectEqualStrings("test@example.com", event.user.?.email.?);
    try testing.expectEqualStrings("testuser", event.user.?.username.?);

    // Verify tags were applied
    try testing.expect(event.tags != null);

    // Verify breadcrumbs were applied
    try testing.expect(event.breadcrumbs != null);
    try testing.expectEqual(@as(usize, 2), event.breadcrumbs.?.len);
    try testing.expectEqualStrings("User clicked button", event.breadcrumbs.?[0].message.?);
    try testing.expectEqualStrings("API call made", event.breadcrumbs.?[1].message.?);
}

test "Scope enriches events with transaction and fingerprint overrides" {
    var scope = try sentry.Scope.init(testing.allocator, 10);
    defer scope.deinit();

    try scope.setTransaction("scope-transaction");
    try scope.setFingerprint(&.{ "group-a", "group-b" });

    var event = sentry.Event.init();
    const applied = try scope.applyToEvent(testing.allocator, &event);
    defer sentry.cleanupAppliedToEvent(testing.allocator, &event, applied);

    try testing.expectEqualStrings("scope-transaction", event.transaction.?);
    try testing.expect(event.fingerprint != null);
    try testing.expectEqual(@as(usize, 2), event.fingerprint.?.len);
    try testing.expectEqualStrings("group-a", event.fingerprint.?[0]);
}

test "Scope event processor can drop event during apply" {
    var scope = try sentry.Scope.init(testing.allocator, 10);
    defer scope.deinit();

    try scope.addEventProcessor(dropEventProcessor);

    var event = sentry.Event.init();
    try testing.expectError(error.EventDropped, scope.applyToEvent(testing.allocator, &event));
}

// ─── 4. UUID v4 Format ─────────────────────────────────────────────────────

test "UUID v4 format and roundtrip" {
    const uuid = sentry.Uuid.v4();

    // Verify hex format: 32 lowercase hex characters
    const hex = uuid.toHex();
    try testing.expectEqual(@as(usize, 32), hex.len);
    for (hex) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }

    // Verify version bits (byte 6, high nibble = 4)
    try testing.expectEqual(@as(u8, 0x40), uuid.bytes[6] & 0xF0);

    // Verify variant bits (byte 8, high 2 bits = 10)
    try testing.expectEqual(@as(u8, 0x80), uuid.bytes[8] & 0xC0);

    // Verify roundtrip: toHex -> fromHex -> toHex
    const parsed = try sentry.Uuid.fromHex(&hex);
    const hex2 = parsed.toHex();
    try testing.expectEqualSlices(u8, &hex, &hex2);

    // Verify dashed format: 8-4-4-4-12
    const dashed = uuid.toDashedHex();
    try testing.expectEqual(@as(usize, 36), dashed.len);
    try testing.expectEqual(@as(u8, '-'), dashed[8]);
    try testing.expectEqual(@as(u8, '-'), dashed[13]);
    try testing.expectEqual(@as(u8, '-'), dashed[18]);
    try testing.expectEqual(@as(u8, '-'), dashed[23]);
}

test "UUID uniqueness" {
    const uuid1 = sentry.Uuid.v4();
    const uuid2 = sentry.Uuid.v4();

    // Two UUIDs should be different
    try testing.expect(!std.mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
}

// ─── 5. Transaction with Child Spans ────────────────────────────────────────

test "Transaction with child spans" {
    var txn = sentry.Transaction.init(testing.allocator, .{
        .name = "GET /api/users",
        .op = "http.server",
        .release = "my-service@2.0.0",
        .environment = "staging",
    });
    defer txn.deinit();

    // Verify transaction has valid trace_id and span_id
    try testing.expectEqual(@as(usize, 32), txn.trace_id.len);
    try testing.expectEqual(@as(usize, 16), txn.span_id.len);
    try testing.expect(txn.start_timestamp > 1704067200.0);

    // Start a child span
    const child = try txn.startChild(.{
        .op = "db.query",
        .description = "SELECT * FROM users WHERE active = true",
    });

    // Verify child inherits trace_id and has parent_span_id
    try testing.expectEqualSlices(u8, &txn.trace_id, &child.trace_id);
    try testing.expect(child.parent_span_id != null);
    try testing.expectEqualSlices(u8, &txn.span_id, &child.parent_span_id.?);

    // Finish child span
    child.finish();
    try testing.expect(child.timestamp != null);
    try testing.expectEqual(sentry.SpanStatus.ok, child.status.?);

    // Finish transaction
    txn.finish();
    try testing.expect(txn.timestamp != null);
    try testing.expectEqual(sentry.SpanStatus.ok, txn.status.?);

    // Serialize to JSON
    const json_str = try txn.toJson(testing.allocator);
    defer testing.allocator.free(json_str);

    // Verify JSON fields
    try testing.expect(std.mem.indexOf(u8, json_str, "\"transaction\":\"GET /api/users\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"type\":\"transaction\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"http.server\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"db.query\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"spans\":[") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"release\":\"my-service@2.0.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"environment\":\"staging\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"status\":\"ok\"") != null);
}

// ─── 6. Session Lifecycle ───────────────────────────────────────────────────

test "Session lifecycle: start, error, end" {
    var session = sentry.Session.start("my-app@1.0.0", "production");

    // Verify initial state
    try testing.expectEqual(sentry.SessionStatus.ok, session.status);
    try testing.expectEqual(@as(u32, 0), session.errors);
    try testing.expect(session.init_flag);
    try testing.expect(session.started > 1704067200.0);

    // Mark as errored
    session.markErrored();
    try testing.expectEqual(sentry.SessionStatus.errored, session.status);
    try testing.expectEqual(@as(u32, 1), session.errors);

    // End the session
    session.end(.exited);
    try testing.expectEqual(sentry.SessionStatus.exited, session.status);
    try testing.expect(session.duration != null);
    try testing.expect(session.duration.? >= 0.0);

    // Serialize to JSON
    const json_str = try session.toJson(testing.allocator);
    defer testing.allocator.free(json_str);

    // Verify JSON fields
    try testing.expect(std.mem.indexOf(u8, json_str, "\"sid\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"init\":true") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"started\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"timestamp\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"status\":\"exited\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"errors\":1") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"release\":\"my-app@1.0.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"environment\":\"production\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"duration\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"attrs\"") != null);
}

// ─── 7. Envelope Serialization ──────────────────────────────────────────────

test "Envelope serialization produces 3-line format" {
    const dsn = try sentry.Dsn.parse("https://testkey@o0.ingest.sentry.io/99999");
    const event = sentry.Event.initMessage("envelope integration test", .info);

    var aw: std.io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    try sentry.envelope.serializeEventEnvelope(testing.allocator, event, dsn, &aw.writer);
    const output = aw.written();

    // Split by newlines
    var lines = std.mem.splitScalar(u8, output, '\n');
    const line1 = lines.next().?; // envelope header
    const line2 = lines.next().?; // item header
    const line3 = lines.rest(); // payload

    // Line 1: envelope header with event_id, dsn, sent_at, sdk
    try testing.expect(std.mem.indexOf(u8, line1, "\"event_id\"") != null);
    try testing.expect(std.mem.indexOf(u8, line1, "\"dsn\"") != null);
    try testing.expect(std.mem.indexOf(u8, line1, "\"sent_at\"") != null);
    try testing.expect(std.mem.indexOf(u8, line1, "\"sentry-zig\"") != null);
    try testing.expect(std.mem.indexOf(u8, line1, "testkey") != null);

    // Line 2: item header with type "event" and length
    try testing.expect(std.mem.indexOf(u8, line2, "\"type\":\"event\"") != null);
    try testing.expect(std.mem.indexOf(u8, line2, "\"length\":") != null);

    // Line 3: non-empty payload
    try testing.expect(line3.len > 0);

    // Verify payload length matches declared length
    const length_prefix = "\"length\":";
    const length_start = std.mem.indexOf(u8, line2, length_prefix).? + length_prefix.len;
    const length_end = std.mem.indexOf(u8, line2[length_start..], "}").? + length_start;
    const declared_length = try std.fmt.parseInt(usize, line2[length_start..length_end], 10);
    try testing.expectEqual(declared_length, line3.len);
}

test "Envelope serialization with attachment includes attachment item" {
    const dsn = try sentry.Dsn.parse("https://testkey@o0.ingest.sentry.io/99999");
    const event = sentry.Event.initMessage("attachment envelope test", .info);

    var attachment = try sentry.Attachment.initOwned(
        testing.allocator,
        "trace.txt",
        "trace-body",
        "text/plain",
        "event.attachment",
    );
    defer attachment.deinit(testing.allocator);

    var aw: std.io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    try sentry.envelope.serializeEventEnvelopeWithAttachments(
        testing.allocator,
        event,
        dsn,
        &.{attachment},
        &aw.writer,
    );
    const output = aw.written();

    try testing.expect(std.mem.indexOf(u8, output, "\"type\":\"attachment\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"filename\":\"trace.txt\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "trace-body") != null);
}

test "Monitor check-in JSON serialization" {
    var check_in = sentry.MonitorCheckIn.init("nightly", .ok);
    check_in.environment = "production";
    check_in.duration = 1.5;

    const payload = try check_in.toJson(testing.allocator);
    defer testing.allocator.free(payload);

    try testing.expect(std.mem.indexOf(u8, payload, "\"monitor_slug\":\"nightly\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"ok\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload, "\"environment\":\"production\"") != null);
}

// ─── 8. CJM End-to-End Flows (Client + Transport + Worker) ─────────────────

test "CJM e2e: event with scope and attachment reaches relay" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .release = "checkout@1.2.3",
        .dist = "42",
        .environment = "staging",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.setUser(.{
        .id = "user-42",
        .email = "buyer@example.com",
    });
    client.setTag("cjm", "checkout");

    var attachment = try sentry.Attachment.initOwned(
        testing.allocator,
        "cart.txt",
        "sku=42",
        "text/plain",
        null,
    );
    defer attachment.deinit(testing.allocator);
    client.addAttachment(attachment);

    client.captureMessage("checkout failed", .err);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"event\""));
    try testing.expect(relay.containsInAny("\"checkout failed\""));
    try testing.expect(relay.containsInAny("\"release\":\"checkout@1.2.3\""));
    try testing.expect(relay.containsInAny("\"dist\":\"42\""));
    try testing.expect(relay.containsInAny("\"environment\":\"staging\""));
    try testing.expect(relay.containsInAny("\"user\":{\"id\":\"user-42\""));
    try testing.expect(relay.containsInAny("\"tags\":{\"cjm\":\"checkout\""));
    try testing.expect(relay.containsInAny("\"type\":\"attachment\""));
    try testing.expect(relay.containsInAny("\"filename\":\"cart.txt\""));
    try testing.expect(relay.containsInAny("sku=42"));
}

test "CJM e2e: explicit server_name is serialized into events" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .server_name = "checkout-node-1",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureMessage("server-name-check", .info);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"event\""));
    try testing.expect(relay.containsInAny("\"server_name\":\"checkout-node-1\""));
}

test "CJM e2e: transaction is sent when traces sample rate is enabled" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .release = "checkout@1.2.3",
        .dist = "42",
        .environment = "staging",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "POST /checkout",
        .op = "http.server",
    });
    defer txn.deinit();

    const child = try txn.startChild(.{
        .op = "db.query",
        .description = "INSERT INTO orders",
    });
    child.finish();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"transaction\":\"POST /checkout\""));
    try testing.expect(relay.containsInAny("\"op\":\"http.server\""));
    try testing.expect(relay.containsInAny("\"op\":\"db.query\""));
    try testing.expect(relay.containsInAny("\"trace\":{"));
    try testing.expect(relay.containsInAny("\"sample_rate\":1.000000"));
    try testing.expect(relay.containsInAny("\"release\":\"checkout@1.2.3\""));
    try testing.expect(relay.containsInAny("\"dist\":\"42\""));
    try testing.expect(relay.containsInAny("\"environment\":\"staging\""));
}

test "CJM e2e: transaction start timestamp can be set explicitly" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const explicit_start = 1704067200.125;
    var txn = client.startTransactionWithTimestamp(.{
        .name = "POST /checkout-explicit-start",
        .op = "http.server",
    }, explicit_start);
    defer txn.deinit();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"transaction\":\"POST /checkout-explicit-start\""));
    try testing.expect(relay.containsInAny("\"start_timestamp\":1704067200.125"));
}

test "CJM e2e: transaction metadata setters serialize trace data tags and extras" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "POST /checkout-meta",
        .op = "http.server",
    });
    defer txn.deinit();

    try txn.setTag("flow", "checkout");
    try txn.setExtra("attempt", .{ .integer = 2 });
    try txn.setData("cache_hit", .{ .bool = true });
    try txn.setOrigin("auto.http");

    const child = try txn.startChild(.{
        .op = "db.query",
        .description = "INSERT INTO orders",
    });
    try child.setTag("db.system", "postgresql");
    try child.setData("rows", .{ .integer = 1 });
    child.finish();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"origin\":\"auto.http\""));
    try testing.expect(relay.containsInAny("\"flow\":\"checkout\""));
    try testing.expect(relay.containsInAny("\"attempt\":2"));
    try testing.expect(relay.containsInAny("\"cache_hit\":true"));
    try testing.expect(relay.containsInAny("\"db.system\":\"postgresql\""));
    try testing.expect(relay.containsInAny("\"rows\":1"));
}

test "CJM e2e: client scope enriches transaction metadata" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.setUser(.{ .id = "scope-user" });
    try client.trySetTag("scope-flow", "checkout");
    try client.trySetExtra("scope-attempt", .{ .integer = 4 });
    try client.trySetContext("scope-context", .{ .integer = 8 });

    var txn = client.startTransaction(.{
        .name = "POST /checkout-scope",
        .op = "http.server",
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"user\":{\"id\":\"scope-user\"}"));
    try testing.expect(relay.containsInAny("\"scope-flow\":\"checkout\""));
    try testing.expect(relay.containsInAny("\"scope-attempt\":4"));
    try testing.expect(relay.containsInAny("\"scope-context\":8"));
}

test "CJM e2e: scope transaction override renames transaction and preserves request" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try client.trySetTransaction("new name");

    var txn = client.startTransaction(.{
        .name = "old name",
        .op = "http.server",
    });
    defer txn.deinit();

    try txn.setRequest(.{
        .method = "GET",
        .url = "https://honk.beep",
    });

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"transaction\":\"new name\""));
    try testing.expect(relay.containsInAny("\"request\":{"));
    try testing.expect(relay.containsInAny("\"url\":\"https://honk.beep\""));
}

test "CJM e2e: global transaction API uses current hub scope metadata" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try sentry.Hub.init(testing.allocator, client);
    defer hub.deinit();

    const previous_hub = sentry.setCurrentHub(&hub);
    defer {
        if (previous_hub) |prev| {
            _ = sentry.setCurrentHub(prev);
        } else {
            _ = sentry.clearCurrentHub();
        }
    }

    try hub.trySetTag("hub-global-tag", "checkout");
    try hub.trySetExtra("hub-global-extra", .{ .integer = 5 });
    try hub.trySetContext("hub-global-context", .{ .integer = 6 });
    try hub.trySetTransaction("hub-global-name");

    var txn = sentry.startTransaction(.{
        .name = "POST /checkout-global",
        .op = "http.server",
    }).?;
    defer txn.deinit();
    try txn.setRequest(.{
        .method = "GET",
        .url = "https://honk.beep",
    });

    try testing.expect(sentry.finishTransaction(&txn));
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"hub-global-tag\":\"checkout\""));
    try testing.expect(relay.containsInAny("\"hub-global-extra\":5"));
    try testing.expect(relay.containsInAny("\"hub-global-context\":6"));
    try testing.expect(relay.containsInAny("\"transaction\":\"hub-global-name\""));
    try testing.expect(relay.containsInAny("\"url\":\"https://honk.beep\""));
}

test "CJM e2e: transaction and span request metadata is serialized" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "POST /checkout-request",
        .op = "http.server",
    });
    defer txn.deinit();

    try txn.setRequest(.{
        .method = "POST",
        .url = "https://api.example.com/orders",
        .query_string = "preview=true",
    });

    const span = try txn.startChild(.{
        .op = "http.client",
        .description = "POST payment gateway",
    });
    try span.setRequest(.{
        .method = "POST",
        .url = "https://payments.example.com/charge",
    });
    span.finish();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"request\":{"));
    try testing.expect(relay.containsInAny("\"url\":\"https://api.example.com/orders\""));
    try testing.expect(relay.containsInAny("\"query_string\":\"preview=true\""));
    try testing.expect(relay.containsInAny("\"url\":\"https://payments.example.com/charge\""));
}

test "CJM e2e: before_send_transaction can drop transactions" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .before_send_transaction = dropTransactionBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "POST /checkout",
        .op = "http.server",
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));

    try testing.expectEqual(@as(usize, 0), relay.requestCount());
}

test "CJM e2e: before_send_transaction can mutate transactions in place" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .before_send_transaction = rewriteTransactionBeforeSend,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "POST /checkout",
        .op = "http.server",
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"transaction\":\"POST /checkout-processed\""));
    try testing.expect(relay.containsInAny("\"op\":\"http.server.processed\""));
}

test "CJM e2e: invalid explicit transaction sample_rate drops transaction" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "POST /invalid-rate",
        .op = "http.server",
        .sample_rate = 2.0,
    });
    defer txn.deinit();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));

    try testing.expectEqual(@as(usize, 0), relay.requestCount());
}

test "CJM e2e: session emits errored and exited updates" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .release = "checkout@1.2.3",
        .environment = "production",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    client.captureException("CheckoutError", "payment declined");
    client.endSession(.exited);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(3, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"session\""));
    try testing.expect(relay.containsInAny("\"status\":\"errored\""));
    try testing.expect(relay.containsInAny("\"seq\":"));
    try testing.expect(relay.containsInAny("\"errors\":1"));
    try testing.expect(relay.containsInAny("\"status\":\"exited\""));
    try testing.expect(relay.containsInAny("\"type\":\"event\""));
    try testing.expect(relay.containsInAny("\"payment declined\""));
}

test "CJM e2e: request session mode omits duration field" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .release = "checkout@1.2.3",
        .environment = "production",
        .session_mode = .request,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    client.endSession(.exited);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"session\""));
    try testing.expect(relay.containsInAny("\"status\":\"exited\""));
    try testing.expect(!relay.containsInAny("\"duration\""));
}

test "CJM e2e: session distinct id is derived from scope user" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .release = "checkout@1.2.3",
        .environment = "production",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.setUser(.{ .id = "user-42", .email = "buyer@example.com" });
    client.startSession();
    client.endSession(.exited);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"session\""));
    try testing.expect(relay.containsInAny("\"did\":\"user-42\""));
}

test "CJM e2e: session distinct id can be set after session start" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .release = "checkout@1.2.3",
        .environment = "production",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.startSession();
    client.setUser(.{ .id = "late-user" });
    client.endSession(.exited);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"session\""));
    try testing.expect(relay.containsInAny("\"did\":\"late-user\""));
}

test "CJM e2e: monitor check-in inherits client environment" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .environment = "production",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var check_in = sentry.MonitorCheckIn.init("checkout-cron", .in_progress);
    client.captureCheckIn(&check_in);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"check_in\""));
    try testing.expect(relay.containsInAny("\"monitor_slug\":\"checkout-cron\""));
    try testing.expect(relay.containsInAny("\"status\":\"in_progress\""));
    try testing.expect(relay.containsInAny("\"environment\":\"production\""));
}

test "CJM e2e: structured log envelope is sent" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureLogMessage("checkout-log", .warn);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"log\""));
    try testing.expect(relay.containsInAny("\"body\":\"checkout-log\""));
    try testing.expect(relay.containsInAny("\"level\":\"warn\""));
    try testing.expect(relay.containsInAny("\"sentry.sdk.name\":\"sentry-zig\""));
    try testing.expect(relay.containsInAny("\"sentry.sdk.version\":\"0.1.0\""));
}

test "CJM e2e: active span propagation context is shared by events and logs" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "GET /trace-shared",
        .op = "http.server",
    });
    defer txn.deinit();

    client.setSpan(.{ .transaction = &txn });
    try testing.expect(client.captureMessageId("event-with-active-span", .info) != null);
    client.captureLogMessage("log-with-active-span", .info);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(2, 2000));

    const expected_trace = try std.fmt.allocPrint(testing.allocator, "\"trace_id\":\"{s}\"", .{txn.trace_id[0..]});
    defer testing.allocator.free(expected_trace);

    try testing.expect(relay.containsInAny("\"type\":\"event\""));
    try testing.expect(relay.containsInAny("\"type\":\"log\""));
    try testing.expect(relay.containsInAny(expected_trace));
}

test "CJM e2e: rate limits drop subsequent error envelopes" {
    const response_headers = [_]std.http.Header{
        .{ .name = "X-Sentry-Rate-Limits", .value = "60:error:organization" },
    };
    var relay = try CaptureRelay.init(testing.allocator, &response_headers);
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureMessage("first should pass", .warning);
    client.captureMessage("second should drop", .warning);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));
    try testing.expectEqual(@as(usize, 1), relay.requestCount());
    try testing.expect(relay.containsInAny("first should pass"));
    try testing.expect(!relay.containsInAny("second should drop"));
}

test "CJM e2e: error rate limits also block events with attachments" {
    const response_headers = [_]std.http.Header{
        .{ .name = "X-Sentry-Rate-Limits", .value = "60:error:organization" },
    };
    var relay = try CaptureRelay.init(testing.allocator, &response_headers);
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var attachment = try sentry.Attachment.initOwned(
        testing.allocator,
        "debug.txt",
        "attachment-payload",
        "text/plain",
        null,
    );
    defer attachment.deinit(testing.allocator);
    client.addAttachment(attachment);

    client.captureMessage("first with attachment", .warning);
    client.captureMessage("second with attachment", .warning);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));
    try testing.expectEqual(@as(usize, 1), relay.requestCount());
    try testing.expect(relay.containsInAny("first with attachment"));
    try testing.expect(!relay.containsInAny("second with attachment"));
}

test "CJM e2e: monitor rate limits block subsequent check-ins" {
    const response_headers = [_]std.http.Header{
        .{ .name = "X-Sentry-Rate-Limits", .value = "60:monitor:organization" },
    };
    var relay = try CaptureRelay.init(testing.allocator, &response_headers);
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .environment = "production",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var first = sentry.MonitorCheckIn.init("limited-checkin", .in_progress);
    client.captureCheckIn(&first);

    var second = sentry.MonitorCheckIn.init("limited-checkin", .ok);
    client.captureCheckIn(&second);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));
    try testing.expectEqual(@as(usize, 1), relay.requestCount());
    try testing.expect(relay.containsInAny("\"type\":\"check_in\""));
}

test "CJM e2e: continued transaction keeps upstream trace identifiers" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = try client.startTransactionFromSentryTrace(
        .{
            .name = "GET /continued",
            .op = "http.server",
        },
        "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
    );
    defer txn.deinit();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"trace_id\":\"0123456789abcdef0123456789abcdef\""));
    try testing.expect(relay.containsInAny("\"parent_span_id\":\"89abcdef01234567\""));
}

test "CJM e2e: startTransactionFromHeaders continues upstream trace identifiers" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const headers = [_]sentry.PropagationHeader{
        .{ .name = "sentry-trace", .value = "fedcba9876543210fedcba9876543210-0123456789abcdef-1" },
    };
    var txn = client.startTransactionFromHeaders(.{
        .name = "GET /continued-headers",
        .op = "http.server",
    }, &headers);
    defer txn.deinit();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"trace_id\":\"fedcba9876543210fedcba9876543210\""));
    try testing.expect(relay.containsInAny("\"parent_span_id\":\"0123456789abcdef\""));
}

test "CJM e2e: startTransactionFromSpan continues trace identifiers" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var parent = client.startTransaction(.{
        .name = "GET /parent",
        .op = "http.server",
    });
    defer parent.deinit();

    var child = client.startTransactionFromSpan(.{
        .name = "GET /continued-from-span",
        .op = "worker",
    }, .{ .transaction = &parent });
    defer child.deinit();

    client.finishTransaction(&child);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"transaction\""));
    try testing.expect(relay.containsInAny("\"trace_id\":\""));
    try testing.expect(relay.containsInAny("\"parent_span_id\":\""));
    try testing.expect(relay.containsInAny("\"transaction\":\"GET /continued-from-span\""));
}

test "CJM e2e: baggage sample_rate 0 drops unsampled continued transaction" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = try client.startTransactionFromPropagationHeaders(
        .{
            .name = "GET /continued-unsampled",
            .op = "http.server",
        },
        null,
        "sentry-trace_id=0123456789abcdef0123456789abcdef,sentry-sample_rate=0.000000",
    );
    defer txn.deinit();

    client.finishTransaction(&txn);
    try testing.expect(client.flush(2000));

    try testing.expectEqual(@as(usize, 0), relay.requestCount());
}

test "CJM e2e: max_request_body_size drops oversized events" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .max_request_body_size = 32,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    try testing.expect(client.captureMessageId("this payload is intentionally too large to be submitted", .err) == null);
    try testing.expect(client.flush(2000));

    try testing.expectEqual(@as(usize, 0), relay.requestCount());
}

test "CJM e2e: default_integrations false omits runtime and os contexts" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .default_integrations = false,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureMessage("trace-only-bootstrap", .info);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"event\""));
    try testing.expect(relay.containsInAny("\"trace_id\""));
    try testing.expect(!relay.containsInAny("\"runtime\":"));
    try testing.expect(!relay.containsInAny("\"os\":"));
}

test "CJM e2e: custom event contexts still receive default trace context" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var contexts = std.json.ObjectMap.init(testing.allocator);
    defer {
        var it = contexts.iterator();
        while (it.next()) |entry| {
            testing.allocator.free(@constCast(entry.key_ptr.*));
            switch (entry.value_ptr.*) {
                .string => |s| testing.allocator.free(@constCast(s)),
                .number_string => |s| testing.allocator.free(@constCast(s)),
                else => {},
            }
        }
        contexts.deinit();
    }
    const key = try testing.allocator.dupe(u8, "custom");
    const val = try testing.allocator.dupe(u8, "value");
    try contexts.put(key, .{ .string = val });

    var event = sentry.Event.initMessage("custom-context-event", .info);
    event.contexts = .{ .object = contexts };
    _ = client.captureEventId(&event);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"event\""));
    try testing.expect(relay.containsInAny("\"custom\":\"value\""));
    try testing.expect(relay.containsInAny("\"trace\":{"));
}

test "CJM e2e: in_app_include marks matching exception frames" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const include_patterns = [_][]const u8{"my.app"};
    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .in_app_include = &include_patterns,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    const frames = [_]sentry.Frame{.{
        .module = "my.app.checkout",
        .function = "submit",
    }};
    const values = [_]sentry.ExceptionValue{.{
        .type = "CheckoutError",
        .value = "failure",
        .stacktrace = sentry.Stacktrace{ .frames = &frames },
    }};
    var event = sentry.Event.initException(&values);
    _ = client.captureEventId(&event);

    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"event\""));
    try testing.expect(relay.containsInAny("\"in_app\":true"));
}

test "CJM e2e: integrations setup callback enriches captured events" {
    var relay = try CaptureRelay.init(testing.allocator, &.{});
    defer relay.deinit();
    try relay.start();

    const local_dsn = try makeLocalDsn(testing.allocator, relay.port());
    defer testing.allocator.free(local_dsn);

    const client = try sentry.init(testing.allocator, .{
        .dsn = local_dsn,
        .integrations = &.{.{
            .setup = applyCheckoutIntegration,
        }},
        .install_signal_handlers = false,
    });
    defer client.deinit();

    client.captureMessage("integration-event", .info);
    try testing.expect(client.flush(2000));
    try testing.expect(relay.waitForAtLeast(1, 2000));

    try testing.expect(relay.containsInAny("\"type\":\"event\""));
    try testing.expect(relay.containsInAny("\"integration\":\"checkout\""));
    try testing.expect(relay.containsInAny("\"category\":\"integration\""));
}

// ─── 9. Timestamp Formatting ────────────────────────────────────────────────

test "Timestamp: now() is reasonable" {
    const t = sentry.timestamp.now();

    // Should be after 2024-01-01T00:00:00Z (1704067200)
    try testing.expect(t > 1704067200.0);

    // Should be before 2100-01-01T00:00:00Z (4102444800)
    try testing.expect(t < 4102444800.0);
}

test "Timestamp: RFC 3339 format" {
    const rfc3339 = sentry.timestamp.nowRfc3339();

    // Length should be exactly 24 characters: YYYY-MM-DDTHH:MM:SS.mmmZ
    try testing.expectEqual(@as(usize, 24), rfc3339.len);

    // Should start with "20" (21st century)
    try testing.expectEqualStrings("20", rfc3339[0..2]);

    // Verify structural characters
    try testing.expectEqual(@as(u8, '-'), rfc3339[4]);
    try testing.expectEqual(@as(u8, '-'), rfc3339[7]);
    try testing.expectEqual(@as(u8, 'T'), rfc3339[10]);
    try testing.expectEqual(@as(u8, ':'), rfc3339[13]);
    try testing.expectEqual(@as(u8, ':'), rfc3339[16]);
    try testing.expectEqual(@as(u8, '.'), rfc3339[19]);
    try testing.expectEqual(@as(u8, 'Z'), rfc3339[23]);
}

test "Timestamp: known epoch formatting" {
    // 2025-02-25T12:00:00.000Z
    const result = sentry.timestamp.formatRfc3339(1740484800000);
    try testing.expectEqualStrings("2025-02-25T12:00:00.000Z", &result);
}
