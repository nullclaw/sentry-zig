const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;
const Writer = std.io.Writer;

const Dsn = @import("dsn.zig").Dsn;
const Event = @import("event.zig").Event;
const Attachment = @import("attachment.zig").Attachment;
const ts = @import("timestamp.zig");

pub const SDK_NAME = "sentry-zig";
pub const SDK_VERSION = "0.1.0";

fn writeEnvelopeHeader(writer: *Writer, dsn: Dsn, event_id: ?[]const u8) !void {
    try writer.writeByte('{');
    if (event_id) |id| {
        try writer.writeAll("\"event_id\":\"");
        try writer.writeAll(id);
        try writer.writeAll("\",");
    }
    try writer.writeAll("\"dsn\":\"");
    try dsn.writeDsn(writer);
    try writer.writeAll("\",\"sent_at\":\"");
    const rfc3339 = ts.nowRfc3339();
    try writer.writeAll(&rfc3339);
    try writer.writeAll("\",\"sdk\":{\"name\":\"");
    try writer.writeAll(SDK_NAME);
    try writer.writeAll("\",\"version\":\"");
    try writer.writeAll(SDK_VERSION);
    try writer.writeAll("\"}}");
    try writer.writeByte('\n');
}

fn writeItemHeader(writer: *Writer, item_type: []const u8, payload_len: usize) !void {
    try writer.writeAll("{\"type\":");
    try json.Stringify.value(item_type, .{}, writer);
    try writer.writeAll(",\"length\":");
    try writer.print("{d}", .{payload_len});
    try writer.writeByte('}');
    try writer.writeByte('\n');
}

/// Serialize a complete event envelope.
///
/// The Sentry envelope format is newline-delimited:
///   {envelope_header_json}\n
///   {item_header_json}\n
///   {item_payload}
pub fn serializeEventEnvelope(allocator: Allocator, event: Event, dsn: Dsn, writer: *Writer) !void {
    return serializeEventEnvelopeWithAttachments(allocator, event, dsn, &.{}, writer);
}

/// Serialize an event envelope and include attachment items.
pub fn serializeEventEnvelopeWithAttachments(
    allocator: Allocator,
    event: Event,
    dsn: Dsn,
    attachments: []const Attachment,
    writer: *Writer,
) !void {
    // First, serialize the event payload to get its byte length.
    const payload = try json.Stringify.valueAlloc(
        allocator,
        event,
        .{ .emit_null_optional_fields = false },
    );
    defer allocator.free(payload);

    try writeEnvelopeHeader(writer, dsn, &event.event_id);
    try writeItemHeader(writer, "event", payload.len);

    // Event payload
    try writer.writeAll(payload);

    for (attachments) |attachment| {
        try writer.writeByte('\n');
        try writer.writeAll("{\"type\":\"attachment\",\"length\":");
        try writer.print("{d}", .{attachment.data.len});
        try writer.writeAll(",\"filename\":");
        try json.Stringify.value(attachment.filename, .{}, writer);

        if (attachment.content_type) |content_type| {
            try writer.writeAll(",\"content_type\":");
            try json.Stringify.value(content_type, .{}, writer);
        }

        if (attachment.attachment_type) |attachment_type| {
            try writer.writeAll(",\"attachment_type\":");
            try json.Stringify.value(attachment_type, .{}, writer);
        }

        try writer.writeByte('}');
        try writer.writeByte('\n');
        try writer.writeAll(attachment.data);
    }
}

/// Serialize a session envelope.
///
/// Session envelopes do not include event_id in the header.
pub fn serializeSessionEnvelope(dsn: Dsn, session_json: []const u8, writer: *Writer) !void {
    try writeEnvelopeHeader(writer, dsn, null);
    try writeItemHeader(writer, "session", session_json.len);
    try writer.writeAll(session_json);
}

/// Serialize a monitor check-in envelope.
pub fn serializeCheckInEnvelope(dsn: Dsn, check_in_json: []const u8, writer: *Writer) !void {
    try writeEnvelopeHeader(writer, dsn, null);
    try writeItemHeader(writer, "check_in", check_in_json.len);

    try writer.writeAll(check_in_json);
}

pub fn serializeTransactionEnvelope(
    dsn: Dsn,
    event_id: [32]u8,
    transaction_json: []const u8,
    writer: *Writer,
) !void {
    try writeEnvelopeHeader(writer, dsn, &event_id);
    try writeItemHeader(writer, "transaction", transaction_json.len);
    try writer.writeAll(transaction_json);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "serializeEventEnvelope produces 3-line format" {
    const allocator = testing.allocator;
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    const event = Event.initMessage("test envelope", .info);

    var aw: Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try serializeEventEnvelope(allocator, event, dsn, &aw.writer);
    const output = aw.written();

    // Split by newlines — expect exactly 3 parts (header, item header, payload)
    var lines = std.mem.splitScalar(u8, output, '\n');
    const line1 = lines.next().?; // envelope header
    const line2 = lines.next().?; // item header
    const line3 = lines.rest(); // payload (may not have trailing newline)

    // Verify line 1 (envelope header) contains required fields
    try testing.expect(std.mem.indexOf(u8, line1, "\"event_id\"") != null);
    try testing.expect(std.mem.indexOf(u8, line1, "\"dsn\"") != null);
    try testing.expect(std.mem.indexOf(u8, line1, "\"sent_at\"") != null);
    try testing.expect(std.mem.indexOf(u8, line1, "\"sentry-zig\"") != null);

    // Verify line 2 (item header) has type and length
    try testing.expect(std.mem.indexOf(u8, line2, "\"type\":\"event\"") != null);
    try testing.expect(std.mem.indexOf(u8, line2, "\"length\":") != null);

    // Verify payload is non-empty
    try testing.expect(line3.len > 0);
}

test "serializeEventEnvelope payload length matches declared length" {
    const allocator = testing.allocator;
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    const event = Event.initMessage("length test", .warning);

    var aw: Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try serializeEventEnvelope(allocator, event, dsn, &aw.writer);
    const output = aw.written();

    // Extract the item header line and payload
    var lines = std.mem.splitScalar(u8, output, '\n');
    _ = lines.next(); // skip envelope header
    const item_header = lines.next().?;
    const payload = lines.rest();

    // Parse the declared length from item header
    const length_prefix = "\"length\":";
    const length_start = std.mem.indexOf(u8, item_header, length_prefix).? + length_prefix.len;
    const length_end = std.mem.indexOf(u8, item_header[length_start..], "}").? + length_start;
    const declared_length = try std.fmt.parseInt(usize, item_header[length_start..length_end], 10);

    try testing.expectEqual(declared_length, payload.len);
}

test "serializeEventEnvelope envelope header contains dsn" {
    const allocator = testing.allocator;
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    const event = Event.init();

    var aw: Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try serializeEventEnvelope(allocator, event, dsn, &aw.writer);
    const output = aw.written();

    // The DSN string should appear in the envelope header
    try testing.expect(std.mem.indexOf(u8, output, "o0.ingest.sentry.io") != null);
    try testing.expect(std.mem.indexOf(u8, output, "examplePublicKey") != null);
}

test "serializeSessionEnvelope produces valid format" {
    const dsn = try Dsn.parse("https://key@sentry.example.com/42");
    const session_json = "{\"sid\":\"abc\",\"status\":\"ok\"}";

    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    try serializeSessionEnvelope(dsn, session_json, &aw.writer);
    const output = aw.written();

    var lines = std.mem.splitScalar(u8, output, '\n');
    const line1 = lines.next().?;
    const line2 = lines.next().?;
    const line3 = lines.rest();

    // Session envelope should NOT have event_id
    try testing.expect(std.mem.indexOf(u8, line1, "\"event_id\"") == null);
    // Should have dsn and sdk
    try testing.expect(std.mem.indexOf(u8, line1, "\"dsn\"") != null);
    try testing.expect(std.mem.indexOf(u8, line1, "\"sentry-zig\"") != null);

    // Item header should be session type
    try testing.expect(std.mem.indexOf(u8, line2, "\"type\":\"session\"") != null);

    // Payload should match
    try testing.expectEqualStrings(session_json, line3);
}

test "serializeEventEnvelopeWithAttachments includes attachment item headers and payloads" {
    const allocator = testing.allocator;
    const dsn = try Dsn.parse("https://examplePublicKey@o0.ingest.sentry.io/1234567");
    const event = Event.initMessage("attachment test", .info);

    var attachment = try Attachment.initOwned(
        allocator,
        "debug.txt",
        "debug-body",
        "text/plain",
        "event.attachment",
    );
    defer attachment.deinit(allocator);

    var aw: Writer.Allocating = .init(allocator);
    defer aw.deinit();

    try serializeEventEnvelopeWithAttachments(allocator, event, dsn, &.{attachment}, &aw.writer);
    const output = aw.written();

    try testing.expect(std.mem.indexOf(u8, output, "\"type\":\"event\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"type\":\"attachment\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"filename\":\"debug.txt\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"content_type\":\"text/plain\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"attachment_type\":\"event.attachment\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "debug-body") != null);
}

test "serializeCheckInEnvelope produces valid format" {
    const dsn = try Dsn.parse("https://key@sentry.example.com/42");
    const check_in_json =
        "{\"check_in_id\":\"0123456789abcdef0123456789abcdef\",\"monitor_slug\":\"nightly\",\"status\":\"ok\"}";

    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    try serializeCheckInEnvelope(dsn, check_in_json, &aw.writer);
    const output = aw.written();

    var lines = std.mem.splitScalar(u8, output, '\n');
    const line1 = lines.next().?;
    const line2 = lines.next().?;
    const line3 = lines.rest();

    try testing.expect(std.mem.indexOf(u8, line1, "\"dsn\"") != null);
    try testing.expect(std.mem.indexOf(u8, line2, "\"type\":\"check_in\"") != null);
    try testing.expectEqualStrings(check_in_json, line3);
}

test "serializeTransactionEnvelope produces valid format" {
    const dsn = try Dsn.parse("https://key@sentry.example.com/42");
    const transaction_json = "{\"type\":\"transaction\",\"transaction\":\"GET /health\"}";
    const event_id = [_]u8{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };

    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    try serializeTransactionEnvelope(dsn, event_id, transaction_json, &aw.writer);
    const output = aw.written();

    var lines = std.mem.splitScalar(u8, output, '\n');
    const line1 = lines.next().?;
    const line2 = lines.next().?;
    const line3 = lines.rest();

    try testing.expect(std.mem.indexOf(u8, line1, "\"event_id\"") != null);
    try testing.expect(std.mem.indexOf(u8, line2, "\"type\":\"transaction\"") != null);
    try testing.expectEqualStrings(transaction_json, line3);
}
