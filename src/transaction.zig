const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;
const Writer = std.io.Writer;

const Uuid = @import("uuid.zig").Uuid;
const ts = @import("timestamp.zig");

/// A span ID is 16 hex characters (8 random bytes).
pub const SpanId = [16]u8;

/// Generate a random span ID (8 random bytes as 16 hex chars).
pub fn generateSpanId() SpanId {
    var bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    return std.fmt.bytesToHex(bytes, .lower);
}

/// Status values for spans and transactions.
pub const SpanStatus = enum {
    ok,
    cancelled,
    unknown,
    invalid_argument,
    deadline_exceeded,
    not_found,
    already_exists,
    permission_denied,
    resource_exhausted,
    failed_precondition,
    aborted,
    out_of_range,
    unimplemented,
    internal_error,
    unavailable,
    data_loss,
    unauthenticated,

    pub fn toString(self: SpanStatus) []const u8 {
        return switch (self) {
            .ok => "ok",
            .cancelled => "cancelled",
            .unknown => "unknown",
            .invalid_argument => "invalid_argument",
            .deadline_exceeded => "deadline_exceeded",
            .not_found => "not_found",
            .already_exists => "already_exists",
            .permission_denied => "permission_denied",
            .resource_exhausted => "resource_exhausted",
            .failed_precondition => "failed_precondition",
            .aborted => "aborted",
            .out_of_range => "out_of_range",
            .unimplemented => "unimplemented",
            .internal_error => "internal_error",
            .unavailable => "unavailable",
            .data_loss => "data_loss",
            .unauthenticated => "unauthenticated",
        };
    }

    /// Custom JSON serialization: emit as string.
    pub fn jsonStringify(self: SpanStatus, jw: anytype) !void {
        try jw.write(self.toString());
    }
};

/// Options for creating a child span.
pub const ChildSpanOpts = struct {
    op: ?[]const u8 = null,
    description: ?[]const u8 = null,
};

/// Options for creating a transaction.
pub const TransactionOpts = struct {
    name: []const u8,
    op: ?[]const u8 = null,
    description: ?[]const u8 = null,
    sampled: bool = true,
    sample_rate: f64 = 1.0,
    release: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    parent_trace_id: ?[32]u8 = null,
    parent_span_id: ?SpanId = null,
    parent_sampled: ?bool = null,
};

/// A span within a transaction.
pub const Span = struct {
    trace_id: [32]u8,
    span_id: SpanId,
    parent_span_id: ?SpanId = null,
    op: ?[]const u8 = null,
    description: ?[]const u8 = null,
    start_timestamp: f64,
    timestamp: ?f64 = null,
    status: ?SpanStatus = null,

    /// Finish the span, setting timestamp and defaulting status to ok.
    pub fn finish(self: *Span) void {
        self.timestamp = ts.now();
        if (self.status == null) {
            self.status = .ok;
        }
    }

    /// Set the span status.
    pub fn setStatus(self: *Span, status: SpanStatus) void {
        self.status = status;
    }
};

/// A distributed tracing transaction.
pub const Transaction = struct {
    event_id: [32]u8,
    trace_id: [32]u8,
    span_id: SpanId,
    parent_span_id: ?SpanId = null,
    name: []const u8,
    op: ?[]const u8 = null,
    description: ?[]const u8 = null,
    start_timestamp: f64,
    timestamp: ?f64 = null,
    status: ?SpanStatus = null,
    spans: std.ArrayList(*Span) = .{},
    allocator: Allocator,
    sampled: bool = true,
    sample_rate: f64 = 1.0,
    parent_sampled: ?bool = null,
    release: ?[]const u8 = null,
    environment: ?[]const u8 = null,

    /// Create a new transaction.
    pub fn init(allocator: Allocator, opts: TransactionOpts) Transaction {
        const event_uuid = Uuid.v4();
        return Transaction{
            .event_id = event_uuid.toHex(),
            .trace_id = opts.parent_trace_id orelse Uuid.v4().toHex(),
            .span_id = generateSpanId(),
            .parent_span_id = opts.parent_span_id,
            .name = opts.name,
            .op = opts.op,
            .description = opts.description,
            .start_timestamp = ts.now(),
            .allocator = allocator,
            .sampled = opts.sampled,
            .sample_rate = opts.sample_rate,
            .parent_sampled = opts.parent_sampled,
            .release = opts.release,
            .environment = opts.environment,
        };
    }

    /// Free resources.
    pub fn deinit(self: *Transaction) void {
        for (self.spans.items) |span| {
            self.allocator.destroy(span);
        }
        self.spans.deinit(self.allocator);
    }

    /// Create a child span with the same trace_id and this transaction's span_id as parent.
    pub fn startChild(self: *Transaction, opts: ChildSpanOpts) !*Span {
        const span = try self.allocator.create(Span);
        errdefer self.allocator.destroy(span);

        span.* = Span{
            .trace_id = self.trace_id,
            .span_id = generateSpanId(),
            .parent_span_id = self.span_id,
            .op = opts.op,
            .description = opts.description,
            .start_timestamp = ts.now(),
        };

        try self.spans.append(self.allocator, span);
        return span;
    }

    /// Finish the transaction, setting timestamp and defaulting status to ok.
    pub fn finish(self: *Transaction) void {
        self.timestamp = ts.now();
        if (self.status == null) {
            self.status = .ok;
        }
    }

    /// Set the transaction status.
    pub fn setStatus(self: *Transaction, status: SpanStatus) void {
        self.status = status;
    }

    /// Serialize the transaction to JSON for envelope payload.
    pub fn toJson(self: *const Transaction, allocator: Allocator) ![]u8 {
        var aw: Writer.Allocating = .init(allocator);
        errdefer aw.deinit();
        const w = &aw.writer;

        try w.writeAll("{\"type\":\"transaction\"");
        try w.writeAll(",\"event_id\":\"");
        try w.writeAll(&self.event_id);
        try w.writeByte('"');

        try w.writeAll(",\"transaction\":");
        try json.Stringify.value(self.name, .{}, w);

        try w.print(",\"start_timestamp\":{d:.3}", .{self.start_timestamp});

        if (self.timestamp) |t| {
            try w.print(",\"timestamp\":{d:.3}", .{t});
        }

        // Trace context
        try w.writeAll(",\"contexts\":{\"trace\":{\"trace_id\":\"");
        try w.writeAll(&self.trace_id);
        try w.writeAll("\",\"span_id\":\"");
        try w.writeAll(&self.span_id);
        try w.writeByte('"');
        if (self.parent_span_id) |parent_span_id| {
            try w.writeAll(",\"parent_span_id\":\"");
            try w.writeAll(&parent_span_id);
            try w.writeByte('"');
        }
        if (self.op) |op| {
            try w.writeAll(",\"op\":");
            try json.Stringify.value(op, .{}, w);
        }
        try w.writeAll(",\"sampled\":");
        try w.writeAll(if (self.sampled) "true" else "false");
        if (self.status) |status| {
            try w.writeAll(",\"status\":\"");
            try w.writeAll(status.toString());
            try w.writeByte('"');
        }
        try w.writeAll("}}");

        if (self.release) |release| {
            try w.writeAll(",\"release\":");
            try json.Stringify.value(release, .{}, w);
        }

        if (self.environment) |env| {
            try w.writeAll(",\"environment\":");
            try json.Stringify.value(env, .{}, w);
        }

        // Spans array
        try w.writeAll(",\"spans\":[");
        for (self.spans.items, 0..) |span, i| {
            if (i > 0) try w.writeByte(',');
            try writeSpanJson(w, span);
        }
        try w.writeByte(']');

        try w.writeAll(",\"platform\":\"other\"");
        try w.writeByte('}');

        return try aw.toOwnedSlice();
    }
};

fn writeSpanJson(w: *Writer, span: *const Span) !void {
    try w.writeAll("{\"trace_id\":\"");
    try w.writeAll(&span.trace_id);
    try w.writeAll("\",\"span_id\":\"");
    try w.writeAll(&span.span_id);
    try w.writeByte('"');

    if (span.parent_span_id) |pid| {
        try w.writeAll(",\"parent_span_id\":\"");
        try w.writeAll(&pid);
        try w.writeByte('"');
    }

    if (span.op) |op| {
        try w.writeAll(",\"op\":");
        try json.Stringify.value(op, .{}, w);
    }

    if (span.description) |desc| {
        try w.writeAll(",\"description\":");
        try json.Stringify.value(desc, .{}, w);
    }

    try w.print(",\"start_timestamp\":{d:.3}", .{span.start_timestamp});

    if (span.timestamp) |t| {
        try w.print(",\"timestamp\":{d:.3}", .{t});
    }

    if (span.status) |status| {
        try w.writeAll(",\"status\":\"");
        try w.writeAll(status.toString());
        try w.writeByte('"');
    }

    try w.writeByte('}');
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "Transaction.init creates valid trace" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /api",
        .op = "http.server",
    });
    defer txn.deinit();

    // trace_id should be 32 hex chars
    try testing.expectEqual(@as(usize, 32), txn.trace_id.len);
    for (txn.trace_id) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }

    // span_id should be 16 hex chars
    try testing.expectEqual(@as(usize, 16), txn.span_id.len);
    for (txn.span_id) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }

    // event_id should be 32 hex chars
    try testing.expectEqual(@as(usize, 32), txn.event_id.len);
    for (txn.event_id) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }

    // start_timestamp should be reasonable
    try testing.expect(txn.start_timestamp > 1704067200.0);
}

test "Transaction.startChild creates span with matching trace_id and parent_span_id" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /api",
        .op = "http.server",
    });
    defer txn.deinit();

    const child = try txn.startChild(.{ .op = "db.query", .description = "SELECT * FROM users" });

    // Child should share trace_id
    try testing.expectEqualSlices(u8, &txn.trace_id, &child.trace_id);

    // Child's parent should be transaction's span_id
    try testing.expect(child.parent_span_id != null);
    try testing.expectEqualSlices(u8, &txn.span_id, &child.parent_span_id.?);

    // Child should have its own span_id
    try testing.expect(!std.mem.eql(u8, &txn.span_id, &child.span_id));
}

test "Transaction.init supports parent trace context" {
    const parent_trace_id: [32]u8 = "0123456789abcdef0123456789abcdef".*;
    const parent_span_id: SpanId = "89abcdef01234567".*;

    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /continued",
        .parent_trace_id = parent_trace_id,
        .parent_span_id = parent_span_id,
        .parent_sampled = true,
    });
    defer txn.deinit();

    try testing.expectEqualSlices(u8, &parent_trace_id, &txn.trace_id);
    try testing.expect(txn.parent_span_id != null);
    try testing.expectEqualSlices(u8, &parent_span_id, &txn.parent_span_id.?);
    try testing.expectEqual(@as(?bool, true), txn.parent_sampled);
}

test "Transaction.startChild keeps span pointers stable across growth" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /stable",
        .op = "http.server",
    });
    defer txn.deinit();

    const first = try txn.startChild(.{ .op = "first" });
    const first_addr = @intFromPtr(first);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        _ = try txn.startChild(.{ .op = "next" });
    }

    try testing.expectEqual(first_addr, @intFromPtr(first));
    try testing.expectEqual(first_addr, @intFromPtr(txn.spans.items[0]));

    first.finish();
    try testing.expect(first.timestamp != null);
}

test "Span.finish sets timestamp and status" {
    var span = Span{
        .trace_id = Uuid.v4().toHex(),
        .span_id = generateSpanId(),
        .start_timestamp = ts.now(),
    };

    try testing.expect(span.timestamp == null);
    try testing.expect(span.status == null);

    span.finish();

    try testing.expect(span.timestamp != null);
    try testing.expect(span.timestamp.? > 0);
    try testing.expectEqual(SpanStatus.ok, span.status.?);
}

test "Transaction.finish sets timestamp" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "POST /submit",
        .op = "http.server",
    });
    defer txn.deinit();

    try testing.expect(txn.timestamp == null);

    txn.finish();

    try testing.expect(txn.timestamp != null);
    try testing.expect(txn.timestamp.? > 0);
    try testing.expectEqual(SpanStatus.ok, txn.status.?);
}

test "Transaction.toJson produces valid JSON with transaction name, op, spans array" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /api",
        .op = "http.server",
        .release = "my-app@1.0.0",
        .environment = "production",
    });
    defer txn.deinit();

    const child = try txn.startChild(.{ .op = "db.query", .description = "SELECT 1" });
    child.finish();

    txn.finish();

    const json_str = try txn.toJson(testing.allocator);
    defer testing.allocator.free(json_str);

    // Verify transaction name
    try testing.expect(std.mem.indexOf(u8, json_str, "\"transaction\":\"GET /api\"") != null);
    // Verify event_id
    try testing.expect(std.mem.indexOf(u8, json_str, "\"event_id\":\"") != null);
    // Verify type
    try testing.expect(std.mem.indexOf(u8, json_str, "\"type\":\"transaction\"") != null);
    // Verify op in trace context
    try testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"http.server\"") != null);
    // Verify spans array
    try testing.expect(std.mem.indexOf(u8, json_str, "\"spans\":[") != null);
    // Verify child span op
    try testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"db.query\"") != null);
    // Verify sampled field in trace context
    try testing.expect(std.mem.indexOf(u8, json_str, "\"sampled\":true") != null);
    // Verify platform
    try testing.expect(std.mem.indexOf(u8, json_str, "\"platform\":\"other\"") != null);
    // Verify release
    try testing.expect(std.mem.indexOf(u8, json_str, "\"release\":\"my-app@1.0.0\"") != null);
    // Verify environment
    try testing.expect(std.mem.indexOf(u8, json_str, "\"environment\":\"production\"") != null);
}
