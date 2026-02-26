const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;
const Writer = std.io.Writer;

const scope_mod = @import("scope.zig");
const Uuid = @import("uuid.zig").Uuid;
const ts = @import("timestamp.zig");

pub const MAX_SPANS: usize = 1000;

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

pub const TransactionOrSpan = union(enum) {
    transaction: *const Transaction,
    span: *const Span,
};

/// Options for creating a transaction.
pub const TransactionOpts = struct {
    name: []const u8,
    op: ?[]const u8 = null,
    description: ?[]const u8 = null,
    start_timestamp: ?f64 = null,
    sampled: bool = true,
    sample_rate: f64 = 1.0,
    release: ?[]const u8 = null,
    dist: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    parent_trace_id: ?[32]u8 = null,
    parent_span_id: ?SpanId = null,
    parent_sampled: ?bool = null,
};

/// A span within a transaction.
pub const Span = struct {
    owner: ?*Transaction = null,
    trace_id: [32]u8,
    span_id: SpanId,
    parent_span_id: ?SpanId = null,
    op: ?[]const u8 = null,
    description: ?[]const u8 = null,
    start_timestamp: f64,
    timestamp: ?f64 = null,
    status: ?SpanStatus = null,
    tags: std.StringHashMap([]const u8),
    data: std.StringHashMap(json.Value),
    sampled: bool = true,
    allocator: Allocator,

    /// Finish the span, setting timestamp and defaulting status to ok.
    pub fn finish(self: *Span) void {
        self.finishWithTimestamp(ts.now());
    }

    /// Finish the span with an explicit timestamp, defaulting status to ok.
    pub fn finishWithTimestamp(self: *Span, timestamp: f64) void {
        self.timestamp = timestamp;
        if (self.status == null) {
            self.status = .ok;
        }
    }

    /// Set the span status.
    pub fn setStatus(self: *Span, status: SpanStatus) void {
        self.status = status;
    }

    pub fn setOp(self: *Span, op: ?[]const u8) void {
        self.op = op;
    }

    pub fn setName(self: *Span, name: ?[]const u8) void {
        self.description = name;
    }

    pub fn getStatus(self: *const Span) ?SpanStatus {
        return self.status;
    }

    pub fn isSampled(self: *const Span) bool {
        return self.sampled;
    }

    pub fn setTag(self: *Span, key: []const u8, value: []const u8) !void {
        try setTagMapEntry(self.allocator, &self.tags, key, value);
    }

    pub fn setData(self: *Span, key: []const u8, value: json.Value) !void {
        try setJsonMapEntry(self.allocator, &self.data, key, value);
    }

    pub fn startChild(self: *Span, opts: ChildSpanOpts) !*Span {
        return self.startChildWithDetails(opts, generateSpanId(), ts.now());
    }

    pub fn startChildWithDetails(
        self: *Span,
        opts: ChildSpanOpts,
        span_id: SpanId,
        start_timestamp: f64,
    ) !*Span {
        const owner = self.owner orelse return error.NoOwnerTransaction;
        return owner.createChildSpan(self.span_id, opts, span_id, start_timestamp);
    }

    pub fn deinit(self: *Span) void {
        deinitTagMapOwned(self.allocator, &self.tags);
        deinitJsonMapOwned(self.allocator, &self.data);
        self.* = undefined;
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
    tags: std.StringHashMap([]const u8),
    extra: std.StringHashMap(json.Value),
    trace_data: std.StringHashMap(json.Value),
    origin: ?[]u8 = null,
    allocator: Allocator,
    sampled: bool = true,
    sample_rate: f64 = 1.0,
    parent_sampled: ?bool = null,
    release: ?[]const u8 = null,
    dist: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    incoming_baggage: ?[]u8 = null,

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
            .start_timestamp = opts.start_timestamp orelse ts.now(),
            .tags = std.StringHashMap([]const u8).init(allocator),
            .extra = std.StringHashMap(json.Value).init(allocator),
            .trace_data = std.StringHashMap(json.Value).init(allocator),
            .allocator = allocator,
            .sampled = opts.sampled,
            .sample_rate = opts.sample_rate,
            .parent_sampled = opts.parent_sampled,
            .release = opts.release,
            .dist = opts.dist,
            .environment = opts.environment,
        };
    }

    /// Free resources.
    pub fn deinit(self: *Transaction) void {
        if (self.incoming_baggage) |value| {
            self.allocator.free(value);
        }
        if (self.origin) |value| {
            self.allocator.free(value);
        }
        for (self.spans.items) |span| {
            span.deinit();
            self.allocator.destroy(span);
        }
        self.spans.deinit(self.allocator);
        deinitTagMapOwned(self.allocator, &self.tags);
        deinitJsonMapOwned(self.allocator, &self.extra);
        deinitJsonMapOwned(self.allocator, &self.trace_data);
    }

    /// Create a child span with the same trace_id and this transaction's span_id as parent.
    pub fn startChild(self: *Transaction, opts: ChildSpanOpts) !*Span {
        return self.startChildWithDetails(opts, generateSpanId(), ts.now());
    }

    /// Create a child span with explicit span id and start timestamp.
    pub fn startChildWithDetails(
        self: *Transaction,
        opts: ChildSpanOpts,
        span_id: SpanId,
        start_timestamp: f64,
    ) !*Span {
        return self.createChildSpan(self.span_id, opts, span_id, start_timestamp);
    }

    fn createChildSpan(
        self: *Transaction,
        parent_span_id: SpanId,
        opts: ChildSpanOpts,
        span_id: SpanId,
        start_timestamp: f64,
    ) !*Span {
        if (self.spans.items.len >= MAX_SPANS) {
            return error.MaxSpansExceeded;
        }

        const span = try self.allocator.create(Span);
        errdefer self.allocator.destroy(span);

        span.* = Span{
            .owner = self,
            .trace_id = self.trace_id,
            .span_id = span_id,
            .parent_span_id = parent_span_id,
            .op = opts.op,
            .description = opts.description,
            .start_timestamp = start_timestamp,
            .tags = std.StringHashMap([]const u8).init(self.allocator),
            .data = std.StringHashMap(json.Value).init(self.allocator),
            .sampled = self.sampled,
            .allocator = self.allocator,
        };

        try self.spans.append(self.allocator, span);
        return span;
    }

    /// Finish the transaction, setting timestamp and defaulting status to ok.
    pub fn finish(self: *Transaction) void {
        self.finishWithTimestamp(ts.now());
    }

    /// Finish the transaction with an explicit timestamp, defaulting status to ok.
    pub fn finishWithTimestamp(self: *Transaction, timestamp: f64) void {
        self.timestamp = timestamp;
        if (self.status == null) {
            self.status = .ok;
        }
    }

    /// Set the transaction status.
    pub fn setStatus(self: *Transaction, status: SpanStatus) void {
        self.status = status;
    }

    pub fn setOp(self: *Transaction, op: ?[]const u8) void {
        self.op = op;
    }

    pub fn setName(self: *Transaction, name: []const u8) void {
        self.name = name;
    }

    pub fn getStatus(self: *const Transaction) ?SpanStatus {
        return self.status;
    }

    pub fn isSampled(self: *const Transaction) bool {
        return self.sampled;
    }

    pub fn setTag(self: *Transaction, key: []const u8, value: []const u8) !void {
        try setTagMapEntry(self.allocator, &self.tags, key, value);
    }

    pub fn setExtra(self: *Transaction, key: []const u8, value: json.Value) !void {
        try setJsonMapEntry(self.allocator, &self.extra, key, value);
    }

    pub fn setData(self: *Transaction, key: []const u8, value: json.Value) !void {
        try setJsonMapEntry(self.allocator, &self.trace_data, key, value);
    }

    pub fn setOrigin(self: *Transaction, origin: ?[]const u8) !void {
        const replacement = if (origin) |value| try self.allocator.dupe(u8, value) else null;
        errdefer if (replacement) |value| self.allocator.free(value);

        if (self.origin) |value| self.allocator.free(value);
        self.origin = replacement;
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
        if (self.origin) |origin| {
            try w.writeAll(",\"origin\":");
            try json.Stringify.value(origin, .{}, w);
        }
        if (self.trace_data.count() > 0) {
            try w.writeAll(",\"data\":");
            try writeJsonMapObject(w, self.trace_data);
        }
        try w.writeAll("}}");

        if (self.tags.count() > 0) {
            try w.writeAll(",\"tags\":");
            try writeTagMapObject(w, self.tags);
        }

        if (self.extra.count() > 0) {
            try w.writeAll(",\"extra\":");
            try writeJsonMapObject(w, self.extra);
        }

        if (self.release) |release| {
            try w.writeAll(",\"release\":");
            try json.Stringify.value(release, .{}, w);
        }

        if (self.dist) |dist| {
            try w.writeAll(",\"dist\":");
            try json.Stringify.value(dist, .{}, w);
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

    if (span.tags.count() > 0) {
        try w.writeAll(",\"tags\":");
        try writeTagMapObject(w, span.tags);
    }

    if (span.data.count() > 0) {
        try w.writeAll(",\"data\":");
        try writeJsonMapObject(w, span.data);
    }

    try w.writeByte('}');
}

fn deinitTagMapOwned(allocator: Allocator, map: *std.StringHashMap([]const u8)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(@constCast(entry.key_ptr.*));
        allocator.free(@constCast(entry.value_ptr.*));
    }
    map.deinit();
}

fn deinitJsonMapOwned(allocator: Allocator, map: *std.StringHashMap(json.Value)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(@constCast(entry.key_ptr.*));
        scope_mod.deinitJsonValueDeep(allocator, entry.value_ptr);
    }
    map.deinit();
}

fn setTagMapEntry(
    allocator: Allocator,
    map: *std.StringHashMap([]const u8),
    key: []const u8,
    value: []const u8,
) !void {
    const key_copy = try allocator.dupe(u8, key);
    errdefer allocator.free(key_copy);
    const value_copy = try allocator.dupe(u8, value);
    errdefer allocator.free(value_copy);

    if (map.fetchRemove(key)) |kv| {
        allocator.free(@constCast(kv.key));
        allocator.free(@constCast(kv.value));
    }

    try map.put(key_copy, value_copy);
}

fn setJsonMapEntry(
    allocator: Allocator,
    map: *std.StringHashMap(json.Value),
    key: []const u8,
    value: json.Value,
) !void {
    const key_copy = try allocator.dupe(u8, key);
    errdefer allocator.free(key_copy);
    var value_copy = try scope_mod.cloneJsonValue(allocator, value);
    errdefer scope_mod.deinitJsonValueDeep(allocator, &value_copy);

    if (map.fetchRemove(key)) |kv| {
        allocator.free(@constCast(kv.key));
        var old = kv.value;
        scope_mod.deinitJsonValueDeep(allocator, &old);
    }

    try map.put(key_copy, value_copy);
}

fn writeTagMapObject(w: *Writer, map: std.StringHashMap([]const u8)) !void {
    try w.writeByte('{');
    var first = true;
    var it = map.iterator();
    while (it.next()) |entry| {
        if (!first) try w.writeByte(',');
        first = false;
        try json.Stringify.value(entry.key_ptr.*, .{}, w);
        try w.writeByte(':');
        try json.Stringify.value(entry.value_ptr.*, .{}, w);
    }
    try w.writeByte('}');
}

fn writeJsonMapObject(w: *Writer, map: std.StringHashMap(json.Value)) !void {
    try w.writeByte('{');
    var first = true;
    var it = map.iterator();
    while (it.next()) |entry| {
        if (!first) try w.writeByte(',');
        first = false;
        try json.Stringify.value(entry.key_ptr.*, .{}, w);
        try w.writeByte(':');
        try json.Stringify.value(entry.value_ptr.*, .{}, w);
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

test "Transaction.startChildWithDetails applies explicit id and timestamp" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /api",
        .op = "http.server",
    });
    defer txn.deinit();

    const span_id: SpanId = "0123456789abcdef".*;
    const start_timestamp = 1704067200.125;
    const child = try txn.startChildWithDetails(
        .{ .op = "db.query", .description = "SELECT * FROM users" },
        span_id,
        start_timestamp,
    );

    try testing.expectEqualSlices(u8, &span_id, &child.span_id);
    try testing.expectEqual(start_timestamp, child.start_timestamp);
    try testing.expect(child.parent_span_id != null);
    try testing.expectEqualSlices(u8, &txn.span_id, &child.parent_span_id.?);
    try testing.expect(child.isSampled());
}

test "Span.startChild creates nested span with parent set to source span" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /nested",
        .op = "http.server",
    });
    defer txn.deinit();

    const root = try txn.startChild(.{ .op = "root" });
    const nested = try root.startChild(.{ .op = "nested" });

    try testing.expect(nested.parent_span_id != null);
    try testing.expectEqualSlices(u8, &root.span_id, &nested.parent_span_id.?);
}

test "Span.startChildWithDetails applies explicit id and timestamp" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /nested-details",
        .op = "http.server",
    });
    defer txn.deinit();

    const root = try txn.startChild(.{ .op = "root" });
    const span_id: SpanId = "fedcba9876543210".*;
    const start_timestamp = 1704067203.125;
    const nested = try root.startChildWithDetails(
        .{ .op = "nested" },
        span_id,
        start_timestamp,
    );

    try testing.expectEqualSlices(u8, &span_id, &nested.span_id);
    try testing.expectEqual(start_timestamp, nested.start_timestamp);
    try testing.expectEqualSlices(u8, &root.span_id, &nested.parent_span_id.?);
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

test "Transaction.init uses explicit start timestamp when provided" {
    const explicit_start = 1704067200.125;
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /timestamp",
        .start_timestamp = explicit_start,
    });
    defer txn.deinit();

    try testing.expectEqual(explicit_start, txn.start_timestamp);
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

test "Transaction.startChild enforces MAX_SPANS limit" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /capped",
        .op = "http.server",
    });
    defer txn.deinit();

    var i: usize = 0;
    while (i < MAX_SPANS) : (i += 1) {
        _ = try txn.startChild(.{ .op = "next" });
    }

    try testing.expectError(error.MaxSpansExceeded, txn.startChild(.{ .op = "overflow" }));
    try testing.expectEqual(MAX_SPANS, txn.spans.items.len);
}

test "Span.finish sets timestamp and status" {
    var span = Span{
        .trace_id = Uuid.v4().toHex(),
        .span_id = generateSpanId(),
        .start_timestamp = ts.now(),
        .tags = std.StringHashMap([]const u8).init(testing.allocator),
        .data = std.StringHashMap(json.Value).init(testing.allocator),
        .allocator = testing.allocator,
    };
    defer span.deinit();

    try testing.expect(span.timestamp == null);
    try testing.expect(span.status == null);

    span.finish();

    try testing.expect(span.timestamp != null);
    try testing.expect(span.timestamp.? > 0);
    try testing.expectEqual(SpanStatus.ok, span.status.?);
}

test "Span.finishWithTimestamp sets explicit timestamp and status" {
    var span = Span{
        .trace_id = Uuid.v4().toHex(),
        .span_id = generateSpanId(),
        .start_timestamp = ts.now(),
        .tags = std.StringHashMap([]const u8).init(testing.allocator),
        .data = std.StringHashMap(json.Value).init(testing.allocator),
        .allocator = testing.allocator,
    };
    defer span.deinit();

    const explicit = 1704067201.250;
    span.finishWithTimestamp(explicit);

    try testing.expectEqual(explicit, span.timestamp.?);
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

test "Transaction.finishWithTimestamp sets explicit timestamp and status" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "POST /submit",
        .op = "http.server",
    });
    defer txn.deinit();

    const explicit = 1704067202.375;
    txn.finishWithTimestamp(explicit);

    try testing.expectEqual(explicit, txn.timestamp.?);
    try testing.expectEqual(SpanStatus.ok, txn.status.?);
}

test "Transaction.toJson produces valid JSON with transaction name, op, spans array" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /api",
        .op = "http.server",
        .release = "my-app@1.0.0",
        .dist = "42",
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
    // Verify dist
    try testing.expect(std.mem.indexOf(u8, json_str, "\"dist\":\"42\"") != null);
    // Verify environment
    try testing.expect(std.mem.indexOf(u8, json_str, "\"environment\":\"production\"") != null);
}

test "Transaction metadata setters serialize trace data tags extra and origin" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /meta",
        .op = "http.server",
    });
    defer txn.deinit();

    try txn.setTag("flow", "checkout");
    try txn.setExtra("attempt", .{ .integer = 2 });
    try txn.setData("cache_hit", .{ .bool = true });
    try txn.setOrigin("auto.http");
    txn.setName("GET /meta-renamed");
    txn.setOp("http.server.renamed");
    txn.setStatus(.ok);
    try testing.expectEqual(@as(?SpanStatus, .ok), txn.getStatus());
    try testing.expect(txn.isSampled());

    txn.finish();
    const json_str = try txn.toJson(testing.allocator);
    defer testing.allocator.free(json_str);

    try testing.expect(std.mem.indexOf(u8, json_str, "\"transaction\":\"GET /meta-renamed\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"origin\":\"auto.http\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"tags\":{") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"flow\":\"checkout\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"extra\":{") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"attempt\":2") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"data\":{") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"cache_hit\":true") != null);
}

test "Span metadata setters serialize tags and data" {
    var txn = Transaction.init(testing.allocator, .{
        .name = "GET /span-meta",
        .op = "http.server",
    });
    defer txn.deinit();

    const child = try txn.startChild(.{ .op = "db.query", .description = "SELECT 1" });
    try child.setTag("db.system", "postgresql");
    try child.setData("rows", .{ .integer = 1 });
    child.setOp("db.query.custom");
    child.setName("SELECT 1 /* custom */");
    child.setStatus(.ok);
    try testing.expectEqual(@as(?SpanStatus, .ok), child.getStatus());
    try testing.expect(child.isSampled());
    child.finish();

    txn.finish();
    const json_str = try txn.toJson(testing.allocator);
    defer testing.allocator.free(json_str);

    try testing.expect(std.mem.indexOf(u8, json_str, "\"db.system\":\"postgresql\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"rows\":1") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"db.query.custom\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"description\":\"SELECT 1 /* custom */\"") != null);
}
