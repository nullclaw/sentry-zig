const std = @import("std");
const testing = std.testing;

const Client = @import("../client.zig").Client;
const Hub = @import("../hub.zig").Hub;
const Span = @import("../transaction.zig").Span;
const Transaction = @import("../transaction.zig").Transaction;
const TransactionOpts = @import("../transaction.zig").TransactionOpts;
const propagation = @import("../propagation.zig");
const PropagationHeader = propagation.PropagationHeader;

pub const TraceParentContext = propagation.TraceParentContext;

/// Parse W3C `traceparent` header.
pub fn parseTraceParent(traceparent: []const u8) ?TraceParentContext {
    return propagation.parseTraceParent(traceparent);
}

/// Find and parse `traceparent` from raw header list.
pub fn parseTraceParentFromHeaders(headers: []const PropagationHeader) ?TraceParentContext {
    return propagation.parseTraceParentFromHeaders(headers);
}

/// Build W3C `traceparent` header from transaction context.
pub fn traceParentFromTransactionAlloc(allocator: std.mem.Allocator, txn: *const Transaction) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "00-{s}-{s}-{s}",
        .{
            txn.trace_id[0..],
            txn.span_id[0..],
            if (txn.sampled) "01" else "00",
        },
    );
}

/// Build W3C `traceparent` header from span context.
pub fn traceParentFromSpanAlloc(allocator: std.mem.Allocator, span: *const Span) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "00-{s}-{s}-{s}",
        .{
            span.trace_id[0..],
            span.span_id[0..],
            if (span.sampled) "01" else "00",
        },
    );
}

/// Start transaction from explicit W3C `traceparent` header.
pub fn startTransactionFromTraceParent(
    client: *Client,
    opts: TransactionOpts,
    traceparent: []const u8,
) !Transaction {
    const parsed = parseTraceParent(traceparent) orelse return error.InvalidTraceParent;
    var actual = opts;
    actual.parent_trace_id = parsed.trace_id;
    actual.parent_span_id = parsed.parent_span_id;
    actual.parent_sampled = parsed.sampled;
    return client.startTransaction(actual);
}

/// Start transaction from current Hub using W3C `traceparent`.
pub fn startCurrentHubTransactionFromTraceParent(
    opts: TransactionOpts,
    traceparent: []const u8,
) !Transaction {
    const hub = Hub.current() orelse return error.NoCurrentHub;
    const parsed = parseTraceParent(traceparent) orelse return error.InvalidTraceParent;
    var actual = opts;
    actual.parent_trace_id = parsed.trace_id;
    actual.parent_span_id = parsed.parent_span_id;
    actual.parent_sampled = parsed.sampled;
    return hub.startTransaction(actual);
}

test "parseTraceParent parses valid header" {
    const parsed = parseTraceParent("00-0123456789abcdef0123456789abcdef-89abcdef01234567-01").?;
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", parsed.trace_id[0..]);
    try testing.expectEqualStrings("89abcdef01234567", parsed.parent_span_id[0..]);
    try testing.expectEqual(@as(?bool, true), parsed.sampled);
}

test "parseTraceParent rejects malformed input" {
    try testing.expect(parseTraceParent("invalid") == null);
    try testing.expect(parseTraceParent("00-00000000000000000000000000000000-89abcdef01234567-01") == null);
    try testing.expect(parseTraceParent("00-0123456789abcdef0123456789abcdef-0000000000000000-01") == null);
    try testing.expect(parseTraceParent("ff-0123456789abcdef0123456789abcdef-89abcdef01234567-01") == null);
    try testing.expect(parseTraceParent("zz-0123456789abcdef0123456789abcdef-89abcdef01234567-01") == null);
}

test "parseTraceParent accepts future versions with trailing data" {
    const parsed = parseTraceParent("01-0123456789abcdef0123456789abcdef-89abcdef01234567-01-extra").?;
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", parsed.trace_id[0..]);
    try testing.expectEqualStrings("89abcdef01234567", parsed.parent_span_id[0..]);
    try testing.expectEqual(@as(?bool, true), parsed.sampled);
}

test "parseTraceParent normalizes uppercase identifiers to lowercase" {
    const parsed = parseTraceParent("00-0123456789ABCDEF0123456789ABCDEF-89ABCDEF01234567-01").?;
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", parsed.trace_id[0..]);
    try testing.expectEqualStrings("89abcdef01234567", parsed.parent_span_id[0..]);
}

test "parseTraceParentFromHeaders is case-insensitive" {
    const headers = [_]PropagationHeader{
        .{
            .name = "TrAcEpArEnT",
            .value = "00-0123456789abcdef0123456789abcdef-89abcdef01234567-01",
        },
    };
    const parsed = parseTraceParentFromHeaders(&headers).?;
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", parsed.trace_id[0..]);
}

test "startTransactionFromTraceParent continues trace ids" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = try startTransactionFromTraceParent(
        client,
        .{
            .name = "GET /otel",
            .op = "http.server",
        },
        "00-0123456789abcdef0123456789abcdef-89abcdef01234567-01",
    );
    defer txn.deinit();

    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", txn.trace_id[0..]);
    try testing.expectEqualStrings("89abcdef01234567", txn.parent_span_id.?[0..]);
    try testing.expectEqual(@as(?bool, true), txn.parent_sampled);
}

test "traceParentFromTransactionAlloc encodes transaction context" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .traces_sample_rate = 1.0,
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var txn = client.startTransaction(.{
        .name = "GET /otel-out",
        .op = "http.server",
    });
    defer txn.deinit();

    const traceparent = try traceParentFromTransactionAlloc(testing.allocator, &txn);
    defer testing.allocator.free(traceparent);

    try testing.expect(std.mem.startsWith(u8, traceparent, "00-"));
    try testing.expect(std.mem.indexOf(u8, traceparent, txn.trace_id[0..]) != null);
    try testing.expect(std.mem.indexOf(u8, traceparent, txn.span_id[0..]) != null);
}
