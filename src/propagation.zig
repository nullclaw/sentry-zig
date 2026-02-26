const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Writer = std.io.Writer;

const max_baggage_members = 64;
const max_baggage_size = 8192;

pub const SentryTrace = struct {
    trace_id: [32]u8,
    span_id: [16]u8,
    sampled: ?bool = null,
};

pub const DynamicSamplingContext = struct {
    trace_id: [32]u8,
    public_key: []const u8,
    release: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    transaction: ?[]const u8 = null,
    sample_rate: ?f64 = null,
    sampled: ?bool = null,
};

pub const ParsedBaggage = struct {
    trace_id: ?[32]u8 = null,
    public_key: ?[]const u8 = null,
    release: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    transaction: ?[]const u8 = null,
    sample_rate: ?f64 = null,
    sampled: ?bool = null,
};

pub const ParsedBaggageOwned = struct {
    allocator: Allocator,
    trace_id: ?[32]u8 = null,
    public_key: ?[]u8 = null,
    release: ?[]u8 = null,
    environment: ?[]u8 = null,
    transaction: ?[]u8 = null,
    sample_rate: ?f64 = null,
    sampled: ?bool = null,

    pub fn deinit(self: *ParsedBaggageOwned) void {
        if (self.public_key) |value| self.allocator.free(value);
        if (self.release) |value| self.allocator.free(value);
        if (self.environment) |value| self.allocator.free(value);
        if (self.transaction) |value| self.allocator.free(value);
        self.* = undefined;
    }
};

pub fn parseSentryTrace(header_value: []const u8) ?SentryTrace {
    const trimmed = std.mem.trim(u8, header_value, " \t");
    if (trimmed.len == 0) return null;

    var parts = std.mem.splitScalar(u8, trimmed, '-');
    const trace_id_part = parts.next() orelse return null;
    const span_id_part = parts.next() orelse return null;
    const sampled_part = parts.next();
    if (parts.next() != null) return null;

    if (!isHex(trace_id_part, 32)) return null;
    if (!isHex(span_id_part, 16)) return null;

    var trace: SentryTrace = undefined;
    @memcpy(trace.trace_id[0..], trace_id_part);
    @memcpy(trace.span_id[0..], span_id_part);
    trace.sampled = if (sampled_part) |sampled_text|
        parseSampled(sampled_text)
    else
        null;

    if (sampled_part != null and trace.sampled == null) return null;
    return trace;
}

pub fn formatSentryTraceAlloc(allocator: Allocator, trace: SentryTrace) ![]u8 {
    if (trace.sampled) |sampled| {
        return std.fmt.allocPrint(
            allocator,
            "{s}-{s}-{d}",
            .{ trace.trace_id, trace.span_id, @as(u8, if (sampled) 1 else 0) },
        );
    }
    return std.fmt.allocPrint(allocator, "{s}-{s}", .{ trace.trace_id, trace.span_id });
}

pub fn formatBaggageAlloc(allocator: Allocator, dsc: DynamicSamplingContext) ![]u8 {
    var aw: Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    const w = &aw.writer;
    var first = true;

    try appendBaggagePair(w, &first, "sentry-trace_id", &dsc.trace_id);
    try appendBaggagePair(w, &first, "sentry-public_key", dsc.public_key);

    if (dsc.release) |release| {
        try appendBaggagePair(w, &first, "sentry-release", release);
    }
    if (dsc.environment) |environment| {
        try appendBaggagePair(w, &first, "sentry-environment", environment);
    }
    if (dsc.transaction) |transaction| {
        try appendBaggagePair(w, &first, "sentry-transaction", transaction);
    }
    if (dsc.sample_rate) |sample_rate| {
        var sample_rate_buf: [32]u8 = undefined;
        const sample_rate_str = try std.fmt.bufPrint(&sample_rate_buf, "{d:.6}", .{sample_rate});
        try appendBaggagePair(w, &first, "sentry-sample_rate", sample_rate_str);
    }
    if (dsc.sampled) |sampled| {
        try appendBaggagePair(w, &first, "sentry-sampled", if (sampled) "true" else "false");
    }

    return try aw.toOwnedSlice();
}

/// Merge incoming baggage with fresh Sentry DSC fields.
/// Existing `sentry-*` keys are replaced while third-party entries are preserved.
pub fn mergeBaggageAlloc(
    allocator: Allocator,
    incoming_baggage: ?[]const u8,
    dsc: DynamicSamplingContext,
) ![]u8 {
    const sentry_baggage = try formatBaggageAlloc(allocator, dsc);
    errdefer allocator.free(sentry_baggage);

    const incoming = incoming_baggage orelse return sentry_baggage;
    if (std.mem.trim(u8, incoming, " \t").len == 0) return sentry_baggage;

    const sentry_member_count = countBaggageMembers(sentry_baggage);
    const max_preserved_members: usize = if (sentry_member_count >= max_baggage_members)
        0
    else
        max_baggage_members - sentry_member_count;

    var aw: Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    const w = &aw.writer;

    var kept_members: usize = 0;
    var kept_len: usize = 0;
    var members = std.mem.splitScalar(u8, incoming, ',');
    while (members.next()) |member_raw| {
        const member = std.mem.trim(u8, member_raw, " \t");
        if (member.len == 0 or isSentryBaggageMember(member)) continue;
        if (kept_members >= max_preserved_members) continue;

        const kept_sep_len: usize = if (kept_members > 0) 1 else 0;
        const new_kept_len = kept_len + kept_sep_len + member.len;
        const sentry_sep_len: usize = if (new_kept_len > 0) 1 else 0;
        if (new_kept_len + sentry_sep_len + sentry_baggage.len > max_baggage_size) continue;

        if (kept_members > 0) {
            try w.writeByte(',');
        }
        try w.writeAll(member);
        kept_members += 1;
        kept_len = new_kept_len;
    }

    if (kept_members > 0) {
        try w.writeByte(',');
    }
    try w.writeAll(sentry_baggage);
    allocator.free(sentry_baggage);
    return try aw.toOwnedSlice();
}

pub fn parseBaggage(header_value: []const u8) ParsedBaggage {
    var parsed: ParsedBaggage = .{};
    var fields = std.mem.splitScalar(u8, header_value, ',');

    while (fields.next()) |field_raw| {
        const field = std.mem.trim(u8, field_raw, " \t");
        if (field.len == 0) continue;

        const eq_index = std.mem.indexOfScalar(u8, field, '=') orelse continue;
        const key = std.mem.trim(u8, field[0..eq_index], " \t");
        const value = std.mem.trim(u8, field[eq_index + 1 ..], " \t");
        if (value.len == 0) continue;

        if (equalsAsciiIgnoreCase(key, "sentry-trace_id")) {
            if (isHex(value, 32)) {
                var trace_id: [32]u8 = undefined;
                @memcpy(trace_id[0..], value);
                parsed.trace_id = trace_id;
            }
            continue;
        }
        if (equalsAsciiIgnoreCase(key, "sentry-public_key")) {
            parsed.public_key = value;
            continue;
        }
        if (equalsAsciiIgnoreCase(key, "sentry-release")) {
            parsed.release = value;
            continue;
        }
        if (equalsAsciiIgnoreCase(key, "sentry-environment")) {
            parsed.environment = value;
            continue;
        }
        if (equalsAsciiIgnoreCase(key, "sentry-transaction")) {
            parsed.transaction = value;
            continue;
        }
        if (equalsAsciiIgnoreCase(key, "sentry-sample_rate")) {
            parsed.sample_rate = std.fmt.parseFloat(f64, value) catch null;
            continue;
        }
        if (equalsAsciiIgnoreCase(key, "sentry-sampled")) {
            parsed.sampled = parseSampledBool(value);
            continue;
        }
    }

    return parsed;
}

pub fn parseBaggageAlloc(allocator: Allocator, header_value: []const u8) !ParsedBaggageOwned {
    const parsed = parseBaggage(header_value);
    var owned: ParsedBaggageOwned = .{
        .allocator = allocator,
        .trace_id = parsed.trace_id,
        .sample_rate = parsed.sample_rate,
        .sampled = parsed.sampled,
    };
    errdefer owned.deinit();

    if (parsed.public_key) |value| owned.public_key = try decodePercentValueAlloc(allocator, value);
    if (parsed.release) |value| owned.release = try decodePercentValueAlloc(allocator, value);
    if (parsed.environment) |value| owned.environment = try decodePercentValueAlloc(allocator, value);
    if (parsed.transaction) |value| owned.transaction = try decodePercentValueAlloc(allocator, value);

    return owned;
}

fn parseSampled(sampled_text: []const u8) ?bool {
    if (std.mem.eql(u8, sampled_text, "1")) return true;
    if (std.mem.eql(u8, sampled_text, "0")) return false;
    return null;
}

fn parseSampledBool(sampled_text: []const u8) ?bool {
    if (std.mem.eql(u8, sampled_text, "1") or std.ascii.eqlIgnoreCase(sampled_text, "true")) return true;
    if (std.mem.eql(u8, sampled_text, "0") or std.ascii.eqlIgnoreCase(sampled_text, "false")) return false;
    return null;
}

fn decodePercentValueAlloc(allocator: Allocator, value: []const u8) ![]u8 {
    const temp = try allocator.dupe(u8, value);
    defer allocator.free(temp);
    const decoded = std.Uri.percentDecodeInPlace(temp);
    const copy = try allocator.alloc(u8, decoded.len);
    @memcpy(copy, decoded);
    return copy;
}

fn isSentryBaggageMember(member: []const u8) bool {
    const eq_index = std.mem.indexOfScalar(u8, member, '=');
    const key = std.mem.trim(
        u8,
        if (eq_index) |idx| member[0..idx] else member,
        " \t",
    );
    return key.len >= "sentry-".len and std.ascii.eqlIgnoreCase(key[0.."sentry-".len], "sentry-");
}

fn countBaggageMembers(header_value: []const u8) usize {
    var count: usize = 0;
    var members = std.mem.splitScalar(u8, header_value, ',');
    while (members.next()) |member_raw| {
        const member = std.mem.trim(u8, member_raw, " \t");
        if (member.len == 0) continue;
        count += 1;
    }
    return count;
}

fn isHex(value: []const u8, expected_len: usize) bool {
    if (value.len != expected_len) return false;
    for (value) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn equalsAsciiIgnoreCase(left: []const u8, right: []const u8) bool {
    return std.ascii.eqlIgnoreCase(left, right);
}

fn appendBaggagePair(w: *Writer, first: *bool, key: []const u8, value: []const u8) !void {
    if (!first.*) {
        try w.writeByte(',');
    } else {
        first.* = false;
    }
    try w.writeAll(key);
    try w.writeByte('=');
    try percentEncodeBaggageValue(w, value);
}

fn percentEncodeBaggageValue(w: *Writer, value: []const u8) !void {
    var start: usize = 0;
    for (value, 0..) |char, index| {
        if (isBaggageValueChar(char)) continue;
        try w.print("{s}%{X:0>2}", .{ value[start..index], char });
        start = index + 1;
    }
    try w.writeAll(value[start..]);
}

fn isBaggageValueChar(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or switch (char) {
        '-', '.', '_', '~', '/', ':' => true,
        else => false,
    };
}

test "parseSentryTrace accepts sampled and unsampled headers" {
    const with_sampled = parseSentryTrace("0123456789abcdef0123456789abcdef-0123456789abcdef-1").?;
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef", &with_sampled.trace_id);
    try testing.expectEqualStrings("0123456789abcdef", &with_sampled.span_id);
    try testing.expectEqual(@as(?bool, true), with_sampled.sampled);

    const without_sampled = parseSentryTrace("0123456789abcdef0123456789abcdef-0123456789abcdef").?;
    try testing.expectEqual(@as(?bool, null), without_sampled.sampled);
}

test "parseSentryTrace rejects invalid headers" {
    try testing.expect(parseSentryTrace("") == null);
    try testing.expect(parseSentryTrace("abc-def") == null);
    try testing.expect(parseSentryTrace("0123456789abcdef0123456789abcdef-0123456789abcdef-x") == null);
    try testing.expect(parseSentryTrace("0123456789abcdef0123456789abcde-0123456789abcdef-1") == null);
}

test "formatSentryTraceAlloc emits expected format" {
    const trace: SentryTrace = .{
        .trace_id = "0123456789abcdef0123456789abcdef".*,
        .span_id = "0123456789abcdef".*,
        .sampled = false,
    };
    const text = try formatSentryTraceAlloc(testing.allocator, trace);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef-0123456789abcdef-0", text);
}

test "formatBaggageAlloc includes sentry dynamic sampling keys" {
    const dsc: DynamicSamplingContext = .{
        .trace_id = "fedcba9876543210fedcba9876543210".*,
        .public_key = "public-key",
        .release = "app@1.2.3",
        .environment = "production",
        .transaction = "POST /checkout",
        .sample_rate = 0.25,
        .sampled = true,
    };

    const baggage = try formatBaggageAlloc(testing.allocator, dsc);
    defer testing.allocator.free(baggage);

    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-trace_id=fedcba9876543210fedcba9876543210") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-public_key=public-key") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-release=app%401.2.3") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-transaction=POST%20/checkout") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-sample_rate=0.250000") != null);
    try testing.expect(std.mem.indexOf(u8, baggage, "sentry-sampled=true") != null);
}

test "parseBaggage extracts sentry keys" {
    const parsed = parseBaggage(
        "thirdparty=1,sentry-trace_id=fedcba9876543210fedcba9876543210,sentry-public_key=pub,sentry-sample_rate=0.750000,sentry-sampled=false",
    );

    try testing.expect(parsed.trace_id != null);
    try testing.expectEqualStrings("fedcba9876543210fedcba9876543210", parsed.trace_id.?[0..]);
    try testing.expectEqualStrings("pub", parsed.public_key.?);
    try testing.expectEqual(@as(?f64, 0.75), parsed.sample_rate);
    try testing.expectEqual(@as(?bool, false), parsed.sampled);
}

test "parseBaggage accepts mixed-case sentry keys" {
    const parsed = parseBaggage(
        "Sentry-Trace_ID=fedcba9876543210fedcba9876543210,SENTRY-PUBLIC_KEY=pub,Sentry-SAMPLED=TRUE",
    );

    try testing.expect(parsed.trace_id != null);
    try testing.expectEqualStrings("fedcba9876543210fedcba9876543210", parsed.trace_id.?[0..]);
    try testing.expectEqualStrings("pub", parsed.public_key.?);
    try testing.expectEqual(@as(?bool, true), parsed.sampled);
}

test "parseBaggageAlloc decodes percent-encoded values" {
    var parsed = try parseBaggageAlloc(
        testing.allocator,
        "sentry-public_key=pub%2Dkey,sentry-release=app%401.2.3,sentry-environment=prod,sentry-transaction=POST%20/checkout",
    );
    defer parsed.deinit();

    try testing.expectEqualStrings("pub-key", parsed.public_key.?);
    try testing.expectEqualStrings("app@1.2.3", parsed.release.?);
    try testing.expectEqualStrings("prod", parsed.environment.?);
    try testing.expectEqualStrings("POST /checkout", parsed.transaction.?);
}

test "mergeBaggageAlloc preserves third-party entries and refreshes sentry keys" {
    const dsc: DynamicSamplingContext = .{
        .trace_id = "fedcba9876543210fedcba9876543210".*,
        .public_key = "new-key",
        .release = "app@2.0.0",
        .sampled = true,
    };

    const merged = try mergeBaggageAlloc(
        testing.allocator,
        "vendor=1, foo=bar ,sentry-trace_id=oldtrace,sentry-public_key=old,sentry-sampled=false",
        dsc,
    );
    defer testing.allocator.free(merged);

    try testing.expect(std.mem.indexOf(u8, merged, "vendor=1") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "foo=bar") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "sentry-trace_id=fedcba9876543210fedcba9876543210") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "sentry-public_key=new-key") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "sentry-release=app%402.0.0") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "sentry-sampled=true") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "oldtrace") == null);
}

test "mergeBaggageAlloc falls back to sentry-only baggage when incoming is empty" {
    const dsc: DynamicSamplingContext = .{
        .trace_id = "fedcba9876543210fedcba9876543210".*,
        .public_key = "pk",
    };

    const merged = try mergeBaggageAlloc(testing.allocator, "   ", dsc);
    defer testing.allocator.free(merged);

    try testing.expect(std.mem.indexOf(u8, merged, "sentry-trace_id=fedcba9876543210fedcba9876543210") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "sentry-public_key=pk") != null);
}

test "mergeBaggageAlloc caps total baggage members" {
    var incoming_builder: Writer.Allocating = .init(testing.allocator);
    defer incoming_builder.deinit();
    const incoming_writer = &incoming_builder.writer;

    var i: usize = 0;
    while (i < 80) : (i += 1) {
        if (i > 0) try incoming_writer.writeByte(',');
        try incoming_writer.print("vendor{d}={d}", .{ i, i });
    }
    const incoming = try incoming_builder.toOwnedSlice();
    defer testing.allocator.free(incoming);

    const dsc: DynamicSamplingContext = .{
        .trace_id = "fedcba9876543210fedcba9876543210".*,
        .public_key = "pk",
    };

    const merged = try mergeBaggageAlloc(testing.allocator, incoming, dsc);
    defer testing.allocator.free(merged);

    try testing.expect(countBaggageMembers(merged) <= max_baggage_members);
    try testing.expect(std.mem.indexOf(u8, merged, "vendor0=0") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "vendor79=79") == null);
}

test "mergeBaggageAlloc caps total baggage size" {
    const large_value = try testing.allocator.alloc(u8, 9000);
    defer testing.allocator.free(large_value);
    @memset(large_value, 'a');

    const incoming = try std.fmt.allocPrint(testing.allocator, "vendor={s},ok=1", .{large_value});
    defer testing.allocator.free(incoming);

    const dsc: DynamicSamplingContext = .{
        .trace_id = "fedcba9876543210fedcba9876543210".*,
        .public_key = "pk",
    };

    const merged = try mergeBaggageAlloc(testing.allocator, incoming, dsc);
    defer testing.allocator.free(merged);

    try testing.expect(merged.len <= max_baggage_size);
    try testing.expect(std.mem.indexOf(u8, merged, "ok=1") != null);
    try testing.expect(std.mem.indexOf(u8, merged, "vendor=") == null);
}
