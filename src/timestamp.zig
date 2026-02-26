const std = @import("std");
const testing = std.testing;

/// Return the current Unix timestamp as f64 seconds (with millisecond precision).
pub fn now() f64 {
    const ms = std.time.milliTimestamp();
    return @as(f64, @floatFromInt(ms)) / 1000.0;
}

/// Return the current time formatted as RFC 3339 with millisecond precision.
pub fn nowRfc3339() [24]u8 {
    const ms = std.time.milliTimestamp();
    return formatRfc3339(@intCast(ms));
}

/// Format epoch milliseconds as RFC 3339: "YYYY-MM-DDTHH:MM:SS.mmmZ" (24 chars).
/// Uses Howard Hinnant's civil date algorithm for epoch-to-date conversion.
pub fn formatRfc3339(epoch_ms: u64) [24]u8 {
    const total_secs = epoch_ms / 1000;
    const millis: u16 = @intCast(epoch_ms % 1000);

    const secs_of_day = total_secs % 86400;
    const hour: u8 = @intCast(secs_of_day / 3600);
    const minute: u8 = @intCast((secs_of_day % 3600) / 60);
    const second: u8 = @intCast(secs_of_day % 60);

    // Howard Hinnant's civil_from_days algorithm
    const days_since_epoch: i64 = @intCast(total_secs / 86400);
    const z: i64 = days_since_epoch + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097); // day of era [0, 146096]
    const yoe: u32 = @intCast(@divFloor(
        @as(i64, doe) - @divFloor(@as(i64, doe), 1460) + @divFloor(@as(i64, doe), 36524) - @divFloor(@as(i64, doe), 146096),
        365,
    )); // year of era [0, 399]
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u32 = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    const mp: u32 = (5 * doy + 2) / 153; // month offset [0, 11]
    const d: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1); // day [1, 31]
    const m_raw: u32 = if (mp < 10) mp + 3 else mp - 9;
    const m: u8 = @intCast(m_raw); // month [1, 12]
    const year: u16 = @intCast(if (m <= 2) y + 1 else y);

    var buf: [24]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year, m, d, hour, minute, second, millis,
    }) catch unreachable;
    return buf;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "formatRfc3339 known epoch" {
    // 2025-02-25T12:00:00.000Z = 1740484800 seconds = 1740484800000 ms
    const result = formatRfc3339(1740484800000);
    try testing.expectEqualStrings("2025-02-25T12:00:00.000Z", &result);
}

test "formatRfc3339 with milliseconds" {
    const result = formatRfc3339(1740484800123);
    try testing.expectEqualStrings("2025-02-25T12:00:00.123Z", &result);
}

test "formatRfc3339 unix epoch" {
    const result = formatRfc3339(0);
    try testing.expectEqualStrings("1970-01-01T00:00:00.000Z", &result);
}

test "nowRfc3339 starts with 20" {
    const result = nowRfc3339();
    try testing.expectEqualStrings("20", result[0..2]);
}

test "now returns reasonable timestamp" {
    const t = now();
    // Should be after 2024-01-01T00:00:00Z = 1704067200
    try testing.expect(t > 1704067200.0);
}

test "formatRfc3339 end of day" {
    // 2023-12-31T23:59:59.999Z
    const result = formatRfc3339(1704067199999);
    try testing.expectEqualStrings("2023-12-31T23:59:59.999Z", &result);
}
