const std = @import("std");
const testing = std.testing;

pub const Uuid = struct {
    bytes: [16]u8,

    /// Generate a new UUID v4 using cryptographic random.
    pub fn v4() Uuid {
        var bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&bytes);

        // Set version 4: byte 6 high nibble = 0x4
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        // Set variant 1: byte 8 high 2 bits = 10
        bytes[8] = (bytes[8] & 0x3F) | 0x80;

        return Uuid{ .bytes = bytes };
    }

    /// Convert to 32-character lowercase hex string (Sentry format, no dashes).
    pub fn toHex(self: Uuid) [32]u8 {
        return std.fmt.bytesToHex(self.bytes, .lower);
    }

    /// Convert to standard dashed UUID format: 8-4-4-4-12.
    pub fn toDashedHex(self: Uuid) [36]u8 {
        const hex = self.toHex();
        var result: [36]u8 = undefined;
        var out_idx: usize = 0;
        for (hex, 0..) |c, i| {
            if (i == 8 or i == 12 or i == 16 or i == 20) {
                result[out_idx] = '-';
                out_idx += 1;
            }
            result[out_idx] = c;
            out_idx += 1;
        }
        return result;
    }

    /// Parse from a 32-character hex string (no dashes).
    pub fn fromHex(hex: []const u8) !Uuid {
        if (hex.len != 32) return error.InvalidLength;
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*b, i| {
            const hi = try hexDigitToInt(hex[i * 2]);
            const lo = try hexDigitToInt(hex[i * 2 + 1]);
            b.* = (@as(u8, hi) << 4) | @as(u8, lo);
        }
        return Uuid{ .bytes = bytes };
    }

    fn hexDigitToInt(c: u8) !u4 {
        return switch (c) {
            '0'...'9' => @intCast(c - '0'),
            'a'...'f' => @intCast(c - 'a' + 10),
            'A'...'F' => @intCast(c - 'A' + 10),
            else => error.InvalidHexDigit,
        };
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test "UUID v4 version bits correct" {
    const uuid = Uuid.v4();
    // Version 4: byte 6 high nibble should be 0x4
    try testing.expectEqual(@as(u8, 0x40), uuid.bytes[6] & 0xF0);
}

test "UUID v4 variant bits correct" {
    const uuid = Uuid.v4();
    // Variant 1: byte 8 high 2 bits should be 10
    try testing.expectEqual(@as(u8, 0x80), uuid.bytes[8] & 0xC0);
}

test "toHex produces 32 lowercase hex chars" {
    const uuid = Uuid.v4();
    const hex = uuid.toHex();
    try testing.expectEqual(@as(usize, 32), hex.len);
    for (hex) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "toDashedHex produces valid format" {
    const uuid = Uuid.v4();
    const dashed = uuid.toDashedHex();
    try testing.expectEqual(@as(usize, 36), dashed.len);
    // Dashes at positions 8, 13, 18, 23
    try testing.expectEqual(@as(u8, '-'), dashed[8]);
    try testing.expectEqual(@as(u8, '-'), dashed[13]);
    try testing.expectEqual(@as(u8, '-'), dashed[18]);
    try testing.expectEqual(@as(u8, '-'), dashed[23]);
}

test "fromHex roundtrip" {
    const uuid = Uuid.v4();
    const hex = uuid.toHex();
    const parsed = try Uuid.fromHex(&hex);
    try testing.expectEqualSlices(u8, &uuid.bytes, &parsed.bytes);
}

test "fromHex with known value" {
    const hex = "550e8400e29b41d4a716446655440000";
    const uuid = try Uuid.fromHex(hex);
    const roundtrip = uuid.toHex();
    try testing.expectEqualStrings(hex, &roundtrip);
}

test "fromHex invalid length" {
    const result = Uuid.fromHex("abc");
    try testing.expectError(error.InvalidLength, result);
}
