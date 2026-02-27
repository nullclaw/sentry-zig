const std = @import("std");
const testing = std.testing;

const Integration = @import("../client.zig").Integration;
const log = @import("log.zig");
const panic = @import("panic.zig");

const DEFAULTS = [_]Integration{
    .{ .setup = log.setup },
    .{ .setup = panic.setup },
};

/// Returns a static slice of built-in setup integrations intended for
/// `Options.integrations`.
///
/// This preset installs default runtime behavior for:
/// - std.log capture (`integrations.log`)
/// - panic capture (`integrations.panic`)
pub fn defaults() []const Integration {
    return &DEFAULTS;
}

test "auto defaults expose log and panic setup callbacks" {
    const values = defaults();
    try testing.expectEqual(@as(usize, 2), values.len);
    try testing.expect(values[0].setup == log.setup);
    try testing.expect(values[1].setup == panic.setup);
    try testing.expect(values[0].ctx == null);
    try testing.expect(values[1].ctx == null);
}
