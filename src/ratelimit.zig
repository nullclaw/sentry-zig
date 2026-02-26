const std = @import("std");
const testing = std.testing;

pub const Category = enum {
    any,
    @"error",
    session,
    transaction,
    check_in,
    attachment,
    log_item,
};

pub const Update = struct {
    any: ?u64 = null,
    @"error": ?u64 = null,
    session: ?u64 = null,
    transaction: ?u64 = null,
    check_in: ?u64 = null,
    attachment: ?u64 = null,
    log_item: ?u64 = null,

    pub fn isEmpty(self: Update) bool {
        return self.any == null and
            self.@"error" == null and
            self.session == null and
            self.transaction == null and
            self.check_in == null and
            self.attachment == null and
            self.log_item == null;
    }

    pub fn setMax(self: *Update, category: Category, seconds: u64) void {
        const slot = switch (category) {
            .any => &self.any,
            .@"error" => &self.@"error",
            .session => &self.session,
            .transaction => &self.transaction,
            .check_in => &self.check_in,
            .attachment => &self.attachment,
            .log_item => &self.log_item,
        };

        if (slot.*) |existing| {
            if (seconds > existing) slot.* = seconds;
        } else {
            slot.* = seconds;
        }
    }

    pub fn merge(self: *Update, other: Update) void {
        if (other.any) |seconds| self.setMax(.any, seconds);
        if (other.@"error") |seconds| self.setMax(.@"error", seconds);
        if (other.session) |seconds| self.setMax(.session, seconds);
        if (other.transaction) |seconds| self.setMax(.transaction, seconds);
        if (other.check_in) |seconds| self.setMax(.check_in, seconds);
        if (other.attachment) |seconds| self.setMax(.attachment, seconds);
        if (other.log_item) |seconds| self.setMax(.log_item, seconds);
    }
};

pub const State = struct {
    any_until_ns: ?i128 = null,
    error_until_ns: ?i128 = null,
    session_until_ns: ?i128 = null,
    transaction_until_ns: ?i128 = null,
    check_in_until_ns: ?i128 = null,
    attachment_until_ns: ?i128 = null,
    log_item_until_ns: ?i128 = null,

    pub fn applyUpdate(self: *State, update: Update, now_ns: i128) void {
        if (update.any) |seconds| applyCategory(self, .any, seconds, now_ns);
        if (update.@"error") |seconds| applyCategory(self, .@"error", seconds, now_ns);
        if (update.session) |seconds| applyCategory(self, .session, seconds, now_ns);
        if (update.transaction) |seconds| applyCategory(self, .transaction, seconds, now_ns);
        if (update.check_in) |seconds| applyCategory(self, .check_in, seconds, now_ns);
        if (update.attachment) |seconds| applyCategory(self, .attachment, seconds, now_ns);
        if (update.log_item) |seconds| applyCategory(self, .log_item, seconds, now_ns);
    }

    pub fn isEnabled(self: *State, category: Category, now_ns: i128) bool {
        if (isActive(&self.any_until_ns, now_ns)) return false;

        const slot = switch (category) {
            .any => &self.any_until_ns,
            .@"error" => &self.error_until_ns,
            .session => &self.session_until_ns,
            .transaction => &self.transaction_until_ns,
            .check_in => &self.check_in_until_ns,
            .attachment => &self.attachment_until_ns,
            .log_item => &self.log_item_until_ns,
        };
        return !isActive(slot, now_ns);
    }
};

pub fn parseRetryAfterHeader(header_value: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, header_value, " \t");
    if (trimmed.len == 0) return null;

    if (std.fmt.parseInt(u64, trimmed, 10)) |seconds| {
        return seconds;
    } else |_| {}

    if (std.fmt.parseFloat(f64, trimmed)) |seconds_float| {
        if (!std.math.isFinite(seconds_float) or seconds_float < 0) return null;
        const max_u64_as_f64 = @as(f64, @floatFromInt(std.math.maxInt(u64)));
        if (seconds_float > max_u64_as_f64) return null;
        return @intFromFloat(std.math.ceil(seconds_float));
    } else |_| {}

    return null;
}

pub fn parseSentryRateLimitsHeader(header_value: []const u8) Update {
    var update: Update = .{};
    var groups = std.mem.splitScalar(u8, header_value, ',');
    while (groups.next()) |group| {
        const trimmed_group = std.mem.trim(u8, group, " \t");
        if (trimmed_group.len == 0) continue;

        var parts = std.mem.splitScalar(u8, trimmed_group, ':');
        const seconds_str = parts.next() orelse continue;
        const categories_field = parts.next() orelse continue;
        _ = parts.next() orelse continue; // scope (required by the envelope header grammar)
        const seconds = parseRetryAfterHeader(seconds_str) orelse continue;

        const categories = std.mem.trim(u8, categories_field, " \t");
        if (categories.len == 0) {
            // Empty categories means a global rate limit.
            update.setMax(.any, seconds);
            continue;
        }

        var applied = false;
        var category_it = std.mem.splitScalar(u8, categories, ';');
        while (category_it.next()) |category_raw| {
            const category = parseCategory(category_raw) orelse continue;
            update.setMax(category, seconds);
            applied = true;
        }

        if (!applied) continue;
    }

    return update;
}

fn parseCategory(category_raw: []const u8) ?Category {
    const category = std.mem.trim(u8, category_raw, " \t");
    if (category.len == 0) return null;

    if (std.ascii.eqlIgnoreCase(category, "default")) return .@"error";
    if (std.ascii.eqlIgnoreCase(category, "error")) return .@"error";
    if (std.ascii.eqlIgnoreCase(category, "session")) return .session;
    if (std.ascii.eqlIgnoreCase(category, "transaction")) return .transaction;
    if (std.ascii.eqlIgnoreCase(category, "monitor")) return .check_in;
    if (std.ascii.eqlIgnoreCase(category, "check_in")) return .check_in;
    if (std.ascii.eqlIgnoreCase(category, "attachment")) return .attachment;
    if (std.ascii.eqlIgnoreCase(category, "log_item")) return .log_item;
    return null;
}

fn applyCategory(self: *State, category: Category, seconds: u64, now_ns: i128) void {
    const slot = switch (category) {
        .any => &self.any_until_ns,
        .@"error" => &self.error_until_ns,
        .session => &self.session_until_ns,
        .transaction => &self.transaction_until_ns,
        .check_in => &self.check_in_until_ns,
        .attachment => &self.attachment_until_ns,
        .log_item => &self.log_item_until_ns,
    };

    const until = now_ns + @as(i128, @intCast(seconds)) * std.time.ns_per_s;
    if (slot.*) |existing| {
        if (until > existing) slot.* = until;
    } else {
        slot.* = until;
    }
}

fn isActive(slot: *?i128, now_ns: i128) bool {
    if (slot.*) |until| {
        if (now_ns < until) {
            return true;
        }
        slot.* = null;
    }
    return false;
}

test "parseRetryAfterHeader parses integer and float values" {
    try testing.expectEqual(@as(?u64, 60), parseRetryAfterHeader("60"));
    try testing.expectEqual(@as(?u64, 61), parseRetryAfterHeader("60.1"));
    try testing.expectEqual(@as(?u64, 0), parseRetryAfterHeader("0"));
}

test "parseRetryAfterHeader rejects invalid values" {
    try testing.expectEqual(@as(?u64, null), parseRetryAfterHeader(""));
    try testing.expectEqual(@as(?u64, null), parseRetryAfterHeader("abc"));
    try testing.expectEqual(@as(?u64, null), parseRetryAfterHeader("-1"));
    try testing.expectEqual(@as(?u64, null), parseRetryAfterHeader("1e400"));
}

test "parseSentryRateLimitsHeader parses categories and global entries" {
    const update = parseSentryRateLimitsHeader("120:error:project:reason, 60:session:foo, 30:monitor:foo, 240::organization");
    try testing.expectEqual(@as(?u64, 120), update.@"error");
    try testing.expectEqual(@as(?u64, 60), update.session);
    try testing.expectEqual(@as(?u64, 30), update.check_in);
    try testing.expectEqual(@as(?u64, 240), update.any);
}

test "parseSentryRateLimitsHeader maps default category to error events" {
    const update = parseSentryRateLimitsHeader("42:default:project");
    try testing.expectEqual(@as(?u64, 42), update.@"error");
}

test "parseSentryRateLimitsHeader ignores unsupported categories" {
    const update = parseSentryRateLimitsHeader("120:security:org, 60:error:org");
    try testing.expectEqual(@as(?u64, null), update.session);
    try testing.expectEqual(@as(?u64, 60), update.@"error");
}

test "parseSentryRateLimitsHeader requires scope segment" {
    const update = parseSentryRateLimitsHeader("120:error");
    try testing.expect(update.isEmpty());
}

test "State applies global and category limits" {
    var state: State = .{};
    var update: Update = .{};
    update.setMax(.transaction, 5);
    update.setMax(.any, 2);

    state.applyUpdate(update, 100 * std.time.ns_per_s);

    try testing.expect(!state.isEnabled(.@"error", 101 * std.time.ns_per_s));
    try testing.expect(!state.isEnabled(.transaction, 101 * std.time.ns_per_s));

    try testing.expect(state.isEnabled(.@"error", 103 * std.time.ns_per_s));
    try testing.expect(!state.isEnabled(.transaction, 103 * std.time.ns_per_s));
    try testing.expect(state.isEnabled(.transaction, 106 * std.time.ns_per_s));
}

test "rate limit state applies header semantics correctly" {
    var state: State = .{};
    const now = 500 * std.time.ns_per_s;

    state.applyUpdate(
        parseSentryRateLimitsHeader("120:error:project:reason, 60:session:foo"),
        now,
    );

    try testing.expect(!state.isEnabled(.@"error", now + std.time.ns_per_s));
    try testing.expect(!state.isEnabled(.session, now + std.time.ns_per_s));
    try testing.expect(state.isEnabled(.transaction, now + std.time.ns_per_s));
    try testing.expect(state.isEnabled(.check_in, now + std.time.ns_per_s));
    try testing.expect(state.isEnabled(.log_item, now + std.time.ns_per_s));

    state.applyUpdate(
        parseSentryRateLimitsHeader(
            \\30::bar,
            \\120:invalid:invalid,
            \\4711:foo;bar;baz;security:project
        ),
        now,
    );

    // Empty categories apply a global limit.
    try testing.expect(!state.isEnabled(.transaction, now + std.time.ns_per_s));
    try testing.expect(!state.isEnabled(.check_in, now + std.time.ns_per_s));
    try testing.expect(!state.isEnabled(.any, now + std.time.ns_per_s));
}
