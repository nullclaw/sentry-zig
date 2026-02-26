const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;
const Writer = std.io.Writer;

const Uuid = @import("uuid.zig").Uuid;
const ts = @import("timestamp.zig");

/// Session status values as defined by the Sentry protocol.
pub const SessionStatus = enum {
    ok,
    exited,
    crashed,
    abnormal,
    errored,

    pub fn toString(self: SessionStatus) []const u8 {
        return switch (self) {
            .ok => "ok",
            .exited => "exited",
            .crashed => "crashed",
            .abnormal => "abnormal",
            .errored => "errored",
        };
    }

    /// Custom JSON serialization: emit as string.
    pub fn jsonStringify(self: SessionStatus, jw: anytype) !void {
        try jw.write(self.toString());
    }
};

/// A Sentry session for release health tracking.
pub const Session = struct {
    sid: [32]u8,
    did: ?[]const u8 = null,
    init_flag: bool = true,
    started: f64,
    timestamp: f64,
    sequence: u64,
    status: SessionStatus = .ok,
    errors: u32 = 0,
    release: []const u8,
    environment: []const u8,
    duration: ?f64 = null,
    track_duration: bool = true,
    dirty: bool = true,

    /// Create a new session with the given release and environment.
    pub fn start(release: []const u8, environment: []const u8) Session {
        return startWithMode(release, environment, true);
    }

    /// Create a session and optionally disable duration tracking (request mode).
    pub fn startWithMode(release: []const u8, environment: []const u8, track_duration: bool) Session {
        const uuid = Uuid.v4();
        const now = ts.now();
        return Session{
            .sid = uuid.toHex(),
            .started = now,
            .timestamp = now,
            .sequence = @intFromFloat(now * 1000.0),
            .release = release,
            .environment = environment,
            .track_duration = track_duration,
        };
    }

    /// Mark the session as having an error. Increments errors count
    /// and sets status to errored if currently ok.
    pub fn markErrored(self: *Session) void {
        self.errors += 1;
        if (self.status == .ok) {
            self.status = .errored;
        }
        self.touch();
        self.dirty = true;
    }

    /// Mark the session as crashed.
    pub fn markCrashed(self: *Session) void {
        self.status = .crashed;
        self.touch();
        self.dirty = true;
    }

    /// End the session with the given status, computing duration.
    pub fn end(self: *Session, status: SessionStatus) void {
        self.status = status;
        self.touch();
        if (self.track_duration) {
            self.duration = self.timestamp - self.started;
        } else {
            self.duration = null;
        }
        self.dirty = true;
    }

    /// Mark the latest update as sent.
    pub fn markSent(self: *Session) void {
        self.init_flag = false;
        self.dirty = false;
    }

    /// Serialize the session to JSON for envelope payload.
    pub fn toJson(self: *const Session, allocator: Allocator) ![]u8 {
        var aw: Writer.Allocating = .init(allocator);
        errdefer aw.deinit();
        const w = &aw.writer;

        try w.writeAll("{\"sid\":\"");
        try w.writeAll(&self.sid);
        try w.writeByte('"');

        if (self.did) |did| {
            try w.writeAll(",\"did\":");
            try json.Stringify.value(did, .{}, w);
        }

        if (self.init_flag) {
            try w.writeAll(",\"init\":true");
        }

        try w.writeAll(",\"started\":\"");
        const started_ms: u64 = @intFromFloat(self.started * 1000.0);
        const started_rfc = ts.formatRfc3339(started_ms);
        try w.writeAll(&started_rfc);
        try w.writeByte('"');

        try w.writeAll(",\"timestamp\":\"");
        const ts_ms: u64 = @intFromFloat(self.timestamp * 1000.0);
        const ts_rfc = ts.formatRfc3339(ts_ms);
        try w.writeAll(&ts_rfc);
        try w.writeByte('"');

        try w.print(",\"seq\":{d}", .{self.sequence});

        try w.writeAll(",\"status\":\"");
        try w.writeAll(self.status.toString());
        try w.writeByte('"');

        try w.print(",\"errors\":{d}", .{self.errors});

        if (self.duration) |dur| {
            try w.print(",\"duration\":{d:.3}", .{dur});
        }

        try w.writeAll(",\"attrs\":{\"release\":");
        try json.Stringify.value(self.release, .{}, w);
        try w.writeAll(",\"environment\":");
        try json.Stringify.value(self.environment, .{}, w);
        try w.writeAll("}}");

        return try aw.toOwnedSlice();
    }

    fn touch(self: *Session) void {
        const now = ts.now();
        const now_seq: u64 = @intFromFloat(now * 1000.0);
        self.timestamp = now;
        if (now_seq <= self.sequence) {
            self.sequence += 1;
        } else {
            self.sequence = now_seq;
        }
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test "Session.start creates valid session" {
    const session = Session.start("my-app@1.0.0", "production");

    // sid should be 32 hex chars
    try testing.expectEqual(@as(usize, 32), session.sid.len);
    for (session.sid) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }

    // started should be a reasonable timestamp
    try testing.expect(session.started > 1704067200.0);
    try testing.expect(session.sequence > 0);

    // init_flag should be true
    try testing.expect(session.init_flag);

    // status should be ok
    try testing.expectEqual(SessionStatus.ok, session.status);

    // errors should be 0
    try testing.expectEqual(@as(u32, 0), session.errors);
}

test "Session.markErrored increments errors and sets status" {
    var session = Session.start("app@1.0", "dev");
    const before_seq = session.sequence;

    session.markErrored();
    try testing.expectEqual(@as(u32, 1), session.errors);
    try testing.expectEqual(SessionStatus.errored, session.status);
    try testing.expect(session.sequence > before_seq);

    session.markErrored();
    try testing.expectEqual(@as(u32, 2), session.errors);
    try testing.expectEqual(SessionStatus.errored, session.status);
}

test "Session.markCrashed sets status" {
    var session = Session.start("app@1.0", "dev");

    session.markCrashed();
    try testing.expectEqual(SessionStatus.crashed, session.status);
}

test "Session.end sets duration and status" {
    var session = Session.start("app@1.0", "dev");
    const before_seq = session.sequence;

    session.end(.exited);
    try testing.expectEqual(SessionStatus.exited, session.status);
    try testing.expect(session.duration != null);
    try testing.expect(session.duration.? >= 0.0);
    try testing.expect(session.sequence > before_seq);
}

test "Session.startWithMode disables duration in request mode" {
    var session = Session.startWithMode("app@1.0", "dev", false);

    session.end(.exited);
    try testing.expectEqual(SessionStatus.exited, session.status);
    try testing.expect(session.duration == null);
}

test "Session.toJson produces valid JSON with expected fields" {
    var session = Session.start("my-app@2.0.0", "staging");
    session.did = "user-abc";

    const json_str = try session.toJson(testing.allocator);
    defer testing.allocator.free(json_str);

    // Verify expected fields are present
    try testing.expect(std.mem.indexOf(u8, json_str, "\"sid\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"did\":\"user-abc\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"init\":true") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"started\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"timestamp\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"seq\":") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"status\":\"ok\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"errors\":0") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"release\":\"my-app@2.0.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"environment\":\"staging\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"attrs\"") != null);
}
