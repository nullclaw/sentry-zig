const std = @import("std");
const testing = std.testing;

const Client = @import("../client.zig").Client;
const Hub = @import("../hub.zig").Hub;
const SendOutcome = @import("../worker.zig").SendOutcome;

/// Detached Hub container for worker threads and async-style task boundaries.
///
/// It clones the current top scope (`fromCurrent`) or an explicit source Hub
/// (`fromTop`) and can temporarily bind that clone as current TLS Hub via `run`.
pub const DetachedHub = struct {
    allocator: std.mem.Allocator,
    hub: *Hub,
    active: bool = true,

    /// Clone from current TLS Hub top scope when available, otherwise initialize
    /// from explicit `client`.
    pub fn fromCurrent(allocator: std.mem.Allocator, client: ?*Client) !DetachedHub {
        const hub_ptr = try allocator.create(Hub);
        errdefer allocator.destroy(hub_ptr);

        if (Hub.current()) |current| {
            hub_ptr.* = try Hub.initFromTop(allocator, current, client);
        } else {
            const base_client = client orelse return error.NoCurrentHubOrClient;
            hub_ptr.* = try Hub.init(allocator, base_client);
        }
        errdefer hub_ptr.deinit();

        return .{
            .allocator = allocator,
            .hub = hub_ptr,
        };
    }

    /// Clone from an explicit source hub.
    pub fn fromTop(allocator: std.mem.Allocator, source: *Hub, client: ?*Client) !DetachedHub {
        const hub_ptr = try allocator.create(Hub);
        errdefer allocator.destroy(hub_ptr);

        hub_ptr.* = try Hub.initFromTop(allocator, source, client);
        errdefer hub_ptr.deinit();

        return .{
            .allocator = allocator,
            .hub = hub_ptr,
        };
    }

    pub fn hubPtr(self: *DetachedHub) *Hub {
        return self.hub;
    }

    /// Run callback with this detached hub installed as current TLS Hub, then
    /// restore the previous TLS Hub.
    pub fn run(self: *DetachedHub, callback: anytype, args: anytype) @TypeOf(@call(.auto, callback, args)) {
        const previous = Hub.setCurrent(self.hub);
        defer {
            _ = Hub.clearCurrent();
            if (previous) |previous_hub| {
                _ = Hub.setCurrent(previous_hub);
            }
        }
        return @call(.auto, callback, args);
    }

    pub fn deinit(self: *DetachedHub) void {
        if (!self.active) return;
        self.active = false;

        if (Hub.current()) |current| {
            if (current == self.hub) {
                _ = Hub.clearCurrent();
            }
        }

        self.hub.deinit();
        self.allocator.destroy(self.hub);
    }
};

/// Spawn a thread that runs with a Hub cloned from current TLS Hub.
///
/// The spawned worker gets an isolated scope snapshot and `Hub.current()` set
/// for the thread lifetime. Any returned error from an error-union callback is
/// captured through Sentry as `ZigError`.
pub fn spawnWithCurrentHub(
    allocator: std.mem.Allocator,
    config: std.Thread.SpawnConfig,
    comptime callback: anytype,
    args: anytype,
) !std.Thread {
    const detached = try DetachedHub.fromCurrent(allocator, null);
    return spawnWithDetached(allocator, detached, config, callback, args);
}

/// Spawn a thread that runs with a Hub cloned from `source`.
pub fn spawnFromHub(
    allocator: std.mem.Allocator,
    source: *Hub,
    config: std.Thread.SpawnConfig,
    comptime callback: anytype,
    args: anytype,
) !std.Thread {
    const detached = try DetachedHub.fromTop(allocator, source, null);
    return spawnWithDetached(allocator, detached, config, callback, args);
}

fn spawnWithDetached(
    allocator: std.mem.Allocator,
    detached: DetachedHub,
    config: std.Thread.SpawnConfig,
    comptime callback: anytype,
    args: anytype,
) !std.Thread {
    const ArgsType = @TypeOf(args);
    const Context = struct {
        allocator: std.mem.Allocator,
        detached: DetachedHub,
        args: ArgsType,
    };

    var owned_detached = detached;
    errdefer owned_detached.deinit();

    const context = try allocator.create(Context);
    errdefer allocator.destroy(context);

    context.* = .{
        .allocator = allocator,
        .detached = owned_detached,
        .args = args,
    };

    return std.Thread.spawn(config, struct {
        fn entry(ctx: *Context) void {
            defer {
                ctx.detached.deinit();
                ctx.allocator.destroy(ctx);
            }
            ctx.detached.run(runTask, .{ctx});
        }

        fn runTask(ctx: *Context) void {
            const ResultType = @TypeOf(@call(.auto, callback, ctx.args));
            switch (@typeInfo(ResultType)) {
                .void => {
                    @call(.auto, callback, ctx.args);
                },
                .error_union => {
                    _ = @call(.auto, callback, ctx.args) catch |err| {
                        _ = ctx.detached.hubPtr().captureErrorId(err);
                    };
                },
                else => {
                    _ = @call(.auto, callback, ctx.args);
                },
            }
        }
    }.entry, .{context});
}

const PayloadState = struct {
    allocator: std.mem.Allocator,
    payloads: std.ArrayListUnmanaged([]u8) = .{},

    fn deinit(self: *PayloadState) void {
        for (self.payloads.items) |payload| self.allocator.free(payload);
        self.payloads.deinit(self.allocator);
        self.* = undefined;
    }
};

fn payloadSendFn(data: []const u8, ctx: ?*anyopaque) SendOutcome {
    const state: *PayloadState = @ptrCast(@alignCast(ctx.?));
    const copied = state.allocator.dupe(u8, data) catch return .{};
    state.payloads.append(state.allocator, copied) catch state.allocator.free(copied);
    return .{};
}

const ObserveCurrent = struct {
    expected: *Hub,
    saw_expected: bool = false,
};

fn observeCurrent(state: *ObserveCurrent) void {
    if (Hub.current()) |current| {
        state.saw_expected = current == state.expected;
    }
}

fn captureWorkerEvent(worker_hub: *DetachedHub) void {
    worker_hub.hubPtr().setTag("worker", "email-delivery");
    _ = worker_hub.hubPtr().captureMessageId("worker start", .info);
}

const SpawnObserve = struct {
    observed_current_hub: bool = false,
    observed_tenant_tag: bool = false,
};

fn spawnedWorkerCapture(state: *SpawnObserve) void {
    if (Hub.current()) |hub| {
        state.observed_current_hub = true;
        if (hub.currentScope().tags.get("tenant")) |tenant| {
            state.observed_tenant_tag = std.mem.eql(u8, tenant, "acme");
        }
        hub.setTag("worker", "thread-1");
        _ = hub.captureMessageId("spawnWithCurrentHub event", .info);
    }
}

const DemoError = error{
    DemoFailure,
};

fn runDemo(value: usize) DemoError!usize {
    if (value == 0) return error.DemoFailure;
    return value + 1;
}

const SpawnError = error{
    BackgroundFailure,
};

fn spawnedWorkerFailure(_: *u8) SpawnError!void {
    return error.BackgroundFailure;
}

fn spawnedWorkerNoop() void {}

test "DetachedHub run swaps current hub and restores previous" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var primary = try Hub.init(testing.allocator, client);
    defer primary.deinit();

    _ = Hub.setCurrent(&primary);
    defer _ = Hub.clearCurrent();

    var detached = try DetachedHub.fromCurrent(testing.allocator, client);
    defer detached.deinit();

    var observation = ObserveCurrent{
        .expected = detached.hubPtr(),
    };
    detached.run(observeCurrent, .{&observation});

    try testing.expect(observation.saw_expected);
    try testing.expect(Hub.current().? == &primary);
}

test "DetachedHub fromCurrent clones top scope and isolates worker scope changes" {
    var payload_state = PayloadState{ .allocator = testing.allocator };
    defer payload_state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .transport = .{
            .send_fn = payloadSendFn,
            .ctx = &payload_state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var primary = try Hub.init(testing.allocator, client);
    defer primary.deinit();

    _ = Hub.setCurrent(&primary);
    defer _ = Hub.clearCurrent();

    primary.setTag("tenant", "acme");

    var detached = try DetachedHub.fromCurrent(testing.allocator, client);
    defer detached.deinit();

    detached.run(captureWorkerEvent, .{&detached});

    try testing.expect(primary.currentScope().tags.get("worker") == null);
    try testing.expectEqualStrings("acme", primary.currentScope().tags.get("tenant").?);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "\"tenant\":\"acme\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "\"worker\":\"email-delivery\"") != null);
}

test "DetachedHub run preserves callback return type including errors" {
    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var detached = try DetachedHub.fromCurrent(testing.allocator, client);
    defer detached.deinit();

    try testing.expectError(error.DemoFailure, detached.run(runDemo, .{0}));
    const value = try detached.run(runDemo, .{41});
    try testing.expectEqual(@as(usize, 42), value);
}

test "DetachedHub fromCurrent requires current hub or explicit client" {
    _ = Hub.clearCurrent();
    try testing.expect(Hub.current() == null);
    try testing.expectError(error.NoCurrentHubOrClient, DetachedHub.fromCurrent(testing.allocator, null));
}

test "spawnWithCurrentHub clones scope context into worker and isolates parent mutations" {
    var payload_state = PayloadState{ .allocator = testing.allocator };
    defer payload_state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .transport = .{
            .send_fn = payloadSendFn,
            .ctx = &payload_state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    _ = Hub.setCurrent(&hub);
    defer _ = Hub.clearCurrent();
    hub.setTag("tenant", "acme");

    var observation = SpawnObserve{};
    const thread = try spawnWithCurrentHub(testing.allocator, .{}, spawnedWorkerCapture, .{&observation});
    thread.join();

    try testing.expect(observation.observed_current_hub);
    try testing.expect(observation.observed_tenant_tag);
    try testing.expectEqualStrings("acme", hub.currentScope().tags.get("tenant").?);
    try testing.expect(hub.currentScope().tags.get("worker") == null);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "\"tenant\":\"acme\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "\"worker\":\"thread-1\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "spawnWithCurrentHub event") != null);
}

test "spawnWithCurrentHub captures returned worker errors" {
    var payload_state = PayloadState{ .allocator = testing.allocator };
    defer payload_state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .transport = .{
            .send_fn = payloadSendFn,
            .ctx = &payload_state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var hub = try Hub.init(testing.allocator, client);
    defer hub.deinit();

    _ = Hub.setCurrent(&hub);
    defer _ = Hub.clearCurrent();

    var token: u8 = 1;
    const thread = try spawnWithCurrentHub(testing.allocator, .{}, spawnedWorkerFailure, .{&token});
    thread.join();

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);

    var saw_error_event = false;
    for (payload_state.payloads.items) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"event\"") != null and
            std.mem.indexOf(u8, payload, "\"value\":\"BackgroundFailure\"") != null)
        {
            saw_error_event = true;
        }
    }
    try testing.expect(saw_error_event);
}

test "spawnWithCurrentHub requires current hub" {
    _ = Hub.clearCurrent();
    try testing.expect(Hub.current() == null);
    try testing.expectError(
        error.NoCurrentHubOrClient,
        spawnWithCurrentHub(testing.allocator, .{}, spawnedWorkerNoop, .{}),
    );
}

test "spawnFromHub works without current TLS hub" {
    var payload_state = PayloadState{ .allocator = testing.allocator };
    defer payload_state.deinit();

    const client = try Client.init(testing.allocator, .{
        .dsn = "https://examplePublicKey@o0.ingest.sentry.io/1234567",
        .transport = .{
            .send_fn = payloadSendFn,
            .ctx = &payload_state,
        },
        .install_signal_handlers = false,
    });
    defer client.deinit();

    var source_hub = try Hub.init(testing.allocator, client);
    defer source_hub.deinit();
    source_hub.setTag("tenant", "acme");

    _ = Hub.clearCurrent();
    try testing.expect(Hub.current() == null);

    var observation = SpawnObserve{};
    const thread = try spawnFromHub(testing.allocator, &source_hub, .{}, spawnedWorkerCapture, .{&observation});
    thread.join();

    try testing.expect(observation.observed_current_hub);
    try testing.expect(observation.observed_tenant_tag);
    try testing.expect(Hub.current() == null);

    try testing.expect(client.flush(1000));
    try testing.expect(payload_state.payloads.items.len >= 1);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "\"tenant\":\"acme\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload_state.payloads.items[0], "\"worker\":\"thread-1\"") != null);
}
