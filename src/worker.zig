const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const ratelimit = @import("ratelimit.zig");

pub const MAX_QUEUE_SIZE: usize = 100;

const WorkQueue = struct {
    storage: []WorkItem = &.{},
    head: usize = 0,
    len: usize = 0,

    fn init(allocator: Allocator, cap: usize) !WorkQueue {
        if (cap == 0) return error.InvalidQueueCapacity;
        return .{
            .storage = try allocator.alloc(WorkItem, cap),
        };
    }

    fn deinit(self: *WorkQueue, allocator: Allocator) void {
        if (self.storage.len > 0) {
            allocator.free(self.storage);
        }
        self.* = .{};
    }

    fn capacity(self: *const WorkQueue) usize {
        return self.storage.len;
    }

    fn pushDropOldest(self: *WorkQueue, item: WorkItem) ?WorkItem {
        if (self.storage.len == 0) return null;

        if (self.len == self.storage.len) {
            const dropped = self.storage[self.head];
            self.storage[self.head] = item;
            self.head = (self.head + 1) % self.storage.len;
            return dropped;
        }

        const tail = (self.head + self.len) % self.storage.len;
        self.storage[tail] = item;
        self.len += 1;
        return null;
    }

    fn popOldest(self: *WorkQueue) ?WorkItem {
        if (self.len == 0) return null;
        const item = self.storage[self.head];
        self.head = (self.head + 1) % self.storage.len;
        self.len -= 1;
        if (self.len == 0) {
            self.head = 0;
        }
        return item;
    }
};

pub const WorkItem = struct {
    data: []u8,
    category: ratelimit.Category,
};

pub const SendOutcome = struct {
    rate_limits: ratelimit.Update = .{},
};

pub const SendFn = *const fn ([]const u8, ?*anyopaque) SendOutcome;

/// Background worker thread that consumes work items from a thread-safe queue.
pub const Worker = struct {
    allocator: Allocator,
    queue: WorkQueue = .{},
    mutex: std.Thread.Mutex = .{},
    condition: std.Thread.Condition = .{},
    flush_condition: std.Thread.Condition = .{},
    shutdown_flag: bool = false,
    in_flight: usize = 0,
    rate_limit_state: ratelimit.State = .{},
    thread: ?std.Thread = null,
    send_fn: SendFn,
    send_ctx: ?*anyopaque = null,

    pub fn init(allocator: Allocator, send_fn: SendFn, send_ctx: ?*anyopaque) !Worker {
        return .{
            .allocator = allocator,
            .queue = try WorkQueue.init(allocator, MAX_QUEUE_SIZE),
            .send_fn = send_fn,
            .send_ctx = send_ctx,
        };
    }

    pub fn deinit(self: *Worker) void {
        while (self.queue.popOldest()) |item| {
            self.allocator.free(item.data);
        }
        self.queue.deinit(self.allocator);
    }

    /// Spawn the background worker thread.
    pub fn start(self: *Worker) !void {
        self.thread = try std.Thread.spawn(.{}, workerLoop, .{self});
    }

    /// Submit a work item to the queue. The worker takes ownership of data.
    /// If the queue is full, the oldest item is dropped.
    /// If shutdown has been requested, the data is freed immediately.
    pub fn submit(self: *Worker, data: []u8, category: ratelimit.Category) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.shutdown_flag) {
            self.allocator.free(data);
            return;
        }

        const dropped = self.queue.pushDropOldest(.{
            .data = data,
            .category = category,
        });
        if (dropped) |old| {
            self.allocator.free(old.data);
        }
        self.condition.signal();
    }

    /// Flush the queue, waiting up to timeout_ms for it to drain.
    /// Returns true if the queue is empty after flush.
    pub fn flush(self: *Worker, timeout_ms: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const timeout_ns: i128 = @as(i128, @intCast(timeout_ms)) * std.time.ns_per_ms;
        const deadline = std.time.nanoTimestamp() + timeout_ns;

        while (self.queue.len > 0 or self.in_flight > 0) {
            // Wake the worker to process queued items.
            self.condition.signal();

            const now = std.time.nanoTimestamp();
            if (now >= deadline) return false;

            const remaining: u64 = @intCast(deadline - now);
            self.flush_condition.timedWait(&self.mutex, remaining) catch {};
        }

        return true;
    }

    /// Signal shutdown and wait for the worker thread to finish.
    pub fn shutdown(self: *Worker) void {
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.shutdown_flag = true;
            self.condition.signal();
        }

        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Return the current queue length (thread-safe).
    pub fn queueLen(self: *Worker) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.queue.len;
    }

    /// Return whether the worker still accepts new items.
    pub fn isAccepting(self: *Worker) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return !self.shutdown_flag;
    }

    fn workerLoop(self: *Worker) void {
        while (true) {
            var item: ?WorkItem = null;

            {
                self.mutex.lock();
                defer self.mutex.unlock();

                while (self.queue.len == 0 and !self.shutdown_flag) {
                    self.condition.wait(&self.mutex);
                }

                if (self.shutdown_flag and self.queue.len == 0 and self.in_flight == 0) {
                    self.flush_condition.signal();
                    return;
                }

                if (self.queue.len > 0) {
                    item = self.queue.popOldest();
                    self.in_flight += 1;
                }

                if (self.queue.len == 0 and self.in_flight == 0) {
                    self.flush_condition.signal();
                }
            }

            if (item) |work| {
                defer self.allocator.free(work.data);

                const now_ns = std.time.nanoTimestamp();
                if (self.rate_limit_state.isEnabled(work.category, now_ns)) {
                    const outcome = self.send_fn(work.data, self.send_ctx);
                    self.rate_limit_state.applyUpdate(outcome.rate_limits, std.time.nanoTimestamp());
                }

                self.mutex.lock();
                self.in_flight -= 1;
                if (self.queue.len == 0 and self.in_flight == 0) {
                    self.flush_condition.signal();
                }
                self.mutex.unlock();
            }
        }
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

var test_send_count: usize = 0;

fn testSendFn(_: []const u8, _: ?*anyopaque) SendOutcome {
    test_send_count += 1;
    return .{};
}

fn noopSendFn(_: []const u8, _: ?*anyopaque) SendOutcome {
    return .{};
}

fn rateLimitingSendFn(_: []const u8, ctx: ?*anyopaque) SendOutcome {
    const counter: *usize = @ptrCast(@alignCast(ctx.?));
    counter.* += 1;
    if (counter.* == 1) {
        var update: ratelimit.Update = .{};
        update.setMax(.any, 1);
        return .{ .rate_limits = update };
    }
    return .{};
}

const CategoryRateLimitCtx = struct {
    sent_error: usize = 0,
    sent_transaction: usize = 0,
};

fn categoryRateLimitingSendFn(data: []const u8, ctx: ?*anyopaque) SendOutcome {
    const state: *CategoryRateLimitCtx = @ptrCast(@alignCast(ctx.?));

    if (std.mem.eql(u8, data, "txn-1")) {
        state.sent_transaction += 1;
        var update: ratelimit.Update = .{};
        update.setMax(.transaction, 1);
        return .{ .rate_limits = update };
    }
    if (std.mem.eql(u8, data, "txn-2")) {
        state.sent_transaction += 1;
        return .{};
    }

    state.sent_error += 1;
    return .{};
}

test "WorkQueue ring semantics keep bounded FIFO order" {
    var queue = try WorkQueue.init(testing.allocator, 3);
    defer queue.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 3), queue.capacity());
    try testing.expectEqual(@as(usize, 0), queue.len);

    try testing.expect(queue.pushDropOldest(.{ .data = undefined, .category = .any }) == null);
    try testing.expect(queue.pushDropOldest(.{ .data = undefined, .category = .@"error" }) == null);
    try testing.expect(queue.pushDropOldest(.{ .data = undefined, .category = .session }) == null);
    try testing.expectEqual(@as(usize, 3), queue.len);

    const dropped = queue.pushDropOldest(.{ .data = undefined, .category = .transaction });
    try testing.expect(dropped != null);
    try testing.expectEqual(ratelimit.Category.any, dropped.?.category);

    try testing.expectEqual(ratelimit.Category.@"error", queue.popOldest().?.category);
    try testing.expectEqual(ratelimit.Category.session, queue.popOldest().?.category);
    try testing.expectEqual(ratelimit.Category.transaction, queue.popOldest().?.category);
    try testing.expect(queue.popOldest() == null);
    try testing.expectEqual(@as(usize, 0), queue.len);
}

test "Worker submit and process via background thread" {
    test_send_count = 0;

    var worker = try Worker.init(testing.allocator, testSendFn, null);
    defer worker.deinit();

    try worker.start();

    // Submit a work item
    const data1 = try testing.allocator.dupe(u8, "item-1");
    try worker.submit(data1, .@"error");

    const data2 = try testing.allocator.dupe(u8, "item-2");
    try worker.submit(data2, .@"error");

    // Flush to wait for processing
    _ = worker.flush(1000);

    worker.shutdown();

    try testing.expectEqual(@as(usize, 2), test_send_count);
}

test "Worker drops oldest when queue full" {
    var worker = try Worker.init(testing.allocator, noopSendFn, null);
    defer worker.deinit();

    // Don't start the thread so items accumulate
    // Submit MAX_QUEUE_SIZE + 5 items
    var i: usize = 0;
    while (i < MAX_QUEUE_SIZE + 5) : (i += 1) {
        const data = try testing.allocator.dupe(u8, "item");
        try worker.submit(data, .@"error");
    }

    try testing.expectEqual(MAX_QUEUE_SIZE, worker.queueLen());
}

test "Worker shutdown drains remaining items" {
    test_send_count = 0;

    var worker = try Worker.init(testing.allocator, testSendFn, null);
    defer worker.deinit();

    try worker.start();

    const data = try testing.allocator.dupe(u8, "final-item");
    try worker.submit(data, .@"error");

    // Shutdown should process remaining items
    worker.shutdown();

    // The item should have been processed or freed
    try testing.expectEqual(@as(usize, 0), worker.queueLen());
}

test "Worker flush returns true when queue is empty" {
    var worker = try Worker.init(testing.allocator, noopSendFn, null);
    defer worker.deinit();

    // Empty queue => flush should return true immediately
    try testing.expect(worker.flush(100));
}

test "Worker drops queued items while rate limited" {
    var send_count: usize = 0;

    var worker = try Worker.init(testing.allocator, rateLimitingSendFn, @ptrCast(&send_count));
    defer worker.deinit();

    try worker.start();

    const first = try testing.allocator.dupe(u8, "first");
    try worker.submit(first, .@"error");

    const second = try testing.allocator.dupe(u8, "second");
    try worker.submit(second, .@"error");

    _ = worker.flush(1000);
    worker.shutdown();

    // First send triggers retry-after; second should be dropped by rate limit.
    try testing.expectEqual(@as(usize, 1), send_count);
}

test "Worker applies category-specific rate limits" {
    var ctx: CategoryRateLimitCtx = .{};
    var worker = try Worker.init(testing.allocator, categoryRateLimitingSendFn, @ptrCast(&ctx));
    defer worker.deinit();

    try worker.start();

    const txn1 = try testing.allocator.dupe(u8, "txn-1");
    try worker.submit(txn1, .transaction);

    const evt1 = try testing.allocator.dupe(u8, "evt-1");
    try worker.submit(evt1, .@"error");

    const txn2 = try testing.allocator.dupe(u8, "txn-2");
    try worker.submit(txn2, .transaction);

    _ = worker.flush(1000);
    worker.shutdown();

    // Transaction limit should only drop transaction items, not errors.
    try testing.expectEqual(@as(usize, 1), ctx.sent_transaction);
    try testing.expectEqual(@as(usize, 1), ctx.sent_error);
}
