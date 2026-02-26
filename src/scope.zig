const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const json = std.json;

const event_mod = @import("event.zig");
const Event = event_mod.Event;
const Level = event_mod.Level;
const User = event_mod.User;
const Breadcrumb = event_mod.Breadcrumb;
const Attachment = @import("attachment.zig").Attachment;
const ts = @import("timestamp.zig");

pub const MAX_BREADCRUMBS = 200;
pub const EventProcessor = *const fn (*Event) bool;

pub const ApplyResult = struct {
    level_applied: bool = false,
    user_allocated: bool = false,
    transaction_allocated: bool = false,
    fingerprint_allocated: bool = false,
    tags_allocated: bool = false,
    extra_allocated: bool = false,
    contexts_allocated: bool = false,
    breadcrumbs_allocated: bool = false,
    applied_user: ?User = null,
    applied_transaction: ?[]const u8 = null,
    applied_fingerprint: ?[][]const u8 = null,
    applied_tags: ?json.Value = null,
    applied_extra: ?json.Value = null,
    applied_contexts: ?json.Value = null,
    applied_breadcrumbs: ?[]Breadcrumb = null,
    previous_level: ?Level = null,
    previous_transaction: ?[]const u8 = null,
    previous_fingerprint: ?[]const []const u8 = null,
    previous_tags: ?json.Value = null,
    previous_extra: ?json.Value = null,
    previous_contexts: ?json.Value = null,
    previous_breadcrumbs: ?[]const Breadcrumb = null,
};

fn cloneOptionalString(allocator: Allocator, value: ?[]const u8) !?[]const u8 {
    if (value) |v| return try allocator.dupe(u8, v);
    return null;
}

fn deinitOptionalString(allocator: Allocator, value: *?[]const u8) void {
    if (value.*) |v| {
        allocator.free(@constCast(v));
        value.* = null;
    }
}

fn cloneUser(allocator: Allocator, user: User) !User {
    var copy: User = .{};
    copy.id = try cloneOptionalString(allocator, user.id);
    errdefer deinitUserDeep(allocator, &copy);

    copy.email = try cloneOptionalString(allocator, user.email);
    copy.username = try cloneOptionalString(allocator, user.username);
    copy.ip_address = try cloneOptionalString(allocator, user.ip_address);
    copy.segment = try cloneOptionalString(allocator, user.segment);
    return copy;
}

pub fn deinitUserDeep(allocator: Allocator, user: *User) void {
    deinitOptionalString(allocator, &user.id);
    deinitOptionalString(allocator, &user.email);
    deinitOptionalString(allocator, &user.username);
    deinitOptionalString(allocator, &user.ip_address);
    deinitOptionalString(allocator, &user.segment);
}

pub fn deinitJsonValueDeep(allocator: Allocator, value: *json.Value) void {
    switch (value.*) {
        .number_string => |s| allocator.free(@constCast(s)),
        .string => |s| allocator.free(@constCast(s)),
        .array => |*arr| {
            for (arr.items) |*item| {
                deinitJsonValueDeep(allocator, item);
            }
            arr.deinit();
        },
        .object => |*obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                allocator.free(@constCast(entry.key_ptr.*));
                deinitJsonValueDeep(allocator, entry.value_ptr);
            }
            obj.deinit();
        },
        else => {},
    }
    value.* = .null;
}

fn deinitJsonObjectDeep(allocator: Allocator, obj: *json.ObjectMap) void {
    var it = obj.iterator();
    while (it.next()) |entry| {
        allocator.free(@constCast(entry.key_ptr.*));
        deinitJsonValueDeep(allocator, entry.value_ptr);
    }
    obj.deinit();
}

fn cloneObjectInto(allocator: Allocator, dest: *json.ObjectMap, src: json.ObjectMap) !void {
    var it = src.iterator();
    while (it.next()) |entry| {
        const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
        errdefer allocator.free(key_copy);

        var value_copy = try cloneJsonValue(allocator, entry.value_ptr.*);
        errdefer deinitJsonValueDeep(allocator, &value_copy);

        try dest.put(key_copy, value_copy);
    }
}

fn upsertOwnedObjectEntry(allocator: Allocator, obj: *json.ObjectMap, key: []const u8, value: json.Value) !void {
    if (obj.fetchOrderedRemove(key)) |kv| {
        allocator.free(@constCast(kv.key));
        var old_value = kv.value;
        deinitJsonValueDeep(allocator, &old_value);
    }

    const key_copy = try allocator.dupe(u8, key);
    errdefer allocator.free(key_copy);

    try obj.put(key_copy, value);
}

pub fn cloneJsonValue(allocator: Allocator, value: json.Value) !json.Value {
    return switch (value) {
        .null => .null,
        .bool => |v| .{ .bool = v },
        .integer => |v| .{ .integer = v },
        .float => |v| .{ .float = v },
        .number_string => |v| .{ .number_string = try allocator.dupe(u8, v) },
        .string => |v| .{ .string = try allocator.dupe(u8, v) },
        .array => |arr| blk: {
            var copy = json.Array.init(allocator);
            errdefer {
                for (copy.items) |*item| {
                    deinitJsonValueDeep(allocator, item);
                }
                copy.deinit();
            }

            for (arr.items) |item| {
                try copy.append(try cloneJsonValue(allocator, item));
            }
            break :blk .{ .array = copy };
        },
        .object => |obj| blk: {
            var copy = json.ObjectMap.init(allocator);
            errdefer deinitJsonObjectDeep(allocator, &copy);

            var it = obj.iterator();
            while (it.next()) |entry| {
                const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(key_copy);

                var value_copy = try cloneJsonValue(allocator, entry.value_ptr.*);
                errdefer deinitJsonValueDeep(allocator, &value_copy);

                try copy.put(key_copy, value_copy);
            }
            break :blk .{ .object = copy };
        },
    };
}

fn cloneBreadcrumb(allocator: Allocator, crumb: Breadcrumb) !Breadcrumb {
    var copy: Breadcrumb = .{
        .timestamp = crumb.timestamp,
        .level = crumb.level,
    };
    copy.type = try cloneOptionalString(allocator, crumb.type);
    errdefer deinitBreadcrumbDeep(allocator, &copy);

    copy.category = try cloneOptionalString(allocator, crumb.category);
    copy.message = try cloneOptionalString(allocator, crumb.message);
    copy.data = if (crumb.data) |value| try cloneJsonValue(allocator, value) else null;
    return copy;
}

pub fn deinitBreadcrumbDeep(allocator: Allocator, crumb: *Breadcrumb) void {
    deinitOptionalString(allocator, &crumb.type);
    deinitOptionalString(allocator, &crumb.category);
    deinitOptionalString(allocator, &crumb.message);
    if (crumb.data) |*value| {
        deinitJsonValueDeep(allocator, value);
    }
    crumb.data = null;
}

/// Fixed-size ring buffer for breadcrumbs.
pub const BreadcrumbBuffer = struct {
    buffer: []Breadcrumb,
    capacity: usize,
    head: usize = 0,
    count: usize = 0,
    allocator: Allocator,

    pub fn init(allocator: Allocator, capacity: usize) !BreadcrumbBuffer {
        const clamped = if (capacity > MAX_BREADCRUMBS) MAX_BREADCRUMBS else capacity;
        const cap = if (clamped == 0) 1 else clamped; // at least 1 to avoid division by zero
        const buf = try allocator.alloc(Breadcrumb, cap);
        return BreadcrumbBuffer{
            .buffer = buf,
            .capacity = cap,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BreadcrumbBuffer) void {
        self.clear();
        self.allocator.free(self.buffer);
        self.* = undefined;
    }

    /// O(1) push. Overwrites oldest breadcrumb when full.
    pub fn push(self: *BreadcrumbBuffer, crumb: Breadcrumb) void {
        if (self.count == self.capacity) {
            deinitBreadcrumbDeep(self.allocator, &self.buffer[self.head]);
        } else {
            self.count += 1;
        }

        self.buffer[self.head] = crumb;
        self.head = (self.head + 1) % self.capacity;
    }

    /// Return breadcrumbs in insertion order.
    pub fn toSlice(self: *const BreadcrumbBuffer, allocator: Allocator) ![]Breadcrumb {
        const result = try allocator.alloc(Breadcrumb, self.count);
        if (self.count < self.capacity) {
            // Buffer has not wrapped around yet.
            @memcpy(result, self.buffer[0..self.count]);
        } else {
            // Buffer has wrapped; oldest is at head.
            const first_part_len = self.capacity - self.head;
            @memcpy(result[0..first_part_len], self.buffer[self.head..self.capacity]);
            @memcpy(result[first_part_len..], self.buffer[0..self.head]);
        }
        return result;
    }

    pub fn clear(self: *BreadcrumbBuffer) void {
        if (self.count == 0) {
            self.head = 0;
            return;
        }

        if (self.count < self.capacity) {
            for (self.buffer[0..self.count]) |*crumb| {
                deinitBreadcrumbDeep(self.allocator, crumb);
            }
        } else {
            for (self.buffer) |*crumb| {
                deinitBreadcrumbDeep(self.allocator, crumb);
            }
        }

        self.head = 0;
        self.count = 0;
    }
};

fn clearTagMapOwned(allocator: Allocator, map: *std.StringHashMap([]const u8)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(@constCast(entry.key_ptr.*));
        allocator.free(@constCast(entry.value_ptr.*));
    }
    map.clearRetainingCapacity();
}

fn deinitTagMapOwned(allocator: Allocator, map: *std.StringHashMap([]const u8)) void {
    clearTagMapOwned(allocator, map);
    map.deinit();
}

fn clearJsonMapOwned(allocator: Allocator, map: *std.StringHashMap(json.Value)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(@constCast(entry.key_ptr.*));
        deinitJsonValueDeep(allocator, entry.value_ptr);
    }
    map.clearRetainingCapacity();
}

fn deinitJsonMapOwned(allocator: Allocator, map: *std.StringHashMap(json.Value)) void {
    clearJsonMapOwned(allocator, map);
    map.deinit();
}

pub fn deinitAttachmentSlice(allocator: Allocator, attachments: []Attachment) void {
    for (attachments) |*attachment| {
        attachment.deinit(allocator);
    }
    allocator.free(attachments);
}

fn cloneStringSlice(allocator: Allocator, values: []const []const u8) ![][]const u8 {
    const cloned = try allocator.alloc([]const u8, values.len);
    var initialized: usize = 0;
    errdefer {
        for (cloned[0..initialized]) |item| {
            allocator.free(@constCast(item));
        }
        allocator.free(cloned);
    }

    for (values) |value| {
        cloned[initialized] = try allocator.dupe(u8, value);
        initialized += 1;
    }

    return cloned;
}

fn deinitStringSlice(allocator: Allocator, values: [][]const u8) void {
    for (values) |value| {
        allocator.free(@constCast(value));
    }
    allocator.free(values);
}

/// The Scope holds mutable state applied to every event.
pub const Scope = struct {
    allocator: Allocator,
    level: ?Level = null,
    user: ?User = null,
    transaction: ?[]const u8 = null,
    fingerprint: std.ArrayListUnmanaged([]const u8) = .{},
    tags: std.StringHashMap([]const u8),
    extra: std.StringHashMap(json.Value),
    contexts: std.StringHashMap(json.Value),
    attachments: std.ArrayListUnmanaged(Attachment) = .{},
    event_processors: std.ArrayListUnmanaged(EventProcessor) = .{},
    breadcrumbs: BreadcrumbBuffer,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: Allocator, max_breadcrumbs: usize) !Scope {
        return Scope{
            .allocator = allocator,
            .tags = std.StringHashMap([]const u8).init(allocator),
            .extra = std.StringHashMap(json.Value).init(allocator),
            .contexts = std.StringHashMap(json.Value).init(allocator),
            .breadcrumbs = try BreadcrumbBuffer.init(allocator, max_breadcrumbs),
        };
    }

    /// Create a deep clone of this scope and all owned data.
    pub fn clone(self: *Scope, allocator: Allocator) !Scope {
        self.mutex.lock();
        defer self.mutex.unlock();

        var cloned = Scope{
            .allocator = allocator,
            .level = self.level,
            .tags = std.StringHashMap([]const u8).init(allocator),
            .extra = std.StringHashMap(json.Value).init(allocator),
            .contexts = std.StringHashMap(json.Value).init(allocator),
            .breadcrumbs = try BreadcrumbBuffer.init(allocator, self.breadcrumbs.capacity),
        };
        errdefer cloned.deinit();

        if (self.user) |u| {
            cloned.user = try cloneUser(allocator, u);
        }

        if (self.transaction) |transaction| {
            cloned.transaction = try allocator.dupe(u8, transaction);
        }

        if (self.fingerprint.items.len > 0) {
            try cloned.fingerprint.ensureTotalCapacity(allocator, self.fingerprint.items.len);
            for (self.fingerprint.items) |item| {
                try cloned.fingerprint.append(allocator, try allocator.dupe(u8, item));
            }
        }

        var tag_it = self.tags.iterator();
        while (tag_it.next()) |entry| {
            const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
            errdefer allocator.free(key_copy);
            const value_copy = try allocator.dupe(u8, entry.value_ptr.*);
            errdefer allocator.free(value_copy);
            try cloned.tags.put(key_copy, value_copy);
        }

        var extra_it = self.extra.iterator();
        while (extra_it.next()) |entry| {
            const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
            errdefer allocator.free(key_copy);
            var value_copy = try cloneJsonValue(allocator, entry.value_ptr.*);
            errdefer deinitJsonValueDeep(allocator, &value_copy);
            try cloned.extra.put(key_copy, value_copy);
        }

        var context_it = self.contexts.iterator();
        while (context_it.next()) |entry| {
            const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
            errdefer allocator.free(key_copy);
            var value_copy = try cloneJsonValue(allocator, entry.value_ptr.*);
            errdefer deinitJsonValueDeep(allocator, &value_copy);
            try cloned.contexts.put(key_copy, value_copy);
        }

        if (self.attachments.items.len > 0) {
            try cloned.attachments.ensureTotalCapacity(allocator, self.attachments.items.len);
            for (self.attachments.items) |attachment| {
                var owned = try attachment.clone(allocator);
                errdefer owned.deinit(allocator);
                try cloned.attachments.append(allocator, owned);
            }
        }

        if (self.event_processors.items.len > 0) {
            try cloned.event_processors.appendSlice(allocator, self.event_processors.items);
        }

        if (self.breadcrumbs.count > 0) {
            const ordered = try self.breadcrumbs.toSlice(allocator);
            defer allocator.free(ordered);
            for (ordered) |crumb| {
                const cloned_crumb = try cloneBreadcrumb(allocator, crumb);
                cloned.breadcrumbs.push(cloned_crumb);
            }
        }

        return cloned;
    }

    pub fn deinit(self: *Scope) void {
        if (self.user) |*u| {
            deinitUserDeep(self.allocator, u);
            self.user = null;
        }
        if (self.transaction) |transaction| {
            self.allocator.free(@constCast(transaction));
            self.transaction = null;
        }
        self.clearFingerprintOwned();
        self.fingerprint.deinit(self.allocator);

        deinitTagMapOwned(self.allocator, &self.tags);
        deinitJsonMapOwned(self.allocator, &self.extra);
        deinitJsonMapOwned(self.allocator, &self.contexts);
        self.clearAttachmentsOwned();
        self.attachments.deinit(self.allocator);
        self.event_processors.deinit(self.allocator);
        self.breadcrumbs.deinit();
        self.* = undefined;
    }

    /// Set the user context (thread-safe).
    pub fn setUser(self: *Scope, user: ?User) void {
        self.trySetUser(user) catch {};
    }

    /// Set the user context and surface allocation failures.
    pub fn trySetUser(self: *Scope, user: ?User) !void {
        var replacement: ?User = null;
        var replacement_owned = false;
        errdefer if (replacement_owned) {
            var owned = replacement.?;
            deinitUserDeep(self.allocator, &owned);
        };

        if (user) |u| {
            replacement = try cloneUser(self.allocator, u);
            replacement_owned = true;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.user) |*existing| {
            deinitUserDeep(self.allocator, existing);
            self.user = null;
        }

        self.user = replacement;
        replacement_owned = false;
    }

    /// Set the event level for this scope.
    pub fn setLevel(self: *Scope, level: ?Level) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.level = level;
    }

    /// Set transaction name override for events in this scope.
    pub fn setTransaction(self: *Scope, transaction: ?[]const u8) !void {
        var replacement: ?[]const u8 = null;
        errdefer if (replacement) |value| self.allocator.free(@constCast(value));

        if (transaction) |name| {
            replacement = try self.allocator.dupe(u8, name);
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.transaction) |current| {
            self.allocator.free(@constCast(current));
            self.transaction = null;
        }

        self.transaction = replacement;
        replacement = null;
    }

    /// Set scope fingerprint override.
    pub fn setFingerprint(self: *Scope, fingerprint: ?[]const []const u8) !void {
        var replacement: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer {
            for (replacement.items) |item| {
                self.allocator.free(@constCast(item));
            }
            replacement.deinit(self.allocator);
        }

        if (fingerprint) |items| {
            try replacement.ensureTotalCapacity(self.allocator, items.len);
            for (items) |item| {
                try replacement.append(self.allocator, try self.allocator.dupe(u8, item));
            }
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        const old = self.fingerprint;
        self.fingerprint = replacement;
        replacement = .{};

        for (old.items) |item| {
            self.allocator.free(@constCast(item));
        }
        var old_mut = old;
        old_mut.deinit(self.allocator);
    }

    /// Set a tag (thread-safe).
    pub fn setTag(self: *Scope, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        var value_copy: ?[]const u8 = null;
        var committed = false;
        errdefer if (!committed) {
            self.allocator.free(key_copy);
            if (value_copy) |v| self.allocator.free(@constCast(v));
        };

        value_copy = try self.allocator.dupe(u8, value);

        self.mutex.lock();
        defer self.mutex.unlock();

        try self.tags.ensureUnusedCapacity(1);

        if (self.tags.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            self.allocator.free(@constCast(kv.value));
        }

        self.tags.putAssumeCapacity(key_copy, value_copy.?);
        committed = true;
    }

    /// Remove a tag.
    pub fn removeTag(self: *Scope, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tags.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            self.allocator.free(@constCast(kv.value));
        }
    }

    /// Set an extra value (thread-safe).
    pub fn setExtra(self: *Scope, key: []const u8, value: json.Value) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        var value_copy: ?json.Value = null;
        var committed = false;
        errdefer if (!committed) {
            self.allocator.free(key_copy);
            if (value_copy) |*v| deinitJsonValueDeep(self.allocator, v);
        };

        value_copy = try cloneJsonValue(self.allocator, value);

        self.mutex.lock();
        defer self.mutex.unlock();

        try self.extra.ensureUnusedCapacity(1);

        if (self.extra.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            var old_value = kv.value;
            deinitJsonValueDeep(self.allocator, &old_value);
        }

        self.extra.putAssumeCapacity(key_copy, value_copy.?);
        committed = true;
    }

    /// Remove an extra value.
    pub fn removeExtra(self: *Scope, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.extra.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            var old_value = kv.value;
            deinitJsonValueDeep(self.allocator, &old_value);
        }
    }

    /// Set a context (thread-safe).
    pub fn setContext(self: *Scope, key: []const u8, value: json.Value) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        var value_copy: ?json.Value = null;
        var committed = false;
        errdefer if (!committed) {
            self.allocator.free(key_copy);
            if (value_copy) |*v| deinitJsonValueDeep(self.allocator, v);
        };

        value_copy = try cloneJsonValue(self.allocator, value);

        self.mutex.lock();
        defer self.mutex.unlock();

        try self.contexts.ensureUnusedCapacity(1);

        if (self.contexts.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            var old_value = kv.value;
            deinitJsonValueDeep(self.allocator, &old_value);
        }

        self.contexts.putAssumeCapacity(key_copy, value_copy.?);
        committed = true;
    }

    /// Remove a context value.
    pub fn removeContext(self: *Scope, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.contexts.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            var old_value = kv.value;
            deinitJsonValueDeep(self.allocator, &old_value);
        }
    }

    /// Add a breadcrumb (thread-safe).
    pub fn addBreadcrumb(self: *Scope, crumb: Breadcrumb) void {
        self.tryAddBreadcrumb(crumb) catch {};
    }

    /// Add a breadcrumb and surface allocation failures.
    pub fn tryAddBreadcrumb(self: *Scope, crumb: Breadcrumb) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var owned = try cloneBreadcrumb(self.allocator, crumb);
        if (owned.timestamp == null) {
            owned.timestamp = ts.now();
        }
        self.breadcrumbs.push(owned);
    }

    /// Clear all breadcrumbs from the scope.
    pub fn clearBreadcrumbs(self: *Scope) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.breadcrumbs.clear();
    }

    /// Add an attachment to the scope. The scope stores an owned clone.
    pub fn addAttachment(self: *Scope, attachment: Attachment) void {
        self.tryAddAttachment(attachment) catch {};
    }

    /// Add an attachment to the scope and surface allocation failures.
    pub fn tryAddAttachment(self: *Scope, attachment: Attachment) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var owned = try attachment.clone(self.allocator);
        errdefer owned.deinit(self.allocator);
        try self.attachments.append(self.allocator, owned);
    }

    /// Clear scope attachments.
    pub fn clearAttachments(self: *Scope) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.clearAttachmentsOwned();
    }

    /// Add an event processor. Return false from a processor to drop the event.
    pub fn addEventProcessor(self: *Scope, processor: EventProcessor) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.event_processors.append(self.allocator, processor);
    }

    /// Clear all configured event processors.
    pub fn clearEventProcessors(self: *Scope) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.event_processors.clearRetainingCapacity();
    }

    /// Snapshot attachments into newly allocated owned copies for event capture.
    pub fn snapshotAttachments(self: *Scope, allocator: Allocator) ![]Attachment {
        self.mutex.lock();
        defer self.mutex.unlock();

        const out = try allocator.alloc(Attachment, self.attachments.items.len);
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |*attachment| {
                attachment.deinit(allocator);
            }
            allocator.free(out);
        }

        for (self.attachments.items) |attachment| {
            out[initialized] = try attachment.clone(allocator);
            initialized += 1;
        }
        return out;
    }

    /// Apply scope tags/extra/contexts to a transaction-like object.
    /// The transaction must provide `setTag`, `setExtra`, and `setContext`.
    pub fn applyToTransaction(self: *Scope, transaction: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var tag_it = self.tags.iterator();
        while (tag_it.next()) |entry| {
            try transaction.setTag(entry.key_ptr.*, entry.value_ptr.*);
        }

        var extra_it = self.extra.iterator();
        while (extra_it.next()) |entry| {
            try transaction.setExtra(entry.key_ptr.*, entry.value_ptr.*);
        }

        var context_it = self.contexts.iterator();
        while (context_it.next()) |entry| {
            try transaction.setContext(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    /// Apply scope data to an event before sending.
    pub fn applyToEvent(self: *Scope, allocator: Allocator, event: *Event) !ApplyResult {
        var result: ApplyResult = .{};
        errdefer cleanupAppliedToEvent(allocator, event, result);

        var processor_snapshot: ?[]EventProcessor = null;
        defer if (processor_snapshot) |snapshot| allocator.free(snapshot);

        self.mutex.lock();
        var lock_held = true;
        errdefer if (lock_held) self.mutex.unlock();

        if (self.level) |level| {
            result.previous_level = event.level;
            event.level = level;
            result.level_applied = true;
        }

        if (event.transaction == null and self.transaction != null) {
            result.previous_transaction = event.transaction;
            const cloned_transaction = try allocator.dupe(u8, self.transaction.?);
            event.transaction = cloned_transaction;
            result.transaction_allocated = true;
            result.applied_transaction = cloned_transaction;
        }

        if (event.fingerprint == null and self.fingerprint.items.len > 0) {
            result.previous_fingerprint = event.fingerprint;
            const cloned_fingerprint = try cloneStringSlice(allocator, self.fingerprint.items);
            event.fingerprint = cloned_fingerprint;
            result.fingerprint_allocated = true;
            result.applied_fingerprint = cloned_fingerprint;
        }

        // Apply user only when event user is not set.
        if (event.user == null and self.user != null) {
            const u = self.user.?;
            const cloned_user = try cloneUser(allocator, u);
            event.user = cloned_user;
            result.user_allocated = true;
            result.applied_user = cloned_user;
        }

        // Merge tags.
        if (self.tags.count() > 0) {
            var obj = json.ObjectMap.init(allocator);
            errdefer deinitJsonObjectDeep(allocator, &obj);

            if (event.tags) |existing_tags| {
                if (existing_tags == .object) {
                    try cloneObjectInto(allocator, &obj, existing_tags.object);
                }
            }

            var scope_it = self.tags.iterator();
            while (scope_it.next()) |entry| {
                const value_copy = try allocator.dupe(u8, entry.value_ptr.*);
                errdefer allocator.free(value_copy);

                try upsertOwnedObjectEntry(allocator, &obj, entry.key_ptr.*, .{ .string = value_copy });
            }

            result.previous_tags = event.tags;
            event.tags = .{ .object = obj };
            result.tags_allocated = true;
            result.applied_tags = event.tags;
        }

        // Merge extra.
        if (self.extra.count() > 0) {
            var obj = json.ObjectMap.init(allocator);
            errdefer deinitJsonObjectDeep(allocator, &obj);

            if (event.extra) |existing_extra| {
                if (existing_extra == .object) {
                    try cloneObjectInto(allocator, &obj, existing_extra.object);
                }
            }

            var scope_it = self.extra.iterator();
            while (scope_it.next()) |entry| {
                var value_copy = try cloneJsonValue(allocator, entry.value_ptr.*);
                errdefer deinitJsonValueDeep(allocator, &value_copy);

                try upsertOwnedObjectEntry(allocator, &obj, entry.key_ptr.*, value_copy);
            }

            result.previous_extra = event.extra;
            event.extra = .{ .object = obj };
            result.extra_allocated = true;
            result.applied_extra = event.extra;
        }

        // Merge contexts.
        if (self.contexts.count() > 0) {
            var obj = json.ObjectMap.init(allocator);
            errdefer deinitJsonObjectDeep(allocator, &obj);

            if (event.contexts) |existing_contexts| {
                if (existing_contexts == .object) {
                    try cloneObjectInto(allocator, &obj, existing_contexts.object);
                }
            }

            var scope_it = self.contexts.iterator();
            while (scope_it.next()) |entry| {
                var value_copy = try cloneJsonValue(allocator, entry.value_ptr.*);
                errdefer deinitJsonValueDeep(allocator, &value_copy);

                try upsertOwnedObjectEntry(allocator, &obj, entry.key_ptr.*, value_copy);
            }

            result.previous_contexts = event.contexts;
            event.contexts = .{ .object = obj };
            result.contexts_allocated = true;
            result.applied_contexts = event.contexts;
        }

        // Merge breadcrumbs: event breadcrumbs first, scope breadcrumbs after.
        if (self.breadcrumbs.count > 0) {
            const ordered = try self.breadcrumbs.toSlice(allocator);
            defer allocator.free(ordered);

            const existing_crumbs = event.breadcrumbs orelse &.{};
            const total_len = existing_crumbs.len + ordered.len;
            const crumbs = try allocator.alloc(Breadcrumb, total_len);
            var initialized: usize = 0;
            errdefer {
                for (crumbs[0..initialized]) |*crumb| {
                    deinitBreadcrumbDeep(allocator, crumb);
                }
                allocator.free(crumbs);
            }

            for (existing_crumbs) |crumb| {
                crumbs[initialized] = try cloneBreadcrumb(allocator, crumb);
                initialized += 1;
            }

            for (ordered) |crumb| {
                crumbs[initialized] = try cloneBreadcrumb(allocator, crumb);
                initialized += 1;
            }

            result.previous_breadcrumbs = event.breadcrumbs;
            event.breadcrumbs = crumbs;
            result.breadcrumbs_allocated = true;
            result.applied_breadcrumbs = crumbs;
        }

        if (self.event_processors.items.len > 0) {
            const copied = try allocator.alloc(EventProcessor, self.event_processors.items.len);
            @memcpy(copied, self.event_processors.items);
            processor_snapshot = copied;
        }

        self.mutex.unlock();
        lock_held = false;

        if (processor_snapshot) |processors| {
            for (processors) |processor| {
                if (!processor(event)) return error.EventDropped;
            }
        }

        return result;
    }

    /// Reset all fields.
    pub fn clear(self: *Scope) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.user) |*u| {
            deinitUserDeep(self.allocator, u);
            self.user = null;
        }
        if (self.transaction) |transaction| {
            self.allocator.free(@constCast(transaction));
            self.transaction = null;
        }
        self.level = null;
        self.clearFingerprintOwned();

        clearTagMapOwned(self.allocator, &self.tags);
        clearJsonMapOwned(self.allocator, &self.extra);
        clearJsonMapOwned(self.allocator, &self.contexts);
        self.clearAttachmentsOwned();
        self.event_processors.clearRetainingCapacity();
        self.breadcrumbs.clear();
    }

    fn clearAttachmentsOwned(self: *Scope) void {
        for (self.attachments.items) |*attachment| {
            attachment.deinit(self.allocator);
        }
        self.attachments.clearRetainingCapacity();
    }

    fn clearFingerprintOwned(self: *Scope) void {
        for (self.fingerprint.items) |item| {
            self.allocator.free(@constCast(item));
        }
        self.fingerprint.clearRetainingCapacity();
    }
};

pub fn cleanupAppliedToEvent(allocator: Allocator, event: *Event, result: ApplyResult) void {
    if (result.level_applied) {
        event.level = result.previous_level;
    }

    if (result.transaction_allocated) {
        if (result.applied_transaction) |transaction| {
            allocator.free(@constCast(transaction));
        }
        event.transaction = result.previous_transaction;
    }

    if (result.fingerprint_allocated) {
        if (result.applied_fingerprint) |fingerprint| {
            deinitStringSlice(allocator, fingerprint);
        }
        event.fingerprint = result.previous_fingerprint;
    }

    if (result.user_allocated) {
        if (result.applied_user) |user| {
            var owned_user = user;
            deinitUserDeep(allocator, &owned_user);
        }
        event.user = null;
    }

    if (result.tags_allocated) {
        if (result.applied_tags) |tags| {
            var owned_tags = tags;
            deinitJsonValueDeep(allocator, &owned_tags);
        }
        event.tags = result.previous_tags;
    }

    if (result.extra_allocated) {
        if (result.applied_extra) |extra| {
            var owned_extra = extra;
            deinitJsonValueDeep(allocator, &owned_extra);
        }
        event.extra = result.previous_extra;
    }

    if (result.contexts_allocated) {
        if (result.applied_contexts) |contexts| {
            var owned_contexts = contexts;
            deinitJsonValueDeep(allocator, &owned_contexts);
        }
        event.contexts = result.previous_contexts;
    }

    if (result.breadcrumbs_allocated) {
        if (result.applied_breadcrumbs) |crumbs| {
            for (crumbs) |*crumb| {
                deinitBreadcrumbDeep(allocator, crumb);
            }
            allocator.free(crumbs);
        }
        event.breadcrumbs = result.previous_breadcrumbs;
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "BreadcrumbBuffer push and read" {
    var buf = try BreadcrumbBuffer.init(testing.allocator, 10);
    defer buf.deinit();

    buf.push(.{ .message = try testing.allocator.dupe(u8, "crumb1"), .category = try testing.allocator.dupe(u8, "test") });
    buf.push(.{ .message = try testing.allocator.dupe(u8, "crumb2"), .category = try testing.allocator.dupe(u8, "test") });

    try testing.expectEqual(@as(usize, 2), buf.count);

    const slice = try buf.toSlice(testing.allocator);
    defer testing.allocator.free(slice);

    try testing.expectEqual(@as(usize, 2), slice.len);
    try testing.expectEqualStrings("crumb1", slice[0].message.?);
    try testing.expectEqualStrings("crumb2", slice[1].message.?);
}

test "BreadcrumbBuffer wraps around" {
    var buf = try BreadcrumbBuffer.init(testing.allocator, 2);
    defer buf.deinit();

    buf.push(.{ .message = try testing.allocator.dupe(u8, "first") });
    buf.push(.{ .message = try testing.allocator.dupe(u8, "second") });
    buf.push(.{ .message = try testing.allocator.dupe(u8, "third") }); // overwrites "first"

    try testing.expectEqual(@as(usize, 2), buf.count);

    const slice = try buf.toSlice(testing.allocator);
    defer testing.allocator.free(slice);

    try testing.expectEqual(@as(usize, 2), slice.len);
    // Should be in order: second, third (oldest first)
    try testing.expectEqualStrings("second", slice[0].message.?);
    try testing.expectEqualStrings("third", slice[1].message.?);
}

test "Scope setTag and setUser" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    scope.setUser(.{ .id = "user-123", .email = "test@example.com" });
    try scope.setTag("environment", "production");
    try scope.setTag("release", "1.0.0");

    try testing.expectEqualStrings("user-123", scope.user.?.id.?);
    try testing.expectEqualStrings("test@example.com", scope.user.?.email.?);
    try testing.expectEqualStrings("production", scope.tags.get("environment").?);
    try testing.expectEqualStrings("1.0.0", scope.tags.get("release").?);
}

test "Scope applyToEvent" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    scope.setUser(.{ .id = "user-42" });
    try scope.setTag("env", "test");
    scope.addBreadcrumb(.{ .message = "navigation", .category = "ui" });

    var event = Event.init();
    const applied = try scope.applyToEvent(testing.allocator, &event);
    defer cleanupAppliedToEvent(testing.allocator, &event, applied);

    // Verify user applied
    try testing.expectEqualStrings("user-42", event.user.?.id.?);

    // Verify tags applied
    try testing.expect(event.tags != null);

    // Verify breadcrumbs applied
    try testing.expect(event.breadcrumbs != null);
    try testing.expectEqual(@as(usize, 1), event.breadcrumbs.?.len);
    try testing.expectEqualStrings("navigation", event.breadcrumbs.?[0].message.?);
}

test "Scope applyToEvent merges tags and breadcrumbs and restores originals on cleanup" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    try scope.setTag("scope", "2");
    scope.addBreadcrumb(.{ .message = "scope-crumb", .category = "scope" });

    var event = Event.init();
    var event_tags = json.ObjectMap.init(testing.allocator);
    try event_tags.put(try testing.allocator.dupe(u8, "event"), .{ .string = try testing.allocator.dupe(u8, "1") });
    event.tags = .{ .object = event_tags };

    const original_crumbs = [_]Breadcrumb{.{ .message = "event-crumb" }};
    event.breadcrumbs = &original_crumbs;

    const applied = try scope.applyToEvent(testing.allocator, &event);

    // Merged tags should contain both keys.
    try testing.expect(event.tags != null);
    const merged_tags = event.tags.?.object;
    try testing.expectEqualStrings("1", merged_tags.get("event").?.string);
    try testing.expectEqualStrings("2", merged_tags.get("scope").?.string);

    // Breadcrumbs should append scope entries after event entries.
    try testing.expect(event.breadcrumbs != null);
    try testing.expectEqual(@as(usize, 2), event.breadcrumbs.?.len);
    try testing.expectEqualStrings("event-crumb", event.breadcrumbs.?[0].message.?);
    try testing.expectEqualStrings("scope-crumb", event.breadcrumbs.?[1].message.?);

    cleanupAppliedToEvent(testing.allocator, &event, applied);

    // Original fields are restored.
    try testing.expect(event.tags != null);
    try testing.expect(event.breadcrumbs != null);
    try testing.expectEqual(@as(usize, 1), event.breadcrumbs.?.len);
    try testing.expectEqualStrings("event-crumb", event.breadcrumbs.?[0].message.?);

    // Cleanup original event tags.
    if (event.tags) |*tags| {
        deinitJsonValueDeep(testing.allocator, tags);
        event.tags = null;
    }
    event.breadcrumbs = null;
}

test "Scope applyToEvent does not override existing event user" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    scope.setUser(.{ .id = "scope-user" });

    var event = Event.init();
    event.user = .{ .id = "event-user" };

    const applied = try scope.applyToEvent(testing.allocator, &event);
    defer cleanupAppliedToEvent(testing.allocator, &event, applied);

    try testing.expect(event.user != null);
    try testing.expectEqualStrings("event-user", event.user.?.id.?);
    try testing.expect(!applied.user_allocated);
}

test "Scope applyToEvent sets transaction and fingerprint and restores on cleanup" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    try scope.setTransaction("txn-from-scope");
    try scope.setFingerprint(&.{ "fp-1", "fp-2" });

    var event = Event.init();
    const applied = try scope.applyToEvent(testing.allocator, &event);

    try testing.expectEqualStrings("txn-from-scope", event.transaction.?);
    try testing.expect(event.fingerprint != null);
    try testing.expectEqual(@as(usize, 2), event.fingerprint.?.len);
    try testing.expectEqualStrings("fp-1", event.fingerprint.?[0]);
    try testing.expectEqualStrings("fp-2", event.fingerprint.?[1]);

    cleanupAppliedToEvent(testing.allocator, &event, applied);
    try testing.expect(event.transaction == null);
    try testing.expect(event.fingerprint == null);
}

const ScopeTransactionProbe = struct {
    allocator: Allocator,
    tags: std.StringHashMap([]const u8),
    extra: std.StringHashMap(json.Value),
    contexts: std.StringHashMap(json.Value),

    fn init(allocator: Allocator) ScopeTransactionProbe {
        return .{
            .allocator = allocator,
            .tags = std.StringHashMap([]const u8).init(allocator),
            .extra = std.StringHashMap(json.Value).init(allocator),
            .contexts = std.StringHashMap(json.Value).init(allocator),
        };
    }

    fn deinit(self: *ScopeTransactionProbe) void {
        var tag_it = self.tags.iterator();
        while (tag_it.next()) |entry| {
            self.allocator.free(@constCast(entry.key_ptr.*));
            self.allocator.free(@constCast(entry.value_ptr.*));
        }
        self.tags.deinit();

        var extra_it = self.extra.iterator();
        while (extra_it.next()) |entry| {
            self.allocator.free(@constCast(entry.key_ptr.*));
            deinitJsonValueDeep(self.allocator, entry.value_ptr);
        }
        self.extra.deinit();

        var context_it = self.contexts.iterator();
        while (context_it.next()) |entry| {
            self.allocator.free(@constCast(entry.key_ptr.*));
            deinitJsonValueDeep(self.allocator, entry.value_ptr);
        }
        self.contexts.deinit();
    }

    fn setTag(self: *ScopeTransactionProbe, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        if (self.tags.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            self.allocator.free(@constCast(kv.value));
        }

        try self.tags.put(key_copy, value_copy);
    }

    fn setExtra(self: *ScopeTransactionProbe, key: []const u8, value: json.Value) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        var value_copy = try cloneJsonValue(self.allocator, value);
        errdefer deinitJsonValueDeep(self.allocator, &value_copy);

        if (self.extra.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            var old = kv.value;
            deinitJsonValueDeep(self.allocator, &old);
        }

        try self.extra.put(key_copy, value_copy);
    }

    fn setContext(self: *ScopeTransactionProbe, key: []const u8, value: json.Value) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        var value_copy = try cloneJsonValue(self.allocator, value);
        errdefer deinitJsonValueDeep(self.allocator, &value_copy);

        if (self.contexts.fetchRemove(key)) |kv| {
            self.allocator.free(@constCast(kv.key));
            var old = kv.value;
            deinitJsonValueDeep(self.allocator, &old);
        }

        try self.contexts.put(key_copy, value_copy);
    }
};

const FailingTransactionSink = struct {
    fn setTag(_: *FailingTransactionSink, _: []const u8, _: []const u8) !void {
        return error.OutOfMemory;
    }

    fn setExtra(_: *FailingTransactionSink, _: []const u8, _: json.Value) !void {}

    fn setContext(_: *FailingTransactionSink, _: []const u8, _: json.Value) !void {}
};

test "Scope applyToTransaction copies tags extra and contexts" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    try scope.setTag("flow", "checkout");
    try scope.setExtra("attempt", .{ .integer = 2 });
    try scope.setContext("app", .{ .integer = 42 });

    var probe = ScopeTransactionProbe.init(testing.allocator);
    defer probe.deinit();

    try scope.applyToTransaction(&probe);

    try testing.expectEqualStrings("checkout", probe.tags.get("flow").?);

    const extra = probe.extra.get("attempt").?;
    try testing.expect(extra == .integer);
    try testing.expectEqual(@as(i64, 2), extra.integer);

    const context = probe.contexts.get("app").?;
    try testing.expect(context == .integer);
    try testing.expectEqual(@as(i64, 42), context.integer);
}

test "Scope applyToTransaction propagates transaction sink errors" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    try scope.setTag("flow", "checkout");

    var sink = FailingTransactionSink{};
    try testing.expectError(error.OutOfMemory, scope.applyToTransaction(&sink));
}

test "Scope stores owned tag strings" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    var key_buf = [_]u8{ 'k', 'e', 'y' };
    var value_buf = [_]u8{ 'o', 'n', 'e' };

    try scope.setTag(key_buf[0..], value_buf[0..]);

    key_buf[0] = 'x';
    value_buf[0] = 'z';

    try testing.expectEqualStrings("one", scope.tags.get("key").?);
}

test "Scope setTag preserves previous value when allocation fails" {
    var failing_allocator_state = std.testing.FailingAllocator.init(testing.allocator, .{});
    const failing_allocator = failing_allocator_state.allocator();

    var scope = try Scope.init(failing_allocator, 10);
    defer scope.deinit();

    try scope.setTag("key", "one");
    failing_allocator_state.fail_index = failing_allocator_state.alloc_index;

    try testing.expectError(error.OutOfMemory, scope.setTag("key", "two"));
    try testing.expectEqualStrings("one", scope.tags.get("key").?);
}

test "Scope setTransaction preserves previous value when allocation fails" {
    var failing_allocator_state = std.testing.FailingAllocator.init(testing.allocator, .{});
    const failing_allocator = failing_allocator_state.allocator();

    var scope = try Scope.init(failing_allocator, 10);
    defer scope.deinit();

    try scope.setTransaction("txn-a");
    failing_allocator_state.fail_index = failing_allocator_state.alloc_index;

    try testing.expectError(error.OutOfMemory, scope.setTransaction("txn-b"));
    try testing.expectEqualStrings("txn-a", scope.transaction.?);
}

test "Scope clear resets all fields" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    scope.setUser(.{ .id = "user-1" });
    try scope.setTag("key", "value");
    scope.addBreadcrumb(.{ .message = "crumb" });
    var attachment = try Attachment.initOwned(
        testing.allocator,
        "note.txt",
        "abc",
        "text/plain",
        null,
    );
    defer attachment.deinit(testing.allocator);
    scope.addAttachment(attachment);

    scope.clear();

    try testing.expect(scope.user == null);
    try testing.expectEqual(@as(usize, 0), scope.tags.count());
    try testing.expectEqual(@as(usize, 0), scope.breadcrumbs.count);
    try testing.expectEqual(@as(usize, 0), scope.attachments.items.len);
}

test "Scope removeExtra and removeContext remove owned values" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    try scope.setExtra("extra-key", .{ .string = "extra-value" });
    try scope.setContext("ctx-key", .{ .integer = 42 });

    try testing.expect(scope.extra.get("extra-key") != null);
    try testing.expect(scope.contexts.get("ctx-key") != null);

    scope.removeExtra("extra-key");
    scope.removeContext("ctx-key");

    try testing.expect(scope.extra.get("extra-key") == null);
    try testing.expect(scope.contexts.get("ctx-key") == null);
}

test "Scope clearBreadcrumbs removes stored breadcrumbs" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    scope.addBreadcrumb(.{ .message = "crumb-1" });
    scope.addBreadcrumb(.{ .message = "crumb-2" });
    try testing.expectEqual(@as(usize, 2), scope.breadcrumbs.count);

    scope.clearBreadcrumbs();
    try testing.expectEqual(@as(usize, 0), scope.breadcrumbs.count);
}

test "Scope level overrides event level during applyToEvent" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    scope.setLevel(.fatal);

    var event = Event.init();
    event.level = .info;

    const applied = try scope.applyToEvent(testing.allocator, &event);
    try testing.expectEqual(Level.fatal, event.level.?);

    cleanupAppliedToEvent(testing.allocator, &event, applied);
    try testing.expectEqual(Level.info, event.level.?);
}

test "Scope applyToEvent rolls back mutations on allocation failure" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    scope.setLevel(.fatal);
    scope.setUser(.{ .id = "scope-user" });
    try scope.setTag("scope-tag", "value");

    var event = Event.init();
    event.level = .info;

    var failing_allocator_state = std.testing.FailingAllocator.init(testing.allocator, .{
        .fail_index = 0,
    });
    const failing_allocator = failing_allocator_state.allocator();

    try testing.expectError(error.OutOfMemory, scope.applyToEvent(failing_allocator, &event));

    // Scope application failed; original event must remain unchanged.
    try testing.expectEqual(Level.info, event.level.?);
    try testing.expect(event.user == null);
    try testing.expect(event.tags == null);
    try testing.expect(event.extra == null);
    try testing.expect(event.contexts == null);
    try testing.expect(event.breadcrumbs == null);
}

test "cleanupAppliedToEvent is robust when event fields are mutated after apply" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    scope.setUser(.{ .id = "scope-user" });
    try scope.setTag("scope-tag", "scope-value");
    try scope.setExtra("scope-extra", .{ .string = "scope" });
    try scope.setContext("scope-context", .{ .integer = 1 });
    try scope.setTransaction("scope-txn");
    try scope.setFingerprint(&.{"scope-fp"});
    scope.addBreadcrumb(.{ .message = "scope-crumb" });

    var event = Event.init();
    const applied = try scope.applyToEvent(testing.allocator, &event);

    // Simulate a before_send hook replacing fields with non-owned data.
    const external_crumbs = [_]Breadcrumb{.{ .message = "external-crumb" }};
    event.user = .{ .id = "external-user" };
    event.tags = .{ .string = "external-tags" };
    event.extra = .{ .string = "external-extra" };
    event.contexts = .{ .string = "external-contexts" };
    event.transaction = "external-transaction";
    event.fingerprint = &.{"external-fingerprint"};
    event.breadcrumbs = &external_crumbs;

    cleanupAppliedToEvent(testing.allocator, &event, applied);

    try testing.expect(event.user == null);
    try testing.expect(event.tags == null);
    try testing.expect(event.extra == null);
    try testing.expect(event.contexts == null);
    try testing.expect(event.transaction == null);
    try testing.expect(event.fingerprint == null);
    try testing.expect(event.breadcrumbs == null);
}

test "Scope snapshotAttachments returns owned copies" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    var attachment = try Attachment.initOwned(
        testing.allocator,
        "payload.txt",
        "hello",
        "text/plain",
        "event.attachment",
    );
    defer attachment.deinit(testing.allocator);

    scope.addAttachment(attachment);

    const snapshot = try scope.snapshotAttachments(testing.allocator);
    defer deinitAttachmentSlice(testing.allocator, snapshot);

    try testing.expectEqual(@as(usize, 1), snapshot.len);
    try testing.expectEqualStrings("payload.txt", snapshot[0].filename);
    try testing.expectEqualStrings("hello", snapshot[0].data);
    try testing.expectEqualStrings("text/plain", snapshot[0].content_type.?);
}

fn dropProcessor(_: *Event) bool {
    return false;
}

fn mutateProcessor(event: *Event) bool {
    event.transaction = "processed-transaction";
    return true;
}

var reentrant_scope_for_processor: ?*Scope = null;

fn reentrantScopeProcessor(_: *Event) bool {
    if (reentrant_scope_for_processor) |scope| {
        scope.setLevel(.warning);
    }
    return true;
}

test "Scope event processors can mutate and drop events" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    try scope.addEventProcessor(mutateProcessor);
    var event = Event.init();
    const applied = try scope.applyToEvent(testing.allocator, &event);
    defer cleanupAppliedToEvent(testing.allocator, &event, applied);
    try testing.expectEqualStrings("processed-transaction", event.transaction.?);

    scope.clearEventProcessors();
    try scope.addEventProcessor(dropProcessor);

    var drop_event = Event.init();
    try testing.expectError(error.EventDropped, scope.applyToEvent(testing.allocator, &drop_event));
}

test "Scope event processors run without holding the scope lock" {
    var scope = try Scope.init(testing.allocator, 10);
    defer scope.deinit();

    reentrant_scope_for_processor = &scope;
    defer reentrant_scope_for_processor = null;

    try scope.addEventProcessor(reentrantScopeProcessor);

    var event = Event.init();
    const applied = try scope.applyToEvent(testing.allocator, &event);
    defer cleanupAppliedToEvent(testing.allocator, &event, applied);

    try testing.expectEqual(Level.warning, scope.level.?);
}
