# Sentry-Zig: User Guide

Practical documentation for integrating the SDK and using core features
in a production application.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Integration in build.zig](#integration-in-buildzig)
3. [Client Lifecycle](#client-lifecycle)
4. [Event Capture and event_id](#event-capture-and-event_id)
5. [Working with Scope](#working-with-scope)
6. [Attachments](#attachments)
7. [Tracing and Transactions](#tracing-and-transactions)
8. [Release Health Sessions](#release-health-sessions)
9. [Monitor Check-Ins](#monitor-check-ins)
10. [Structured Logs](#structured-logs)
11. [Hooks and Processors](#hooks-and-processors)
12. [Rate Limits and Queue](#rate-limits-and-queue)
13. [Crash Handling (POSIX)](#crash-handling-posix)
14. [Production Checklist](#production-checklist)
15. [Troubleshooting](#troubleshooting)
16. [SDK Status](#sdk-status)

## Quick Start

```zig
const std = @import("std");
const sentry = @import("sentry-zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const client = try sentry.init(allocator, .{
        .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
        .release = "my-app@1.0.0",
        .environment = "production",
        .traces_sample_rate = 1.0,
    });
    defer client.deinit();

    client.captureMessage("service started", .info);
    _ = client.flush(5000);
}
```

## Integration in build.zig

```sh
zig fetch --save git+https://github.com/nullclaw/sentry-zig.git
```

For reproducible production builds, pin to a release tag:

```sh
zig fetch --save https://github.com/nullclaw/sentry-zig/archive/refs/tags/v0.1.0.tar.gz
```

```zig
const sentry_dep = b.dependency("sentry-zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("sentry-zig", sentry_dep.module("sentry-zig"));
```

Current stable release: `v0.1.0` (SemVer tags).

## Client Lifecycle

`Client` manages:
- HTTP transport,
- background worker,
- rate-limit state,
- current `Scope`,
- release health session.

Basic rules:
- Initialize `Client` once per process.
- Always call `defer client.deinit();`.
- Before process shutdown, call `flush(...)` when needed.

Key methods:
- `flush(timeout_ms)` - waits until the queue is drained.
- `close(timeout_ms_or_null)` - ends the session, drains the queue, and stops the worker.
- `deinit()` - standard safe shutdown path.

If `Options.integrations` is provided, each integration setup callback runs during client initialization.

```zig
fn setupIntegration(client: *sentry.Client, _: ?*anyopaque) void {
    client.setTag("integration", "checkout");
}
```

## Event Capture and event_id

### Message/exception

```zig
client.captureMessage("checkout failed", .err);
client.captureException("PaymentError", "gateway timeout");
```

### Get `event_id`

```zig
if (client.captureMessageId("retrying payment", .warning)) |event_id| {
    std.log.warn("event_id={s}", .{event_id});
}
```

### Last accepted ID

```zig
if (client.lastEventId()) |last_id| {
    std.log.info("last event={s}", .{last_id});
}
```

If an event is filtered out (`before_send`, processor, sampling), `*Id`
methods return `null`.

## Working with Scope

`Scope` is automatically applied to new events.

```zig
client.setUser(.{
    .id = "user-42",
    .email = "user@example.com",
});
client.setTag("feature", "checkout");
client.setExtra("order_id", .{ .integer = 12345 });
client.setContext("region", .{ .string = "eu-west-1" });

client.addBreadcrumb(.{
    .category = "http",
    .message = "POST /api/checkout",
    .level = .info,
});
```

Cleanup:

```zig
client.removeUser();
client.removeTag("feature");
client.removeExtra("order_id");
client.removeContext("region");
client.clearBreadcrumbs();
```

Additional methods:
- `setLevel` sets the default level.
- `setTransaction` and `setFingerprint` affect event grouping.

For strict Zig-style error handling, fallible variants are available:
- `trySetUser`, `trySetTag`, `trySetExtra`, `trySetContext`
- `trySetTransaction`, `trySetFingerprint`
- `tryAddBreadcrumb`, `tryAddAttachment`, `tryAddEventProcessor`

### Hub and scope stack

Use `Hub` for isolated scope blocks:

```zig
var hub = try sentry.Hub.init(allocator, client);
defer hub.deinit();

try hub.pushScope();
defer _ = hub.popScope();

hub.setTag("stage", "checkout");
hub.captureMessage("scoped event", .info);
```

TLS helper methods:
- `sentry.setCurrentHub(&hub)`
- `sentry.currentHub()`
- `sentry.clearCurrentHub()`

After `setCurrentHub`, you can use global helper calls:
- `sentry.captureMessage(...)`
- `sentry.captureException(...)`
- `sentry.captureCheckIn(...)`
- `sentry.startSession()` / `sentry.endSession(...)`
- `sentry.lastEventId()`
- `sentry.flush(...)` / `sentry.close(...)`
- `sentry.addBreadcrumb(...)` / `sentry.clearBreadcrumbs()`
- `sentry.pushScope()` / `sentry.popScope()`
- `sentry.withScope(...)`
- `sentry.configureScope(...)`

## Attachments

### From memory

```zig
var attachment = try sentry.Attachment.initOwned(
    allocator,
    "debug.txt",
    "diagnostic payload",
    "text/plain",
    "event.attachment",
);
defer attachment.deinit(allocator);

client.addAttachment(attachment);
```

### From file

```zig
var file_attachment = try sentry.Attachment.fromPath(
    allocator,
    "/var/log/my-app.log",
    null,
    "text/plain",
    "event.attachment",
);
defer file_attachment.deinit(allocator);

client.addAttachment(file_attachment);
```

After `addAttachment`, the local object can be safely `deinit`-ed: the SDK keeps
an internal copy.

## Tracing and Transactions

```zig
var txn = client.startTransaction(.{
    .name = "POST /checkout",
    .op = "http.server",
});
defer txn.deinit();

const span = try txn.startChild(.{
    .op = "db.query",
    .description = "INSERT INTO orders",
});
span.finish();

client.finishTransaction(&txn);
```

### Sampling

Globally:

```zig
const client = try sentry.init(allocator, .{
    .dsn = "...",
    .traces_sample_rate = 0.2,
});
```

Dynamically:

```zig
fn traceSampler(ctx: sentry.TracesSamplingContext) f64 {
    if (std.mem.eql(u8, ctx.transaction_name, "POST /checkout")) return 1.0;
    return 0.1;
}

const client = try sentry.init(allocator, .{
    .dsn = "...",
    .traces_sample_rate = 0.0,
    .traces_sampler = traceSampler,
});
```

`traces_sampler` has priority over `traces_sample_rate`.

For regular event messages, the SDK automatically adds default contexts
(`contexts.trace`, `contexts.runtime`, `contexts.os`) when trace context
is missing in the input event.

Set `default_integrations=false` to disable automatic `runtime`/`os` context enrichment.

Set `in_app_include` / `in_app_exclude` to classify exception stack frames.
Matching `in_app_include` patterns set `frame.in_app=true`, matching
`in_app_exclude` patterns set `frame.in_app=false`.
For transaction envelopes, the SDK adds a dynamic trace header
(`trace_id/public_key/sample_rate/sampled`).

### Trace Propagation

Continue an upstream trace from an incoming `sentry-trace` header:

```zig
var txn = try client.startTransactionFromSentryTrace(
    .{
        .name = "GET /orders",
        .op = "http.server",
    },
    "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
);
defer txn.deinit();
```

Or use both propagation headers in one call:

```zig
var txn2 = try client.startTransactionFromPropagationHeaders(
    .{ .name = "GET /orders", .op = "http.server" },
    maybe_sentry_trace_header,
    maybe_baggage_header,
);
defer txn2.deinit();
```

If `baggage` contains `sentry-sample_rate` and explicit `sample_rate` is not set in
transaction options, the SDK uses that propagated sample rate.

Generate downstream propagation headers from a transaction:

```zig
const sentry_trace = try client.sentryTraceHeader(&txn, allocator);
defer allocator.free(sentry_trace);

const baggage = try client.baggageHeader(&txn, allocator);
defer allocator.free(baggage);
```

When a transaction was started from incoming `baggage`, third-party baggage members are preserved
in downstream headers while `sentry-*` members are refreshed from the current transaction context.

You can parse incoming baggage directly:

```zig
const parsed_baggage = sentry.parseBaggage(incoming_baggage_header); // borrowed fields
var parsed_baggage_owned = try sentry.parseBaggageAlloc(allocator, incoming_baggage_header); // decoded owned fields
defer parsed_baggage_owned.deinit();
```

### attach_stacktrace

```zig
const client = try sentry.init(allocator, .{
    .dsn = "...",
    .attach_stacktrace = true,
});
```

With `attach_stacktrace=true`, the SDK adds thread stacktrace payload for events
where `threads` are not already populated.

## Release Health Sessions

### Manual mode

```zig
client.startSession();
// business logic...
client.endSession(.exited);
```

If `Scope.user` is set before `startSession`, session `did` is derived from user context
in priority order: `id`, then `email`, then `username`.
If user context is set after `startSession`, `did` is attached on the next session update.

### Auto mode

```zig
const client = try sentry.init(allocator, .{
    .dsn = "...",
    .release = "my-app@1.0.0",
    .auto_session_tracking = true,
});
```

Important:
- Without `release`, sessions do not start.
- `.application` mode tracks duration.
- `.request` mode does not send duration.

## Monitor Check-Ins

```zig
var check_in = sentry.MonitorCheckIn.init("nightly-job", .in_progress);
client.captureCheckIn(&check_in);

check_in.status = .ok;
check_in.duration = 12.3;
client.captureCheckIn(&check_in);
```

If `check_in.environment == null`, the SDK uses `Options.environment`.

## Structured Logs

```zig
client.captureLogMessage("checkout started", .info);

var log_entry = sentry.LogEntry.init("payment provider timeout", .err);
client.captureLog(&log_entry);
```

For advanced fields, set `LogEntry.attributes` and `LogEntry.trace_id`
before sending.

Use `before_send_log` to drop or mutate structured logs before queueing.

## Hooks and Processors

### `before_send`

```zig
fn beforeSend(event: *sentry.Event) ?*sentry.Event {
    if (event.level == .debug) return null;
    return event; // return the same pointer
}
```

### `before_send_transaction`

```zig
fn beforeSendTransaction(txn: *sentry.Transaction) ?*sentry.Transaction {
    if (std.mem.eql(u8, txn.name, "GET /health")) return null;
    txn.op = "http.server.processed";
    return txn; // return the same pointer
}
```

### `before_breadcrumb`

```zig
fn beforeBreadcrumb(crumb: sentry.Breadcrumb) ?sentry.Breadcrumb {
    if (crumb.category != null and std.mem.eql(u8, crumb.category.?, "healthcheck")) return null;
    return crumb;
}
```

### Scope event processor

```zig
fn processor(event: *sentry.Event) bool {
    if (event.message != null and event.message.?.formatted != null and
        std.mem.indexOf(u8, event.message.?.formatted.?, "ignore-me") != null)
    {
        return false;
    }
    return true;
}

client.addEventProcessor(processor);
```

## Rate Limits and Queue

The worker handles:
- `Retry-After`,
- `X-Sentry-Rate-Limits`.

Default behavior:
- when the queue overflows, the oldest items are dropped;
- envelopes with `event` (including those with attachments) follow the `error` category rate limit;
- `session`, `transaction`, and `check_in` categories are limited independently.

## Crash Handling (POSIX)

By default, handlers are installed for:
- `SIGSEGV`
- `SIGABRT`
- `SIGBUS`
- `SIGILL`
- `SIGFPE`

Configuration:
- `install_signal_handlers = true|false`
- `cache_dir` for crash marker files.
- when `server_name` is unset and `default_integrations=true`, the SDK attempts to use local hostname.
- `http_proxy` / `https_proxy` for explicit proxy URLs.
- `accept_invalid_certs` to disable TLS certificate verification for direct HTTPS transport in local/dev setups.
- `transport` for custom envelope sender callback.
- `max_request_body_size` to drop oversized envelopes.

`accept_invalid_certs=true` is not supported together with explicit proxy transport settings.

## Production Checklist

- Set `release`, `environment`, and `server_name` explicitly.
- Set `dist` when multiple build distributions share the same release.
- Configure sampling: `sample_rate`, `traces_sample_rate`/`traces_sampler`.
- Add `before_send` to edit/filter payloads.
- Add breadcrumbs at critical CJM stages.
- Verify graceful shutdown (`flush`/`deinit`).
- Verify event delivery on staging.

## Troubleshooting

### No events in Sentry

- Verify DSN correctness.
- Verify the process does not exit before `flush/deinit`.
- Verify events are not dropped by `before_send` or an event processor.
- Verify `sample_rate`/`traces_sample_rate`.

### Sessions are not sent

- Ensure `release` is set.
- Ensure `startSession` is actually called (or `auto_session_tracking=true`).

### Check-ins without environment

- Set `Options.environment`, or fill `check_in.environment` manually.

## SDK Status

Current focus:
- events/scope/envelope pipeline,
- transactions/spans/sampling,
- release health sessions,
- monitor check-ins,
- worker + transport rate limits.

Roadmap:
- expanded integration ecosystem.

To track changes, use commit history and integration tests
in `tests/integration_test.zig`.
