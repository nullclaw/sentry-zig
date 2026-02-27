# Sentry-Zig: User Guide

Practical documentation for integrating the SDK and using core features
in a production application.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Compatibility and Support Policy](#compatibility-and-support-policy)
3. [Build and Delivery Model](#build-and-delivery-model)
4. [Integration in build.zig](#integration-in-buildzig)
5. [CI/CD Reference](#cicd-reference)
6. [Auto Integrations](#auto-integrations)
7. [Client Lifecycle](#client-lifecycle)
8. [Event Capture and event_id](#event-capture-and-event_id)
9. [Working with Scope](#working-with-scope)
10. [Attachments](#attachments)
11. [Tracing and Transactions](#tracing-and-transactions)
12. [Release Health Sessions](#release-health-sessions)
13. [Monitor Check-Ins](#monitor-check-ins)
14. [Structured Logs](#structured-logs)
15. [Hooks and Processors](#hooks-and-processors)
16. [Rate Limits and Queue](#rate-limits-and-queue)
17. [Crash Handling (POSIX)](#crash-handling-posix)
18. [Performance Tuning](#performance-tuning)
19. [Security and Data Governance](#security-and-data-governance)
20. [Production Checklist](#production-checklist)
21. [Troubleshooting](#troubleshooting)
22. [Testing Helpers](#testing-helpers)
23. [Support Model](#support-model)

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

## Compatibility and Support Policy

- Zig version: `>= 0.15.2`.
- The SDK does not target older Zig versions.
- Versioning follows SemVer tags (`vMAJOR.MINOR.PATCH`).
- For deterministic production builds, pin exact release tags.

Version enforcement points:

- `build.zig.zon`: `.minimum_zig_version = "0.15.2"`
- `build.zig`: compile-time guard for `< 0.15.2`
- `src/sentry.zig`: module compile-time guard for `< 0.15.2`

## Build and Delivery Model

Sentry-Zig is distributed as source and integrated directly into your Zig build.

- No separate SDK binary publishing step is required.
- Your application pipeline should resolve the dependency, build your app,
  run tests, and publish your own deployable artifact.
- Use tagged source tarballs for reproducibility and controlled upgrades.

## Integration in build.zig

```sh
zig fetch --save git+https://github.com/nullclaw/sentry-zig.git
```

For reproducible production builds, pin to a release tag:

```sh
zig fetch --save https://github.com/nullclaw/sentry-zig/archive/refs/tags/v0.2.0.tar.gz
```

```zig
const sentry_dep = b.dependency("sentry-zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("sentry-zig", sentry_dep.module("sentry-zig"));
```

Current stable release: `v0.2.0` (SemVer tags).

## CI/CD Reference

Recommended checks:

- `zig fmt --check .`
- `zig build test`
- `zig build test-integration` (staging/integration environments)

Example GitHub Actions workflow:

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mlugg/setup-zig@v2
        with:
          version: 0.15.2
      - run: test "$(zig version)" = "0.15.2"
      - run: zig fmt --check .
      - run: zig build test
      - run: zig build test-integration
```

Release checklist:

1. Update version references in docs if needed.
2. Tag the repository (`vX.Y.Z`).
3. Validate integration tests against the tag.
4. Roll out in staged environments before production.

## Auto Integrations

### Global init guard

`initGlobal` creates a client, binds a Hub as current TLS Hub, and returns a guard.
When the guard is deinitialized, the previous Hub is restored.

```zig
var guard = try sentry.initGlobal(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
    .release = "my-app@1.0.0",
    .environment = "production",
    .install_signal_handlers = false,
});
defer guard.deinit();

_ = sentry.captureMessage("captured through global API", .info);
```

### std.log integration helper

Set a custom `std_options.logFn` in your app root and install integration config:

```zig
pub const std_options: std.Options = .{
    .logFn = sentry.integrations.log.logFn,
};
```

```zig
sentry.integrations.log.install(.{
    .min_level = .info,
    .include_scope_prefix = true,
    .forward_to_default_logger = true,
    .max_message_bytes = 2048,
});
```

You can also attach built-in setup callbacks directly via `Options.integrations`:

```zig
const client = try sentry.init(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
    .integrations = sentry.integrations.auto.defaults(),
});
defer client.deinit();
```

Or initialize via helper that prepends built-ins and creates client:

```zig
const client = try sentry.integrations.auto.initWithDefaults(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
});
defer client.deinit();
```

Global variant (binds current TLS hub):

```zig
var guard = try sentry.integrations.auto.initGlobalWithDefaults(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
});
defer guard.deinit();
```

Minimal runtime wiring helpers:

```zig
pub const std_options: std.Options = sentry.integrations.auto.stdOptions();
pub const panic = sentry.integrations.auto.panicHandler;

sentry.integrations.auto.installRuntime(.{
    .log = .{ .min_level = .info },
    .panic = .{ .exception_type = "AppPanic" },
});
```

One-call bootstrap variant (runtime config + built-in integration defaults):

```zig
const client = try sentry.integrations.auto.initWithDefaultsAndRuntime(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
}, .{
    .log = .{
        .min_level = .info,
        .forward_to_default_logger = false,
    },
    .panic = .{
        .exception_type = "AppPanic",
    },
});
defer client.deinit();
```

Global one-call variant:

```zig
var guard = try sentry.integrations.auto.initGlobalWithDefaultsAndRuntime(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
}, .{
    .log = .{ .min_level = .info },
    .panic = .{ .exception_type = "AppPanic" },
});
defer guard.deinit();
```

### panic integration helper

Forward panics to Sentry before Zig default panic handling:

```zig
pub const panic = std.debug.FullPanic(sentry.integrations.panic.captureAndForward);
```

Optional runtime configuration:

```zig
sentry.integrations.panic.install(.{
    .exception_type = "AppPanic",
    .flush_timeout_ms = 2000,
    .capture_backtrace = true,
    .max_backtrace_frames = 32,
});
```

### HTTP request integration helper

Use `integrations.http.RequestContext` to get middleware-style request
instrumentation with automatic per-request Hub isolation.

```zig
var req_ctx = try sentry.integrations.http.RequestContext.begin(allocator, client, .{
    .name = "GET /orders/:id",
    .method = "GET",
    .url = "https://api.example.com/orders/42",
    .query_string = "expand=items",
    .sentry_trace_header = incoming_sentry_trace,
    .baggage_header = incoming_baggage,
    .add_breadcrumb_on_finish = true,
    .breadcrumb_category = "http.server",
});
defer req_ctx.deinit();

req_ctx.setTag("route", "orders.show");
req_ctx.setStatusCode(200);
req_ctx.finish(null);
```

Error path:

```zig
_ = req_ctx.fail(error.DatabaseTimeout, 500);
```

Middleware-style handler execution helper:

```zig
const status = try sentry.integrations.http.runIncomingRequest(
    allocator,
    client,
    .{
        .name = "GET /orders/:id",
        .method = "GET",
        .url = "https://api.example.com/orders/42",
        .sentry_trace_header = incoming_sentry_trace,
        .baggage_header = incoming_baggage,
    },
    incomingHandler,
    handler_ctx,
    .{},
);
_ = status;
```

Current TLS Hub variant (no explicit `client` parameter):

```zig
const status = try sentry.integrations.auto.runIncomingRequestWithCurrentHub(
    allocator,
    .{
        .name = "GET /orders/:id",
        .method = "GET",
        .url = "https://api.example.com/orders/42",
    },
    incomingHandler,
    handler_ctx,
    .{},
);
_ = status;
```

Typed Current TLS Hub variant (compile-time validated handler signature):

```zig
const IncomingState = struct { handled: bool = false };
fn incomingTyped(ctx: *sentry.integrations.http.RequestContext, state: *IncomingState) !u16 {
    state.handled = true;
    return 204;
}

var state = IncomingState{};
const status = try sentry.integrations.auto.runIncomingRequestWithCurrentHubTyped(
    allocator,
    .{
        .name = "GET /orders/:id",
        .method = "GET",
        .url = "https://api.example.com/orders/42",
    },
    incomingTyped,
    &state,
    .{},
);
_ = status;
```

Header-driven variant:

```zig
const headers = [_]sentry.PropagationHeader{
    .{ .name = "sentry-trace", .value = incoming_sentry_trace },
    .{ .name = "baggage", .value = incoming_baggage },
};
const status = try sentry.integrations.http.runIncomingRequestFromHeaders(
    allocator,
    client,
    .{
        .name = "GET /orders/:id",
        .method = "GET",
        .url = "https://api.example.com/orders/42",
    },
    &headers,
    incomingHandler,
    handler_ctx,
    .{},
);
_ = status;
// traceparent is also supported when sentry-trace header is absent.
```

Current TLS Hub header-driven variant:

```zig
const status = try sentry.integrations.auto.runIncomingRequestFromHeadersWithCurrentHub(
    allocator,
    .{
        .name = "GET /orders/:id",
        .method = "GET",
        .url = "https://api.example.com/orders/42",
    },
    &headers,
    incomingHandler,
    handler_ctx,
    .{},
);
_ = status;
```

### Outgoing HTTP request integration helper

Use `integrations.http.OutgoingRequestContext` inside an active transaction/span
to create client spans and propagate trace headers downstream.

```zig
var out = try sentry.integrations.http.OutgoingRequestContext.begin(.{
    .method = "POST",
    .url = "https://payments.example.com/charge",
    .description = "POST payments charge",
    .add_breadcrumb_on_finish = true,
    .breadcrumb_category = "http.client",
});
defer out.deinit();

var headers = try out.propagationHeadersAlloc(allocator);
defer headers.deinit(allocator);
// Add headers.sentry_trace and headers.baggage to outgoing request headers.

var header_list = try out.propagationHeaderListAlloc(allocator);
defer header_list.deinit(allocator);
// header_list.slice() returns []sentry.PropagationHeader.

var header_list_w3c = try out.propagationHeaderListWithTraceParentAlloc(allocator);
defer header_list_w3c.deinit(allocator);
// includes sentry-trace + baggage + traceparent.

out.setStatusCode(200);
out.finish(null);
```

Both incoming and outgoing contexts add HTTP breadcrumbs on finish by default.
Disable with `.add_breadcrumb_on_finish = false` when you need lower breadcrumb volume.

Error path:

```zig
_ = out.fail(error.UpstreamTimeout, null); // defaults status_code to 500
```

Middleware-style outgoing helper:

```zig
const upstream_status = try sentry.integrations.http.runOutgoingRequest(
    .{
        .method = "POST",
        .url = "https://payments.example.com/charge",
    },
    outgoingHandler,
    handler_ctx,
    .{},
);
_ = upstream_status;
```

Typed outgoing helper variant:

```zig
const OutState = struct { propagated: bool = false };
fn outgoingTyped(ctx: *sentry.integrations.http.OutgoingRequestContext, state: *OutState) !u16 {
    var h = try ctx.propagationHeadersAlloc(allocator);
    defer h.deinit(allocator);
    state.propagated = true;
    return 200;
}

var out_state = OutState{};
const upstream_status = try sentry.integrations.auto.runOutgoingRequestWithCurrentHubTyped(
    .{
        .method = "POST",
        .url = "https://payments.example.com/charge",
    },
    outgoingTyped,
    &out_state,
    .{},
);
_ = upstream_status;
```

### Error-return integration helper

Capture returned errors from error-union functions without changing control flow:

```zig
const result = try sentry.integrations.errors.runAndCapture(doWork, .{input});
```

Direct wrapper variants:

```zig
try sentry.integrations.errors.captureResult(doWork(input));
try sentry.integrations.errors.captureResultAs(doWork(input), "DomainFailure");
```

### Worker/task runtime integration helper

Use `integrations.runtime.DetachedHub` to clone the current top scope and run
task code under the cloned Hub (with TLS current-Hub restore on exit).

```zig
var detached = try sentry.integrations.runtime.DetachedHub.fromCurrent(allocator, client);
defer detached.deinit();

const result = try detached.run(workerStep, .{input});
```

For thread-based workers, use spawn helpers:

```zig
const worker = try sentry.integrations.runtime.spawnWithCurrentHub(
    allocator,
    .{},
    workerStep,
    .{input},
);
worker.join();
```

If you need to spawn from an explicit source Hub (without a TLS current Hub):

```zig
const worker = try sentry.integrations.runtime.spawnFromHub(
    allocator,
    source_hub,
    .{},
    workerStep,
    .{input},
);
worker.join();
```

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
client.captureError(error.PaymentGatewayTimeout);
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
- `sentry.Hub.run(&hub, callback)` for temporary TLS hub override

After `setCurrentHub`, you can use global helper calls:
- `sentry.captureMessage(...)`
- `sentry.captureException(...)`
- `sentry.captureError(...)`
- `sentry.captureCheckIn(...)`
- `sentry.startSession()` / `sentry.endSession(...)`
- `sentry.lastEventId()`
- `sentry.flush(...)` / `sentry.close(...)`
- `sentry.addBreadcrumb(...)` / `sentry.clearBreadcrumbs()`
- `sentry.pushScope()` / `sentry.popScope()`
- `sentry.withScope(...)`
- `sentry.configureScope(...)`
- `sentry.withIntegration(...)`

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

// Optional explicit trace/span ids (advanced distributed tracing control)
var fixed_ids_txn = client.startTransaction(.{
    .name = "POST /checkout-fixed",
    .op = "http.server",
    .trace_id = "0123456789abcdef0123456789abcdef".*,
    .span_id = "89abcdef01234567".*,
});
defer fixed_ids_txn.deinit();

// Optional explicit start timestamp (seconds, unix epoch)
var timed_txn = client.startTransactionWithTimestamp(.{
    .name = "POST /checkout-backdated",
    .op = "http.server",
}, 1704067200.125);
defer timed_txn.deinit();

const fixed_span = try timed_txn.startChildWithDetails(
    .{ .op = "db.query", .description = "SELECT 1" },
    "0123456789abcdef".*,
    1704067200.250,
);
fixed_span.finishWithTimestamp(1704067200.500);
try timed_txn.setTag("flow", "checkout");
try timed_txn.setExtra("attempt", .{ .integer = 2 });
try timed_txn.setData("cache_hit", .{ .bool = true });
try timed_txn.setOrigin("auto.http");
try fixed_span.setTag("db.system", "postgresql");
try fixed_span.setData("rows", .{ .integer = 1 });
try timed_txn.setRequest(.{
    .method = "POST",
    .url = "https://api.example.com/orders",
});
try fixed_span.setRequest(.{
    .method = "POST",
    .url = "https://api.example.com/orders",
});
const trace_ctx = timed_txn.getTraceContext();
const span_trace_header = try fixed_span.sentryTraceHeaderAlloc(allocator);
defer allocator.free(span_trace_header);

const span = try txn.startChild(.{
    .op = "db.query",
    .description = "INSERT INTO orders",
});
const nested = try span.startChild(.{
    .op = "db.lock",
    .description = "Acquire order lock",
});
nested.finish();
span.finish();
try txn.setTag("flow", "checkout");
try txn.setExtra("attempt", .{ .integer = 2 });
try txn.setData("cache_hit", .{ .bool = true });
try txn.setOrigin("auto.http");

client.finishTransaction(&txn);
```

The transaction span list is capped at `1000` child spans (`sentry.MAX_SPANS`).

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
    if (ctx.custom_sampling_context) |custom| {
        if (custom.* == .object) {
            if (custom.object.get("rate")) |rate| {
                switch (rate) {
                    .float => return rate.float,
                    .integer => return @as(f64, @floatFromInt(rate.integer)),
                    else => {},
                }
            }
        }
    }
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
Sampler context includes `transaction_name`, `transaction_op`, `trace_id`, `span_id`,
`parent_sampled`, and per-transaction custom input from
`TransactionOpts.custom_sampling_context`.
When `traces_sampler` is not set, `TransactionOpts.sampled_override`
forces per-transaction sampling (`true` => rate `1.0`, `false` => rate `0.0`)
and takes precedence over `TransactionOpts.sample_rate`.

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

const headers = [_]sentry.PropagationHeader{
    .{ .name = "sentry-trace", .value = maybe_sentry_trace_header.? },
    .{ .name = "baggage", .value = maybe_baggage_header.? },
};
var txn3 = client.startTransactionFromHeaders(
    .{ .name = "GET /orders", .op = "http.server" },
    &headers,
);
defer txn3.deinit();

var txn4 = client.startTransactionFromSpan(
    .{ .name = "GET /orders-fanout", .op = "worker" },
    .{ .transaction = &txn2 },
);
defer txn4.deinit();
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
const parsed_trace = sentry.parseHeaders(&headers);
```

### OTel/W3C traceparent helpers

Use `integrations.otel` when your edge/middleware primarily exposes W3C `traceparent`.

```zig
const traceparent = "00-0123456789abcdef0123456789abcdef-89abcdef01234567-01";

var txn = try sentry.integrations.otel.startTransactionFromTraceParent(
    client,
    .{ .name = "GET /inventory", .op = "http.server" },
    traceparent,
);
defer txn.deinit();

const outgoing_traceparent = try sentry.integrations.otel.traceParentFromTransactionAlloc(allocator, &txn);
defer allocator.free(outgoing_traceparent);
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

### attach_debug_images

```zig
const client = try sentry.init(allocator, .{
    .dsn = "...",
    .attach_debug_images = true, // default
});
```

With `attach_debug_images=true`, the SDK injects default `debug_meta.images`
for events that do not already provide debug image metadata.

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
In `.application` mode, individual `session` updates include `seq` (monotonic sequence).
In `.request` mode, updates are aggregated into `sessions` envelopes.

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
- `.request` mode does not send duration and reports aggregated counts.
- Request-mode aggregates are auto-flushed every `session_aggregate_flush_interval_ms` (default `60000`).
- Set `session_aggregate_flush_interval_ms = 0` to disable timer-based flushing and rely on explicit
  `flush(...)` / `close(...)`.

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
When options are configured, default log attributes are added if missing:
`sentry.environment`, `sentry.release`, and `server.address`.

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

### Built-in transport backends

For custom delivery pipelines, use:
- `sentry.transport_backends.file.Backend` to persist envelopes as files.
- `sentry.transport_backends.fanout.Backend` to send each envelope to multiple targets.

```zig
var file_backend = try sentry.transport_backends.file.Backend.init(allocator, .{
    .directory = "/var/tmp/sentry-outbox",
    .failure_backoff_seconds = 1,
});
defer file_backend.deinit();
const file_transport = file_backend.transportConfig();

var fanout_backend = try sentry.transport_backends.fanout.Backend.init(allocator, &.{
    .{ .send_fn = file_transport.send_fn, .ctx = file_transport.ctx },
    // Add more targets here (for example, another file sink or custom sender).
});
defer fanout_backend.deinit();

const client = try sentry.init(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
    .transport = fanout_backend.transportConfig(),
});
defer client.deinit();

const backend_stats = file_backend.stats();
_ = backend_stats;
```

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

## Performance Tuning

Primary tuning knobs:

- `sample_rate`: controls event volume (`0.0..1.0`).
- `traces_sample_rate` / `traces_sampler`: controls tracing volume.
- `max_request_body_size`: drops oversized envelopes early.
- `max_breadcrumbs`: bounds per-event breadcrumb memory.
- `session_aggregate_flush_interval_ms`: controls request-mode session aggregate flush cadence.

Operational guidance:

- Use lower sample rates in high-throughput services.
- Prefer dynamic sampling (`traces_sampler`) for critical paths.
- Monitor queue pressure and raise shutdown timeout if needed.
- Keep attachment payload sizes bounded.

## Security and Data Governance

- Use `before_send`, `before_send_transaction`, and `before_send_log` to redact sensitive fields.
- Use `before_breadcrumb` to drop noisy or sensitive breadcrumbs.
- Set `send_default_pii` intentionally according to your privacy policy.
- Keep `accept_invalid_certs=false` outside local development.
- Review `Scope` data writes to avoid accidental PII leakage (`user`, `extras`, `contexts`).

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

### Events are dropped under load

- Confirm whether sampling is intentionally low (`sample_rate`, tracing sampling).
- Check queue saturation patterns in your service lifecycle.
- Reduce envelope size (`max_request_body_size`, attachment payloads).
- Verify Sentry rate-limit responses (`Retry-After`, `X-Sentry-Rate-Limits`).

## Testing Helpers

Use `sentry.testkit` for in-process capture tests without external relay setup.

```zig
const std = @import("std");
const sentry = @import("sentry-zig");

fn capture(client: *sentry.Client, _: ?*anyopaque) !void {
    _ = client.captureMessageId("sdk-test-message", .warning);
}

var events = try sentry.testkit.withCapturedEvents(
    std.testing.allocator,
    capture,
    null,
);
defer events.deinit();

try std.testing.expectEqual(@as(usize, 1), events.items.len);
```

Available helpers:

- `sentry.testkit.TestTransport`
- `sentry.testkit.withCapturedEnvelopes(...)`
- `sentry.testkit.withCapturedEnvelopesOptions(...)`
- `sentry.testkit.withCapturedEvents(...)`
- `sentry.testkit.withCapturedEventsOptions(...)`

## Support Model

- Stable surface: core capture APIs, tracing/session/check-in flows, envelope transport.
- Compatibility baseline: Zig `0.15.2+`.
- Change tracking: follow repository tags and commit history.

To track changes, use commit history and integration tests
in `tests/integration_test.zig`.
