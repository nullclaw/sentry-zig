# Sentry-Zig

Native Sentry SDK in Zig (`0.15.2+`) for capturing errors, transactions, sessions,
and monitor check-ins via the Sentry Envelope protocol.

This repository focuses on a clean public API, production-safe defaults, and
predictable shutdown behavior.

Detailed guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)

## Documentation Map

- [README.md](README.md): install, architecture map, production bootstrap.
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md): full usage reference with advanced flows.

## Quickstart

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

    client.captureMessage("Hello from Zig", .info);
    _ = client.flush(5000);
}
```

## Requirements

- Zig `>= 0.15.2`

Version enforcement is explicit in three places:

- `build.zig.zon`: `.minimum_zig_version = "0.15.2"`
- `build.zig`: compile-time guard (`@compileError`) for `< 0.15.2`
- `src/sentry.zig`: module-level compile-time guard (`@compileError`) for `< 0.15.2`

## Installation

Add dependency:

```sh
zig fetch --save git+https://github.com/nullclaw/sentry-zig.git
```

For reproducible production builds, pin to a release tag:

```sh
zig fetch --save https://github.com/nullclaw/sentry-zig/archive/refs/tags/v0.2.0.tar.gz
```

Import module in `build.zig`:

```zig
const sentry_dep = b.dependency("sentry-zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("sentry-zig", sentry_dep.module("sentry-zig"));
```

## Build and Delivery Model

Sentry-Zig is consumed as a Zig dependency source package.

- You do not need to publish or preload SDK-specific binary artifacts.
- Your application CI/CD resolves the dependency (`zig fetch`), compiles your app,
  and runs tests.
- Release tags are used for deterministic builds.

## CI/CD Integration

Minimal CI checks:

- `zig build test` on every pull request.
- `zig build test-integration` in integration/staging pipelines.
- `zig fmt --check .` for formatting gate.

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
      - run: zig build test
      - run: zig build test-integration
```

## Versioning and Releases

- Current stable release: `v0.2.0`
- Versioning policy: Semantic Versioning (SemVer)
- Zig compatibility target: `>= 0.15.2` (older Zig versions are out of scope)
- Use release tags for pinned dependencies and deterministic builds.

## Core Concepts

- `Client`: owns transport, worker queue, and runtime configuration.
- `InitGuard`: helper returned by `initGlobal` that binds/restores TLS Hub automatically.
- `Scope`: mutable event context (user, tags, extras, breadcrumbs, attachments).
- `Hub`: scope stack + thread-local current hub API for scoped captures.
- Global helpers via current Hub: `captureMessage`, `captureException`, `captureError`, `captureCheckIn`, `startSession`, `endSession`, `flush`, `close`, `addBreadcrumb`, `pushScope`, `configureScope`, `withIntegration`.
- `Event`: error/message payload (`captureMessage`, `captureException`, `captureEvent`).
- `Transaction` + `Span`: tracing payloads (`startTransaction`, `finishTransaction`).
- `Session`: release health lifecycle (`startSession`, `endSession`).
- `MonitorCheckIn`: cron monitor status payload (`captureCheckIn`).
- `LogEntry`: structured log payload (`captureLogMessage`, `captureLog`).

## Zig-First API

- Most mutating API calls have both forms:
  - ergonomic (`setTag`, `addBreadcrumb`, `addAttachment`) that never fail outwardly.
  - explicit fallible (`trySetTag`, `tryAddBreadcrumb`, `tryAddAttachment`) for strict error handling.
- Use `try*` methods when you want full control over `OutOfMemory` and other allocation failures.

## Feature Status

| Capability | Status | Notes |
|---|---|---|
| Event capture | Implemented | Message/exception/custom event capture, before-send filtering |
| Scope enrichment | Implemented | User/tags/extras/contexts/breadcrumbs/fingerprint/transaction |
| Attachments | Implemented | In-memory and file-backed attachments |
| Transactions & spans | Implemented | Sampling + trace context serialization |
| Event context bootstrap | Implemented | Captured events receive missing `contexts.trace` + runtime/os entries while preserving custom contexts |
| Transaction DSC envelope header | Implemented | Envelope header includes `trace_id/public_key/sample_rate/sampled` |
| Trace propagation headers | Implemented | `sentry-trace`/`baggage` generation + continuation from trace value, header pairs, or explicit propagation headers |
| Traces sampler callback | Implemented | `traces_sampler` has priority over `traces_sample_rate` |
| Sessions (application/request mode) | Implemented | Request mode disables duration tracking and emits aggregated `sessions` envelopes |
| Session distinct id (`did`) | Implemented | Derived from `Scope.user` (`id`/`email`/`username`) when available |
| Monitor check-ins | Implemented | `check_in` envelopes with env inheritance |
| Worker + queue draining | Implemented | Bounded queue + `flush`/`close` semantics |
| Transport rate limits | Implemented | `Retry-After` + `X-Sentry-Rate-Limits` parsing |
| Transport customization | Implemented | Custom transport callback + explicit HTTP/HTTPS proxy options + built-in `transport_backends.file` / `transport_backends.fanout` |
| Signal crash marker flow | Implemented | POSIX marker write/read cycle |
| Hub/TLS scope stack | Implemented | Push/pop scopes + TLS current hub helpers |
| Structured logs pipeline | Implemented | `log` envelope items + `captureLogMessage` API |
| Auto integration helpers | Implemented | Global init guard + std.log/panic/http inbound+outbound/error/runtime helper integrations + OTel traceparent helper API |
| Extended integrations | Roadmap | Additional framework/runtime integrations will be added incrementally |

## Common Usage

```zig
// Capture message
client.captureMessage("checkout failed", .err);

// Capture exception
client.captureException("PaymentError", "gateway timeout");

// Capture Zig error value
client.captureError(error.PaymentGatewayTimeout);

// Get event id when accepted
if (client.captureMessageId("degraded mode", .warning)) |event_id| {
    std.log.warn("event_id={s}", .{event_id});
}

// Scope data
client.setUser(.{ .id = "user-42", .email = "user@example.com" });
client.setTag("feature", "checkout");
client.addBreadcrumb(.{ .category = "http", .message = "POST /checkout", .level = .info });

// Structured log
client.captureLogMessage("checkout started", .info);
```

```zig
// Continue trace from incoming sentry-trace header
var txn = try client.startTransactionFromSentryTrace(
    .{ .name = "GET /orders", .op = "http.server" },
    "0123456789abcdef0123456789abcdef-89abcdef01234567-1",
);
defer txn.deinit();

// Propagate trace downstream
const sentry_trace = try client.sentryTraceHeader(&txn, allocator);
defer allocator.free(sentry_trace);
const baggage = try client.baggageHeader(&txn, allocator);
defer allocator.free(baggage);

// Variant that accepts both incoming headers
var txn2 = try client.startTransactionFromPropagationHeaders(
    .{ .name = "GET /orders", .op = "http.server" },
    incoming_sentry_trace,
    incoming_baggage,
);
defer txn2.deinit();
const headers = [_]sentry.PropagationHeader{
    .{ .name = "sentry-trace", .value = incoming_sentry_trace.? },
    .{ .name = "baggage", .value = incoming_baggage.? },
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
// Optional explicit start timestamp (seconds, unix epoch)
var timed_txn = client.startTransactionWithTimestamp(
    .{ .name = "GET /orders-backdated", .op = "http.server" },
    1704067200.125,
);
defer timed_txn.deinit();
var fixed_ids_txn = client.startTransaction(.{
    .name = "GET /orders-fixed",
    .op = "http.server",
    .trace_id = "0123456789abcdef0123456789abcdef".*,
    .span_id = "89abcdef01234567".*,
});
defer fixed_ids_txn.deinit();
// Optional explicit child-span details
const fixed_span = try timed_txn.startChildWithDetails(
    .{ .op = "db.query", .description = "SELECT 1" },
    "0123456789abcdef".*,
    1704067200.250,
);
fixed_span.finishWithTimestamp(1704067200.500);
const nested_span = try fixed_span.startChild(.{
    .op = "db.lock",
    .description = "Acquire order lock",
});
nested_span.finish();
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
// `sentry-sample_rate` from baggage is honored when transaction opts use default sample_rate.
// Third-party baggage members are preserved when generating downstream baggage headers.

// Parse incoming baggage directly (borrowed or decoded/owned variants)
const parsed_baggage = sentry.parseBaggage(incoming_baggage);
var parsed_baggage_owned = try sentry.parseBaggageAlloc(allocator, incoming_baggage);
defer parsed_baggage_owned.deinit();
const parsed_trace = sentry.parseHeaders(&headers);
```

```zig
// Hub scope stack
var hub = try sentry.Hub.init(allocator, client);
defer hub.deinit();

try hub.pushScope();
defer _ = hub.popScope();

hub.setTag("flow", "checkout");
hub.captureMessage("scoped event", .info);

// Optional global API through TLS current hub
_ = sentry.setCurrentHub(&hub);
defer _ = sentry.clearCurrentHub();
_ = sentry.captureMessage("global scoped capture", .warning);
```

```zig
// Global bootstrap that binds a Hub automatically (guard restores previous hub)
var guard = try sentry.initGlobal(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
    .install_signal_handlers = false,
});
defer guard.deinit();

// std.log integration helper (set this as std_options.logFn in your app root)
sentry.integrations.log.install(.{
    .min_level = .info,
    .forward_to_default_logger = true,
});
```

```zig
// One-line built-in setup preset for Options.integrations
const client = try sentry.init(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
    .integrations = sentry.integrations.auto.defaults(),
});
defer client.deinit();
```

```zig
// Full bootstrap helper that prepends built-ins and initializes client directly
const client = try sentry.integrations.auto.initWithDefaults(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
});
defer client.deinit();
```

```zig
// Minimal runtime wiring helpers
pub const std_options: std.Options = sentry.integrations.auto.stdOptions();
pub const panic = sentry.integrations.auto.panicHandler;

sentry.integrations.auto.installRuntime(.{
    .log = .{ .min_level = .info },
    .panic = .{ .exception_type = "AppPanic" },
});
```

```zig
// One-call bootstrap: apply runtime config + prepend built-ins + initialize client
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

```zig
// Global one-call variant: runtime config + default integrations + current TLS hub binding
var guard = try sentry.integrations.auto.initGlobalWithDefaultsAndRuntime(allocator, .{
    .dsn = "https://PUBLIC_KEY@o0.ingest.sentry.io/PROJECT_ID",
}, .{
    .log = .{ .min_level = .info },
    .panic = .{ .exception_type = "AppPanic" },
});
defer guard.deinit();
```

```zig
// HTTP request helper: starts/continues trace, binds per-request hub, maps status
var req_ctx = try sentry.integrations.http.RequestContext.begin(allocator, client, .{
    .name = "GET /orders/:id",
    .method = "GET",
    .url = "https://api.example.com/orders/42",
    .sentry_trace_header = incoming_sentry_trace,
    .baggage_header = incoming_baggage,
    .add_breadcrumb_on_finish = true,
});
defer req_ctx.deinit();

req_ctx.setTag("route", "orders.show");
req_ctx.setStatusCode(200);
req_ctx.finish(null);
```

```zig
// Middleware-style helper for inbound handlers (auto begin/finish/error capture)
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

```zig
// Same flow but resolved from current TLS Hub (no explicit client argument)
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

```zig
// Typed variant: no anyopaque in your handler, signature validated at compile time
const IncomingState = struct { handled: bool = false };
fn incomingTyped(ctx: *sentry.integrations.http.RequestContext, state: *IncomingState) !u16 {
    state.handled = true;
    return 204;
}

var state = IncomingState{};
const status = try sentry.integrations.auto.runIncomingRequestWithCurrentHubTyped(
    allocator,
    .{ .name = "GET /orders/:id", .method = "GET" },
    incomingTyped,
    &state,
    .{},
);
_ = status;
```

```zig
// Variant that extracts sentry-trace/baggage from raw headers automatically
const incoming_headers = [_]sentry.PropagationHeader{
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
    &incoming_headers,
    incomingHandler,
    handler_ctx,
    .{},
);
_ = status;
// If sentry-trace is missing, traceparent is also supported automatically.
```

```zig
// Current TLS Hub variant for header-driven inbound flow
const status = try sentry.integrations.auto.runIncomingRequestFromHeadersWithCurrentHub(
    allocator,
    .{
        .name = "GET /orders/:id",
        .method = "GET",
        .url = "https://api.example.com/orders/42",
    },
    &incoming_headers,
    incomingHandler,
    handler_ctx,
    .{},
);
_ = status;
```

```zig
// Downstream HTTP helper: child span + propagation headers + status mapping
var out = try sentry.integrations.http.OutgoingRequestContext.begin(.{
    .method = "POST",
    .url = "https://payments.example.com/charge",
    .description = "POST payments charge",
});
defer out.deinit();

var headers = try out.propagationHeadersAlloc(allocator);
defer headers.deinit(allocator);
// Attach headers.sentry_trace and headers.baggage to your outgoing HTTP request.

var header_list = try out.propagationHeaderListAlloc(allocator);
defer header_list.deinit(allocator);
// Or use header_list.slice() where []sentry.PropagationHeader is accepted.

var header_list_w3c = try out.propagationHeaderListWithTraceParentAlloc(allocator);
defer header_list_w3c.deinit(allocator);
// Includes sentry-trace + baggage + traceparent.

out.setStatusCode(200);
out.finish(null);
// HTTP breadcrumb is added automatically on finish by default.
```

```zig
// Typed outgoing helper variant
const OutState = struct { propagated: bool = false };
fn outgoingTyped(ctx: *sentry.integrations.http.OutgoingRequestContext, state: *OutState) !u16 {
    var h = try ctx.propagationHeadersAlloc(allocator);
    defer h.deinit(allocator);
    state.propagated = true;
    return 200;
}

var out_state = OutState{};
const code = try sentry.integrations.auto.runOutgoingRequestWithCurrentHubTyped(
    .{ .method = "POST", .url = "https://payments.example.com/charge" },
    outgoingTyped,
    &out_state,
    .{},
);
_ = code;
```

```zig
// OTel/W3C traceparent continuation helper
var txn_from_traceparent = try sentry.integrations.otel.startTransactionFromTraceParent(
    client,
    .{ .name = "GET /inventory", .op = "http.server" },
    incoming_traceparent_header,
);
defer txn_from_traceparent.deinit();
```

```zig
// Built-in transport backend composition
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

```zig
// Middleware-style helper for outbound handlers (auto span finish/error capture)
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

```zig
// Error-return helper: captures returned errors automatically
const value = try sentry.integrations.errors.runAndCapture(doWork, .{input});
```

```zig
// Worker/task helper: clone current top scope into detached Hub and run code with TLS swap
var detached = try sentry.integrations.runtime.DetachedHub.fromCurrent(allocator, client);
defer detached.deinit();

try detached.run(workerEntry, .{&detached});
```

```zig
// Thread helper: spawn worker with inherited Hub context automatically
const worker = try sentry.integrations.runtime.spawnWithCurrentHub(
    allocator,
    .{},
    workerEntry,
    .{arg1, arg2},
);
worker.join();
```

## Configuration

All options are provided via `sentry.Options` in `sentry.init`.

| Option | Type | Default | Description |
|---|---|---|---|
| `dsn` | `[]const u8` | required | Sentry DSN |
| `debug` | `bool` | `false` | Debug flag |
| `release` | `?[]const u8` | `null` | Release identifier |
| `dist` | `?[]const u8` | `null` | Distribution/build identifier applied to events and transactions |
| `environment` | `?[]const u8` | `null` | Environment name |
| `server_name` | `?[]const u8` | `null` | Host/server name |
| `sample_rate` | `f64` | `1.0` | Event sampling (`0.0..1.0`) |
| `traces_sample_rate` | `f64` | `0.0` | Trace sampling (`0.0..1.0`) |
| `traces_sampler` | `?TracesSampler` | `null` | Per-transaction sampling callback |
| `max_breadcrumbs` | `u32` | `100` | Scope breadcrumb cap |
| `attach_stacktrace` | `bool` | `false` | Attach synthetic thread stacktrace payload when event has no threads |
| `attach_debug_images` | `bool` | `true` | Attach default `debug_meta.images` payload when event has no debug image metadata |
| `send_default_pii` | `bool` | `false` | Reserved option for explicit PII policy toggles |
| `in_app_include` | `?[]const []const u8` | `null` | Optional in-app include patterns for stack frame classification |
| `in_app_exclude` | `?[]const []const u8` | `null` | Optional in-app exclude patterns for stack frame classification |
| `default_integrations` | `bool` | `true` | Controls default integration behavior for future integrations |
| `integrations` | `?[]const Integration` | `null` | Setup callbacks executed during client initialization |
| `before_send` | `?*const fn (*Event) ?*Event` | `null` | Drop/mutate event before queueing |
| `before_breadcrumb` | `?*const fn (Breadcrumb) ?Breadcrumb` | `null` | Drop/mutate breadcrumb |
| `before_send_transaction` | `?*const fn (*Transaction) ?*Transaction` | `null` | Drop/mutate transaction before queueing |
| `before_send_log` | `?*const fn (*LogEntry) ?*LogEntry` | `null` | Drop/mutate log entry before queueing |
| `transport` | `?TransportConfig` | `null` | Custom transport callback override |
| `http_proxy` | `?[]const u8` | `null` | Explicit HTTP proxy URL (fallback to env vars when unset) |
| `https_proxy` | `?[]const u8` | `null` | Explicit HTTPS proxy URL (fallback to env vars when unset) |
| `accept_invalid_certs` | `bool` | `false` | Disable TLS certificate verification for direct HTTPS transport (development/testing only) |
| `max_request_body_size` | `?usize` | `null` | Drop envelopes larger than this byte size |
| `enable_logs` | `bool` | `true` | Enable/disable structured log submissions |
| `cache_dir` | `[]const u8` | `"/tmp/sentry-zig"` | Crash marker directory |
| `user_agent` | `[]const u8` | `"sentry-zig/0.2.0"` | Transport User-Agent |
| `install_signal_handlers` | `bool` | `true` | POSIX signal handler install |
| `auto_session_tracking` | `bool` | `false` | Auto-start session on init |
| `session_mode` | `SessionMode` | `.application` | `.application` / `.request` |
| `session_aggregate_flush_interval_ms` | `u64` | `60000` | Request-mode aggregate auto-flush interval (`0` disables timer flush) |
| `shutdown_timeout_ms` | `u64` | `2000` | Timeout for shutdown flush |

When `default_integrations = false`, automatic runtime/os context enrichment is disabled
(trace context bootstrap remains enabled).
`traces_sampler` receives `transaction_name`, `transaction_op`, `trace_id`, `span_id`,
`parent_sampled`, and optional `custom_sampling_context` from `TransactionOpts`.
Without `traces_sampler`, `TransactionOpts.sampled_override` forces per-transaction
sampling (`true` => `1.0`, `false` => `0.0`) and overrides
`TransactionOpts.sample_rate`.
Structured log records automatically include default `sentry.environment`,
`sentry.release`, and `server.address` attributes when configured.
When `server_name` is unset and `default_integrations = true`, the SDK attempts to use the local hostname.
`in_app_include`/`in_app_exclude` are applied to exception stack frames.
`attach_debug_images=true` injects default `debug_meta.images` metadata for events that do not already include debug image info.
`accept_invalid_certs=true` is intended for local/dev environments and is not supported together with explicit proxy transport.

Example integration setup callback:

```zig
fn setupCheckoutIntegration(client: *sentry.Client, _: ?*anyopaque) void {
    client.setTag("integration", "checkout");
}
```

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for full examples and edge cases.

## Shutdown and Reliability

- `flush(timeout_ms)` waits for queue drain without stopping client.
- `close(null)` flushes (with default timeout) and shuts down worker.
- `deinit()` is the standard safe shutdown path and should always run.

## Operational Readiness

- Set `release`, `environment`, and `server_name` explicitly.
- Validate event delivery on a staging environment before production rollout.
- Keep queue drain guarantees in shutdown hooks (`flush` + `deinit`).
- Add `before_send` / processors for redaction and noise filtering.
- Tune sampling and queue/body limits to your traffic profile.

## Testing

Run all tests:

```sh
zig build test
```

Run integration tests only:

```sh
zig build test-integration
```

Test capture helpers:

```zig
const std = @import("std");
const sentry = @import("sentry-zig");

fn capture(client: *sentry.Client, _: ?*anyopaque) !void {
    _ = client.captureMessageId("hello testkit", .info);
}

var events = try sentry.testkit.withCapturedEvents(
    std.testing.allocator,
    capture,
    null,
);
defer events.deinit();
```

Tracing note: each transaction stores up to `1000` child spans (`MAX_SPANS`).

## Resources

- Full guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- Project repository: [github.com/nullclaw/sentry-zig](https://github.com/nullclaw/sentry-zig)

## License

MIT
