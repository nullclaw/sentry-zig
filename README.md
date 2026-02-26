# Sentry-Zig

Native Sentry SDK in Zig (`0.15.x`) for capturing errors, transactions, sessions,
and monitor check-ins via the Sentry Envelope protocol.

This repository focuses on a clean public API, production-safe defaults, and
predictable shutdown behavior.

Detailed guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)

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

- Zig `>= 0.15.0`

## Installation

Add dependency:

```sh
zig fetch --save git+https://github.com/nullclaw/sentry-zig.git
```

Import module in `build.zig`:

```zig
const sentry_dep = b.dependency("sentry-zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("sentry-zig", sentry_dep.module("sentry-zig"));
```

## Core Concepts

- `Client`: owns transport, worker queue, and runtime configuration.
- `Scope`: mutable event context (user, tags, extras, breadcrumbs, attachments).
- `Event`: error/message payload (`captureMessage`, `captureException`, `captureEvent`).
- `Transaction` + `Span`: tracing payloads (`startTransaction`, `finishTransaction`).
- `Session`: release health lifecycle (`startSession`, `endSession`).
- `MonitorCheckIn`: cron monitor status payload (`captureCheckIn`).

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
| Traces sampler callback | Implemented | `traces_sampler` has priority over `traces_sample_rate` |
| Sessions (application/request mode) | Implemented | Request mode disables duration tracking |
| Monitor check-ins | Implemented | `check_in` envelopes with env inheritance |
| Worker + queue draining | Implemented | Bounded queue + `flush`/`close` semantics |
| Transport rate limits | Implemented | `Retry-After` + `X-Sentry-Rate-Limits` parsing |
| Signal crash marker flow | Implemented | POSIX marker write/read cycle |
| Hub/TLS scope stack | Not implemented | Planned area |
| Extended integrations | Not implemented | Planned area |
| Structured logs pipeline | Not implemented | Planned area |

## Common Usage

```zig
// Capture message
client.captureMessage("checkout failed", .err);

// Capture exception
client.captureException("PaymentError", "gateway timeout");

// Get event id when accepted
if (client.captureMessageId("degraded mode", .warning)) |event_id| {
    std.log.warn("event_id={s}", .{event_id});
}

// Scope data
client.setUser(.{ .id = "user-42", .email = "user@example.com" });
client.setTag("feature", "checkout");
client.addBreadcrumb(.{ .category = "http", .message = "POST /checkout", .level = .info });
```

## Configuration

All options are provided via `sentry.Options` in `sentry.init`.

| Option | Type | Default | Description |
|---|---|---|---|
| `dsn` | `[]const u8` | required | Sentry DSN |
| `debug` | `bool` | `false` | Debug flag |
| `release` | `?[]const u8` | `null` | Release identifier |
| `environment` | `?[]const u8` | `null` | Environment name |
| `server_name` | `?[]const u8` | `null` | Host/server name |
| `sample_rate` | `f64` | `1.0` | Event sampling (`0.0..1.0`) |
| `traces_sample_rate` | `f64` | `0.0` | Trace sampling (`0.0..1.0`) |
| `traces_sampler` | `?TracesSampler` | `null` | Per-transaction sampling callback |
| `max_breadcrumbs` | `u32` | `100` | Scope breadcrumb cap |
| `before_send` | `?*const fn (*Event) ?*Event` | `null` | Drop/mutate event before queueing |
| `before_breadcrumb` | `?*const fn (Breadcrumb) ?Breadcrumb` | `null` | Drop/mutate breadcrumb |
| `cache_dir` | `[]const u8` | `"/tmp/sentry-zig"` | Crash marker directory |
| `user_agent` | `[]const u8` | `"sentry-zig/0.1.0"` | Transport User-Agent |
| `install_signal_handlers` | `bool` | `true` | POSIX signal handler install |
| `auto_session_tracking` | `bool` | `false` | Auto-start session on init |
| `session_mode` | `SessionMode` | `.application` | `.application` / `.request` |
| `shutdown_timeout_ms` | `u64` | `2000` | Timeout for shutdown flush |

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for full examples and edge cases.

## Shutdown and Reliability

- `flush(timeout_ms)` waits for queue drain without stopping client.
- `close(null)` flushes (with default timeout) and shuts down worker.
- `deinit()` is the standard safe shutdown path and should always run.

## Testing

Run all tests:

```sh
zig build test
```

Run integration tests only:

```sh
zig build test-integration
```

## Roadmap Notes

Current focus is complete stability of core data flows:
events, tracing, sessions, envelopes, and transport behavior.

## License

MIT
