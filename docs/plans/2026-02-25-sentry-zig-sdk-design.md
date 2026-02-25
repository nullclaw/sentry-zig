# Sentry SDK for Zig — Design Document

**Date:** 2026-02-25
**Target:** NullClaw (https://github.com/nullclaw/nullclaw)
**Zig Version:** 0.15.2
**Approach:** Pure Zig implementation (no C dependencies)

## Overview

A pure Zig Sentry SDK implementing the Sentry envelope protocol. Designed as a zero-dependency Zig package that integrates with NullClaw's existing architecture (vtable-based polymorphism, allocator-aware, minimal footprint).

## Scope

Full-featured SDK:
- Error/exception capture with stack traces
- Breadcrumbs (ring buffer, 100 entries)
- User context, tags, extra data, structured contexts
- Transactions and spans (performance monitoring)
- Session tracking (started/crashed/errored/exited)
- Crash reporting via POSIX signal handlers
- Attachments support

## Architecture

### Module Structure

```
src/
├── sentry.zig              # Public API — init(), captureEvent(), close()
├── dsn.zig                 # DSN parsing
├── transport.zig           # HTTP transport (std.http.Client)
├── envelope.zig            # Sentry Envelope serialization
├── event.zig               # Event, Exception, Message structures
├── breadcrumb.zig          # Ring buffer for 100 breadcrumbs
├── scope.zig               # Scope: user, tags, extra, contexts, breadcrumbs
├── session.zig             # Session tracking
├── transaction.zig         # Transaction + Span for performance monitoring
├── uuid.zig                # UUID v4 generation
├── timestamp.zig           # RFC 3339 formatting
├── json.zig                # JSON serialization via std.json
├── worker.zig              # Background thread with event queue
├── signal_handler.zig      # POSIX signal handler for crash reporting
```

### Public API

```zig
const sentry = @import("sentry");

// Initialize
var client = try sentry.init(allocator, .{
    .dsn = "https://key@o0.ingest.sentry.io/12345",
    .release = "nullclaw@2025.2.25",
    .environment = "production",
    .sample_rate = 1.0,
    .traces_sample_rate = 0.2,
    .max_breadcrumbs = 100,
    .server_name = null,          // auto-detect
    .before_send = null,          // filter callback
});
defer client.deinit();

// Error capture
client.captureMessage("Something went wrong", .err);
client.captureException("RuntimeError", "division by zero", stack_trace);

// Scope
client.setUser(.{ .id = "42", .email = "user@example.com" });
client.setTag("module", "agent");
client.setExtra("turn_count", .{ .integer = 15 });

// Breadcrumbs
client.addBreadcrumb(.{
    .category = "http",
    .message = "POST /api/chat",
    .level = .info,
    .data = &.{ .{ "status_code", "200" } },
});

// Transactions (Performance)
var txn = client.startTransaction(.{
    .name = "agent.turn",
    .op = "task",
});
var span = txn.startChild(.{
    .op = "llm.request",
    .description = "anthropic.chat",
});
span.finish();
txn.finish();

// Sessions
client.startSession();
client.endSession(.exited);

// Flush + shutdown
try client.flush(5000);
```

### Data Flow

```
captureEvent() ──> Scope enrichment ──> before_send callback ──> Worker Queue
                                                                      │
                                                          Background Thread
                                                                      │
                                                              Envelope serialize
                                                                      │
                                                         POST /api/{project_id}/envelope/
                                                              std.http.Client (TLS)
                                                                      │
                                                              Rate limit tracking
                                                              (429 → backoff)
```

### Transport

- `std.http.Client` with TLS — zero external dependencies
- Background worker thread with mutex-protected queue
- Batch sending: up to 30 events or 2-second timeout
- Rate limiting: parses `X-Sentry-Rate-Limits` and `Retry-After` headers
- Graceful shutdown: `flush()` waits for queue drain with timeout

### Envelope Format

```
{"event_id":"abc123...","dsn":"https://key@host/123","sent_at":"2025-02-25T12:00:00Z"}\n
{"type":"event","length":N}\n
{...event JSON payload...}\n
```

### DSN Format

```
{PROTOCOL}://{PUBLIC_KEY}@{HOST}/{PATH}/{PROJECT_ID}
```

### Crash Reporting

- Signal handlers for SEGV, ABRT, BUS, ILL, FPE via `std.posix`
- Async-signal-safe: writes minimal crash file to disk
- On next startup: detects crash file and sends to Sentry
- Stack traces via `std.debug.StackTrace` when available

### Session Tracking

- `startSession()` creates session with `init` timestamp
- Auto-sends session update on crash/error
- `endSession(.exited)` ends session normally
- Sessions sent as separate envelope items

### Error Handling

```zig
pub const SentryError = error{
    InvalidDsn,
    TransportFailed,
    QueueFull,
    AlreadyInitialized,
    NotInitialized,
    InvalidEventId,
    SerializationFailed,
};
```

### Testing Strategy

- Mock transport for unit tests (records sent envelopes to ArrayList)
- Each module has inline `test` blocks
- Integration test with real `std.http.Client` (opt-in via env var)

## Design Decisions

1. **No C dependencies** — matches NullClaw's philosophy (single sqlite3 dep, 678KB binary)
2. **Allocator-aware** — no global state, fits Zig idioms
3. **std.http.Client** — built-in TLS, no libcurl needed
4. **Background worker** — non-blocking event sending
5. **POSIX signals** — crash reporting without Crashpad/Breakpad
6. **Ring buffer breadcrumbs** — fixed-size, O(1) add
