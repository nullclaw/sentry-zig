# Sentry-Zig: User Guide

Практическая документация по подключению SDK и использованию основных возможностей
в production-приложении.

## Содержание

1. [Быстрый старт](#быстрый-старт)
2. [Подключение в build.zig](#подключение-в-buildzig)
3. [Жизненный цикл клиента](#жизненный-цикл-клиента)
4. [Захват событий и event_id](#захват-событий-и-event_id)
5. [Работа со Scope](#работа-со-scope)
6. [Attachments](#attachments)
7. [Трейсинг и транзакции](#трейсинг-и-транзакции)
8. [Release Health Sessions](#release-health-sessions)
9. [Monitor Check-Ins](#monitor-check-ins)
10. [Hooks и процессоры](#hooks-и-процессоры)
11. [Rate limits и очередь](#rate-limits-и-очередь)
12. [Crash handling (POSIX)](#crash-handling-posix)
13. [Production checklist](#production-checklist)
14. [Troubleshooting](#troubleshooting)
15. [Статус SDK](#статус-sdk)

## Быстрый старт

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

## Подключение в build.zig

```sh
zig fetch --save git+https://github.com/nullclaw/sentry-zig.git
```

```zig
const sentry_dep = b.dependency("sentry-zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("sentry-zig", sentry_dep.module("sentry-zig"));
```

## Жизненный цикл клиента

`Client` управляет:
- HTTP transport,
- background worker,
- rate-limit state,
- текущим `Scope`,
- сессией release health.

Базовые правила:
- Инициализируйте `Client` один раз на процесс.
- Всегда вызывайте `defer client.deinit();`.
- Перед завершением процесса при необходимости вызовите `flush(...)`.

Ключевые методы:
- `flush(timeout_ms)` — ждёт пока очередь опустеет.
- `close(timeout_ms_or_null)` — завершает сессию, дренирует очередь и выключает worker.
- `deinit()` — стандартный безопасный shutdown-путь.

## Захват событий и event_id

### Сообщение/исключение

```zig
client.captureMessage("checkout failed", .err);
client.captureException("PaymentError", "gateway timeout");
```

### Получить `event_id`

```zig
if (client.captureMessageId("retrying payment", .warning)) |event_id| {
    std.log.warn("event_id={s}", .{event_id});
}
```

### Последний принятый ID

```zig
if (client.lastEventId()) |last_id| {
    std.log.info("last event={s}", .{last_id});
}
```

Если событие отфильтровано (`before_send`, processor, sampling), методы `*Id`
возвращают `null`.

## Работа со Scope

`Scope` автоматически применяется к новым событиям.

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

Очистка:

```zig
client.removeUser();
client.removeTag("feature");
client.removeExtra("order_id");
client.removeContext("region");
```

Дополнительно:
- `setLevel` задаёт level по умолчанию.
- `setTransaction` и `setFingerprint` влияют на группировку событий.

Для строгого Zig-style error handling доступны fallible-версии:
- `trySetUser`, `trySetTag`, `trySetExtra`, `trySetContext`
- `trySetTransaction`, `trySetFingerprint`
- `tryAddBreadcrumb`, `tryAddAttachment`, `tryAddEventProcessor`

## Attachments

### Из памяти

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

### Из файла

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

После `addAttachment` локальный объект можно безопасно `deinit`: SDK хранит
внутреннюю копию.

## Трейсинг и транзакции

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

Глобально:

```zig
const client = try sentry.init(allocator, .{
    .dsn = "...",
    .traces_sample_rate = 0.2,
});
```

Динамически:

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

`traces_sampler` имеет приоритет над `traces_sample_rate`.

## Release Health Sessions

### Ручной режим

```zig
client.startSession();
// business logic...
client.endSession(.exited);
```

### Авто-режим

```zig
const client = try sentry.init(allocator, .{
    .dsn = "...",
    .release = "my-app@1.0.0",
    .auto_session_tracking = true,
});
```

Важно:
- Без `release` сессии не стартуют.
- `.application` mode считает duration.
- `.request` mode duration не отправляет.

## Monitor Check-Ins

```zig
var check_in = sentry.MonitorCheckIn.init("nightly-job", .in_progress);
client.captureCheckIn(&check_in);

check_in.status = .ok;
check_in.duration = 12.3;
client.captureCheckIn(&check_in);
```

Если `check_in.environment == null`, SDK подставляет `Options.environment`.

## Hooks и процессоры

### `before_send`

```zig
fn beforeSend(event: *sentry.Event) ?*sentry.Event {
    if (event.level == .debug) return null;
    return event; // вернуть тот же указатель
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

## Rate limits и очередь

Worker учитывает:
- `Retry-After`,
- `X-Sentry-Rate-Limits`.

Поведением по умолчанию:
- при переполнении очереди удаляются самые старые элементы;
- envelope с `event` (даже если с attachments) соблюдают `error` category rate-limit;
- категории `session` и `transaction` лимитируются независимо.

## Crash handling (POSIX)

По умолчанию устанавливаются handlers для:
- `SIGSEGV`
- `SIGABRT`
- `SIGBUS`
- `SIGILL`
- `SIGFPE`

Конфигурация:
- `install_signal_handlers = true|false`
- `cache_dir` для crash marker файлов.

## Production checklist

- Явно задать `release`, `environment`, `server_name`.
- Настроить sampling: `sample_rate`, `traces_sample_rate`/`traces_sampler`.
- Добавить `before_send` для редактирования/фильтрации payload.
- Добавить breadcrumbs в критичные CJM-этапы.
- Проверить graceful shutdown (`flush`/`deinit`).
- Проверить отправку событий на staging.

## Troubleshooting

### Нет событий в Sentry

- Проверьте корректность DSN.
- Проверьте, что процесс не завершается до `flush/deinit`.
- Проверьте, что событие не дропается в `before_send` или event processor.
- Проверьте `sample_rate`/`traces_sample_rate`.

### Сессии не отправляются

- Убедитесь, что указан `release`.
- Убедитесь, что `startSession` действительно вызывается (или `auto_session_tracking=true`).

### Check-ins без environment

- Укажите `Options.environment`, либо заполните `check_in.environment` вручную.

## Статус SDK

Текущий фокус:
- events/scope/envelope pipeline,
- transactions/spans/sampling,
- release health sessions,
- monitor check-ins,
- worker + transport rate limits.

Не реализовано на текущий момент:
- Hub model и TLS scope stack,
- расширенная экосистема интеграций,
- structured logs pipeline.

Для трекинга изменений используйте историю коммитов и интеграционные тесты
в `tests/integration_test.zig`.
