//! Built-in integration helpers for Sentry-Zig.
//!
//! These integrations are opt-in helpers that improve automatic instrumentation
//! ergonomics for common Zig runtime flows.

pub const log = @import("integrations/log.zig");
pub const panic = @import("integrations/panic.zig");
