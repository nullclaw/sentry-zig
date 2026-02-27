const std = @import("std");
const builtin = @import("builtin");

comptime {
    const minimum = std.SemanticVersion{
        .major = 0,
        .minor = 15,
        .patch = 2,
    };
    if (builtin.zig_version.order(minimum) == .lt) {
        @compileError("sentry-zig build requires Zig >= 0.15.2");
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sentry_mod = b.addModule("sentry-zig", .{
        .root_source_file = b.path("src/sentry.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ─── Unit Tests ─────────────────────────────────────────────────────
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/sentry.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // ─── Integration Tests ──────────────────────────────────────────────
    const integration_test_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_test_mod.addImport("sentry-zig", sentry_mod);

    const integration_tests = b.addTest(.{
        .root_module = integration_test_mod,
    });

    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_integration_step = b.step("test-integration", "Run integration tests");
    test_integration_step.dependOn(&run_integration_tests.step);

    // ─── Test Step (runs both unit and integration tests) ───────────────
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_integration_tests.step);
}
