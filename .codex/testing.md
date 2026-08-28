# 测试记录

- 日期：2026-08-28
- 执行者：Codex
- `cargo fmt --all -- --check`：通过。
- `git diff --check`：通过。
- `cargo test --locked`：未完成；本机缺少 MSVC linker，用户随后明确要求停止本地编译并使用 GitHub Actions。
- Python 版本契约测试：未执行；沙箱中的 WindowsApps `python.exe` 无法启动，且没有 `py` launcher。
- Rust 单元测试已加入源码，覆盖 Podman snake_case、Docker 组合字段、模板回退、Incus OpenMetrics 和累计计数重置。
