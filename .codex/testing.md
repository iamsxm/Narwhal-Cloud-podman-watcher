# 测试记录

- 日期：2026-08-28
- 执行者：Codex
- `cargo fmt --all -- --check`：通过。
- `git diff --check`：通过。
- `cargo test --locked`：未完成；本机缺少 MSVC linker，用户随后明确要求停止本地编译并使用 GitHub Actions。
- Python 版本契约测试：未执行；沙箱中的 WindowsApps `python.exe` 无法启动，且没有 `py` launcher。
- Rust 单元测试已加入源码，覆盖 Podman snake_case、Docker 组合字段、模板回退、Incus OpenMetrics 和累计计数重置。

## v1.6.33

- `cargo fmt --all -- --check`：通过。
- `cargo metadata --locked --no-deps`：已通过，包版本为 `1.6.33`。
- bundled Python `-m py_compile server/app.py tests/test_server_runtime.py`：已通过。
- `git diff --check`：通过。
- `bash -n scripts/install-rust-client.sh`：Windows 沙箱无法创建 WSL Bash 实例（`E_ACCESSDENIED`），由 Ubuntu GitHub Actions 的 shell 步骤继续验证。
- Rust 测试：已增加 `/proc/net` socket、监听端口、入站来源、OCI 暴露/配置风险和 Server 字段契约测试；按用户要求仅由 GitHub Actions 执行。
- Server 测试：已增加版本提示和更新动作去重测试；完整 unittest discovery 由 GHCR workflow 安装依赖后执行。
- 首次 GHCR run `33182033396`：失败于 `requests` 未安装；workflow 已补充 `client/requirements.txt`，不涉及运行时代码。
