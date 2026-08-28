# 验证报告

- 日期：2026-08-28
- 执行者：Codex
- 验收范围：Rust Client 核心资源指标采集与版本一致性。
- 本地静态验证：通过 Rust 格式解析和 Git 空白错误检查。
- 本地编译：按用户指令跳过，交由 GitHub Actions 的 Linux musl AMD64/ARM64 构建矩阵执行。
- Python 测试：本机无可执行 Python 运行时，未执行。
- 遗留风险：当前改动没有在真实 Podman/Incus 宿主机运行；首轮累计网络和 Incus CPU 采样按设计为 0，第二轮开始产生速率。

## v1.6.33 验证范围

- 日期：2026-08-28
- 执行者：Codex
- 目标：补齐 Rust Client 下层连接、端口、来源、安全摘要指标，并支持版本判断和远程更新。
- 客户端边界：一键更新仅对明确上报 `agent_kind=rust` 且支持动作轮询的版本开放。
- 本地验证：Rust 格式解析、Cargo 锁文件元数据、Python 语法编译和 Git diff 静态检查。
- CI 验证：GitHub Actions 执行 Rust AMD64 单元测试、AMD64/ARM64 musl 构建、Server 完整 unittest 与多架构镜像构建。
- 运行说明：首次采样建立累计计数基线，RX/TX、pps、CPU 差值及协议速率从第二个报告周期开始有效。
- 已知限制：NAT 后原始来源依赖宿主机 conntrack，Rust 当前仅观察容器网络命名空间；无活动远端 socket 时来源 Top3 合理显示为空。
- 本地结果：`cargo fmt --check`、`cargo metadata --locked --no-deps`、Python `py_compile` 与 `git diff --check` 均通过；本地未编译 Rust。
- 首次远程验证：GHCR workflow 在测试导入 Python Client 时发现缺少 `requests`，已修复 workflow 依赖安装并重新触发。
