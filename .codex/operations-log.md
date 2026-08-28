# 操作日志

- 日期：2026-08-28
- 执行者：Codex
- 上下文检索：使用 `rg`、PowerShell 文件读取和 Git 检查 Rust/Python 采集链路及 Server 入库契约。
- 关键结论：Server 原样存储 Client 指标；Rust Podman 字段兼容缺失、Incus 指标未实现是全零主因。
- 实施决策：复用 Python Client 已验证的数据口径，在 Rust 中建立统一解析函数和累计计数状态，不新增第三方采集框架。
- 代码修改：统一 OCI stats 解析；Podman JSON/模板合并；Incus OpenMetrics CPU、内存、网络、pps、文件系统采集；新增累计计数速率状态。
- 依赖处理：新增 `Cargo.lock` 并声明 Rust 1.83 MSRV，锁定间接依赖到兼容版本。
- 验证调整：用户明确要求不在本地编译，Rust 编译交由 GitHub Actions；本地仅执行格式、静态 diff 和 Python 版本契约测试。
