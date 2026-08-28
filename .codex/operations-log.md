# 操作日志

- 日期：2026-08-28
- 执行者：Codex
- 上下文检索：使用 `rg`、PowerShell 文件读取和 Git 检查 Rust/Python 采集链路及 Server 入库契约。
- 关键结论：Server 原样存储 Client 指标；Rust Podman 字段兼容缺失、Incus 指标未实现是全零主因。
- 实施决策：复用 Python Client 已验证的数据口径，在 Rust 中建立统一解析函数和累计计数状态，不新增第三方采集框架。
- 代码修改：统一 OCI stats 解析；Podman JSON/模板合并；Incus OpenMetrics CPU、内存、网络、pps、文件系统采集；新增累计计数速率状态。
- 依赖处理：新增 `Cargo.lock` 并声明 Rust 1.83 MSRV，锁定间接依赖到兼容版本。
- 验证调整：用户明确要求不在本地编译，Rust 编译交由 GitHub Actions；本地仅执行格式、静态 diff 和 Python 版本契约测试。

## v1.6.33 下层指标与远程更新

- 日期：2026-08-28
- 执行者：Codex
- 契约复核：对照 `client/agent.py`、`server/app.py` 与 Rust payload，确认 Server 面板读取的安全和网络字段名称。
- 指标实现：读取容器网络命名空间的 `/proc/<pid>/net`，补齐连接、SYN_RECV、监听端口、入站/出站 IP、包速率和 TCP/UDP 协议速率。
- 来源统计：复用 Python Client 的 `ip-api` 批量国家解析口径并增加进程内缓存；解析失败统一回退为 `UN`。
- 安全摘要：补齐 Podman/Docker 端口映射、Incus proxy、容器配置风险、Top CPU 进程与基础可疑进程识别。
- 版本更新：改用语义版本比较，区分 Client 可更新与 Server 待更新；新增签名动作轮询及固定 `update_client` 动作。
- 客户端隔离：Rust 上报增加 `agent_kind=rust`；Server 前端和更新 API 均校验客户端类型，避免向 Python Client 误发 Rust 更新动作。
- 首次升级：`v1.6.32` 不具备动作轮询能力，面板提供首次升级命令；升级至 `v1.6.33` 后支持一键更新。
- 验证策略：遵照用户要求不执行本地 Rust 编译，GitHub Actions 使用锁文件运行 AMD64 测试以及 AMD64/ARM64 musl 构建。
