# Narwhal Cloud Podman Watcher (CS)

一个轻量级的 **CS 架构 Podman 监控工具**：

- **Server 主控端**：汇总多机容器状态、网络状态与预警，提供 Web 页面。
- **Client 客户端**：按固定间隔采集数据并上报。
- **通信安全**：`HMAC-SHA256` 共享密钥签名鉴权。
- **部署方式**：Server/Client 均容器化，支持一键安装与一键更新。

## 新增能力（本次增强）

- **一键更新**：`install.sh` 支持 `update` 操作，会先 `git pull --ff-only` 更新仓库（包含 `sh` 脚本本身），再自动重建/重启服务。
- **自动复用历史配置**：更新模式会自动读取已有 `/opt/narwhal-monitor/*.env` 配置，不再要求重复输入。
- **Server HTTPS 自动化**：支持自动拉起 Caddy 反向代理：
  - 域名场景：自动申请公网证书（ACME HTTP-01）。
  - Cloudflare 域名场景：支持 DNS Challenge（可橙云），自动签发并续期公网证书。
  - IP 场景：自动签发内部证书（`tls internal`）。

> 注意：IP 场景下的内部证书不是公网 CA 证书，浏览器默认可能提示不受信任；如需“绿锁”建议使用域名。

## 快速安装

> 适用环境：Debian / Ubuntu（脚本使用 `apt-get` 自动补齐依赖）

### 1) 克隆仓库

```bash
git clone https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git
cd Narwhal-Cloud-podman-watcher
```

### 2) 运行一键安装/更新器

```bash
sudo bash scripts/install.sh
```

脚本会自动：
- 检查并安装依赖：`podman` / `git` / `curl`
- 选择操作：`install` 或 `update`
- 选择目标：`server` / `client` / `both`

### 3) 真·单命令安装（无需手动 clone）

```bash
curl -fsSL https://raw.githubusercontent.com/podcctv/Narwhal-Cloud-podman-watcher/main/scripts/bootstrap-install.sh -o /tmp/narwhal-bootstrap-install.sh
sudo bash /tmp/narwhal-bootstrap-install.sh
```

## 交互式参数（首次 install）

### Server

- 镜像来源（`local` / `github`）
- GitHub 镜像地址
- 后端监听端口（Server 容器内部服务绑定到宿主机端口）
- 共享密钥
- 磁盘告警阈值
- 是否启用 HTTPS 反代（Caddy）
- TLS Host（域名或 IP）
- TLS Email（域名证书可选）
- TLS 证书模式（`auto` / `internal` / `cloudflare_dns`）
- Cloudflare API Token（当选择 `cloudflare_dns` 时必填，需具备 Zone DNS Edit 权限）

### Client

- 镜像来源（`local` / `github`）
- GitHub 镜像地址
- 是否启用客户端日志输出到 `podman logs`（排障建议开启；正式环境可关闭）
- Server URL（建议 `https://...`）
- 共享密钥
- Host ID
- 上报间隔

## update 模式行为

- 自动执行仓库更新（`git fetch` + `git pull --ff-only`）。
- 自动读取并复用配置：
  - Server: `/opt/narwhal-monitor/server.env` + `/opt/narwhal-monitor/server-install.env`
  - Client: `/opt/narwhal-monitor/client.env` + `/opt/narwhal-monitor/client-install.env`
- 自动重建/重启容器，无需重新输入历史参数。
- 默认自动清理无用资源（旧镜像、未使用容器/网络/卷、apt 缓存与无用依赖），缓解磁盘空间压力。
  - 如需跳过：运行前设置 `SKIP_CLEANUP_ON_UPDATE=1`。

## HTTPS 配置指引（两种公网证书方式）

> 两种方式都会由 Caddy 自动续期证书，无需手工续期。

### 方式 A：域名直连（ACME HTTP-01，最简单）

适用：你使用 Cloudflare 托管 DNS，但可将该记录设置为 **DNS only（灰云）**。

1. 在 Cloudflare DNS 中为你的主机新增 `A/AAAA` 记录（例如 `monitor.example.com`）指向服务器公网 IP。  
2. 将该记录设置为 **DNS only（灰云）**，不要走 Cloudflare 代理。  
3. 服务器放通 `80/443` 端口。  
4. 运行安装脚本时填写：
   - `Enable HTTPS reverse proxy`: `yes`
   - `TLS host`: `monitor.example.com`
   - `TLS cert mode`: `auto`（域名下会自动走公网 ACME）
   - `TLS email`: 建议填写
5. Client 端 `SERVER_URL` 使用 `https://monitor.example.com`。

### 方式 B：Cloudflare DNS Challenge（可橙云）

适用：你希望保留 Cloudflare 代理（橙云）或不便开放 80 端口。

1. 在 Cloudflare 创建 API Token，权限至少包含：
   - `Zone:DNS:Edit`
   - `Zone:Zone:Read`
2. 运行安装脚本时填写：
   - `Enable HTTPS reverse proxy`: `yes`
   - `TLS host`: `monitor.example.com`
   - `TLS cert mode`: `cloudflare_dns`
   - `Cloudflare API token`: 填入上一步 token
3. 脚本会自动使用带 Cloudflare DNS 模块的 Caddy 镜像（优先 `ghcr.io/caddy-dns/cloudflare:latest`，并带回退策略），并注入 token。若你填了旧地址 `docker.io/caddy-dns/cloudflare`，安装脚本会自动改写到 `ghcr.io`。  
4. Client 端 `SERVER_URL` 使用 `https://monitor.example.com`。

> 安全建议：Cloudflare Token 请仅授予单一 Zone 的最小权限，避免使用全局 API Key。

## 监控项

- 容器 CPU 占用
- 容器连接数（按容器 PID 统计 socket）
- 网络速度（RX/TX）
- 离线容器生命周期管理：离线后默认保留 1 天并标记离线时长（按小时刷新），超过 1 天默认隐藏，超过 30 天自动删除历史数据
- 指定磁盘文件容量与挂载点使用率
- Podman 网络健康（IPv4 / IPv6）

## 仅安装单端（可选）

```bash
sudo bash scripts/install-server.sh install
sudo bash scripts/install-client.sh install
```

仅更新单端（复用已有配置）：

```bash
sudo bash scripts/install-server.sh update
sudo bash scripts/install-client.sh update
```

## 容器权限说明

Client 为采集宿主信息，默认包含：

- `--network host`
- `--pid host`
- `/run/podman/podman.sock` 挂载
- `/xfs_disk.img`、`/data` 只读挂载

## 开发运行

### Server

```bash
cd server
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8080
```

### Client

```bash
cd client
pip install -r requirements.txt
python agent.py --server http://127.0.0.1:8080 --secret change-me --interval 300
```
