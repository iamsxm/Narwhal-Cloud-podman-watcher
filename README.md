# Narwhal Cloud Podman Watcher (CS)

一个轻量级的 **CS 架构 Podman 监控工具**：

- **Server 主控端**：汇总不同机器的容器状态、网络状态与预警，提供 Web 页面。
- **Client 客户端**：每 5 分钟采集一次数据并上报，尽量降低资源占用。
- **通信安全**：基于 `HMAC-SHA256` 的共享密钥签名鉴权。
- **部署方式**：Server/Client 均在 Podman 容器中运行，支持交互式一键安装脚本。

## 监控项

- 容器 CPU 占用
- 容器连接数（基于容器 PID 对应 socket 数量）
- 网络速度（RX/TX，按采集周期换算）
- 指定磁盘文件（默认 `/xfs_disk.img`）容量与挂载点使用率（默认 `/data`）
- Podman 网络健康（IPv4 / IPv6）

## 快速安装（从 Git 到一键部署）

> 适用环境：Debian / Ubuntu（安装脚本使用 `apt-get` 自动补齐依赖）

### 1) 克隆仓库

```bash
git clone <your-repo-url> narwhal-cloud-podman-watcher
cd narwhal-cloud-podman-watcher
```

### 2) 一键安装（推荐）

```bash
sudo bash scripts/install.sh
```

`install.sh` 会自动：
- 检查并安装依赖：`podman` / `git` / `curl`
- 进入交互式安装流程
- 让你选择安装 `server`、`client` 或 `both`

### 3) 交互式安装项说明

#### Server 安装会询问
- 镜像来源（`local` 本地 build / `github` 直接拉取 GHCR 镜像）
- GitHub 镜像地址（仅在选择 `github` 时使用，默认 `ghcr.io/narwhal-cloud/podman-watcher-server:latest`）
- Web 端口（默认 `8080`）
- 共享密钥（用于 Client 鉴权）
- 磁盘告警阈值（默认 `80`）

#### Client 安装会询问
- 镜像来源（`local` 本地 build / `github` 直接拉取 GHCR 镜像）
- GitHub 镜像地址（仅在选择 `github` 时使用，默认 `ghcr.io/narwhal-cloud/podman-watcher-client:latest`）
- Server URL（例如 `http://1.2.3.4:8080`）
- 共享密钥（需要和 Server 一致）
- Host ID（默认当前机器 hostname）
- 上报间隔（默认 `300` 秒）

### 4) 安装完成后会打印完整配置清单

Server/Client 安装脚本结束时都会输出：
- 容器名
- 端口 / Server URL
- 共享密钥
- Host ID / 上报间隔
- Env 文件路径
- 镜像名
- 挂载目录与关键路径

便于你直接核对部署参数，避免“装完忘了填了什么”。

### 5) 仅安装单端（可选）

```bash
sudo bash scripts/install-server.sh
sudo bash scripts/install-client.sh
```

安装完成后，访问 `http://<server-ip>:<port>/`。

## 容器权限说明（是否 OK）

Client 需要读取宿主 Podman 与网络状态，因此容器运行参数已包含：

- `--network host`：用于真实网络探测（IPv4/IPv6）
- `--pid host`：用于按容器 PID 统计连接数
- `-v /run/podman/podman.sock:/run/podman/podman.sock`：访问 Podman 信息
- 只读挂载 `/xfs_disk.img`、`/data`：做磁盘容量检测

在大多数 Debian/Ubuntu + Podman 环境下，这组权限可以满足监控需求；如遇 SELinux/AppArmor 限制，可按发行版策略补充标签或策略。

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
