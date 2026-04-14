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

## 快速安装

在仓库根目录执行：

### 1) 安装 Server

```bash
bash scripts/install-server.sh
```

脚本会交互式询问：
- Web 端口
- 共享密钥
- 磁盘告警阈值

安装完成后，访问 `http://<server-ip>:<port>/`。

### 2) 安装 Client（每台机器执行）

```bash
bash scripts/install-client.sh
```

脚本会交互式询问：
- Server URL
- 共享密钥
- Host ID
- 上报间隔（默认 300 秒）

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
