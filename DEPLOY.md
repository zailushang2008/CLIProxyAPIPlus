# CLIProxyAPIPlus (utls 版) 部署指南

## 快速部署

```bash
# 下载二进制（从 GitHub Release）
# 解压
gzip -d cli-proxy-api.gz
chmod +x cli-proxy-api

# 创建配置
cp config.example.yaml config.yaml
# 编辑 config.yaml（改 api-keys、secret-key 等）

# 运行
./cli-proxy-api
```

## 配置说明

关键配置项：
- `port: 8317` — 内部端口
- `remote-management.secret-key` — 管理面板密码（会自动 bcrypt 哈希）
- `api-keys` — 下游客户端调用的 API Key
- `auth-dir` — 认证文件目录，默认 `~/.cli-proxy-api`

## Docker 部署

```bash
git clone https://github.com/zailushang2008/CLIProxyAPIPlus.git
cd CLIProxyAPIPlus
docker build -t cli-proxy-api-plus:utls .
docker compose up -d
```

docker-compose.yml 预设端口 18317:8317，auth 目录挂载到 /root/.cli-proxy-api。

## Systemd 服务

```bash
cat > /etc/systemd/system/cli-proxy-api.service << 'EOF'
[Unit]
Description=CLIProxyAPIPlus
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/CLIProxyAPIPlus
ExecStart=/opt/CLIProxyAPIPlus/cli-proxy-api
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cli-proxy-api
```

## 验证

```bash
curl http://localhost:8317/v0/models
```
