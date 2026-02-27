# caddy2-ipban

Caddy 2 HTTP 中间件插件，检测恶意扫描请求并封禁源 IP。

## 功能

- 规则匹配：精确路径、前缀、关键词、正则、User-Agent
- 规则来源：本地文件（fsnotify 热重载）、远程 URL（ETag 条件刷新）、内置默认规则
- 进程内封禁存储，支持 TTL、阈值封禁、JSON 持久化
- Linux ipset 内核级封锁（不可用时自动降级）
- IP/CIDR 白名单
- 随机 4xx 状态码迷惑扫描器

## 安装

使用 [xcaddy](https://github.com/caddyserver/xcaddy) 构建包含此插件的 Caddy：

```bash
xcaddy build --with github.com/ysicing/caddy2-ipban
```

## Caddyfile 配置

```caddyfile
{
    order ipban first
}

example.com {
    ipban {
        # 规则来源（不配置则使用内置默认规则）
        # 本地文件：rule_source /etc/caddy/rules.json
        # 远程 URL：rule_source https://example.com/rules.json
        rule_source /etc/caddy/rules.json
        refresh_interval 1h

        # 白名单（私有/回环 IP 自动跳过）
        allow 198.51.100.0/24 203.0.113.50

        # 封禁时长（默认 7 天）
        ban_duration 24h

        # 返回给被封禁请求的状态码（默认: 451，可自定义多个随机返回）
        # status_codes 400 403 404 429

        # Linux ipset 内核级封锁
        # ipset_name blacklist
    }
}
```

所有配置项均可选，零配置即可使用内置默认规则。封禁记录和远程规则缓存自动存储到 Caddy 数据目录。

## 规则格式

JSON 格式，灵感来自 sing-box：

```json
{
  "version": 1,
  "rules": [
    {
      "path": ["/.env", "/.git/config"],
      "path_prefix": ["/wp-admin/", "/phpmyadmin"],
      "path_keyword": ["passwd", "phpinfo"],
      "path_regex": ["\\.php\\d?$"],
      "user_agent_keyword": ["sqlmap", "nikto"],
      "user_agent_regex": ["python-requests/\\d"]
    }
  ]
}
```

所有字符串匹配不区分大小写。完整示例见 [rules.example.json](rules.example.json)。

## 请求处理流程

```
ServeHTTP → clientIP → 公网IP? → 白名单? → 已封禁? → 规则匹配? → 封禁+拦截 / 放行
```

私有/回环 IP 和白名单 IP 直接放行，被封禁的请求收到随机 4xx 状态码。

## 开发

使用 [Task](https://taskfile.dev)：

```bash
task build          # xcaddy 构建
task test           # 运行测试
task test:race      # 竞态检测
task vet            # 静态分析
task lint           # vet + test:race
```

或直接用 Go 命令：

```bash
go test -race ./...
go vet ./...
```

## 许可证

MIT