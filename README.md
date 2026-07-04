# SingBox GUI

一个 Windows 下的 sing-box 图形化管理工具，类似 v2rayN。

## 功能

- 节点列表管理（导入、订阅、右键应用节点）
- 支持协议：VMess / VLESS / Trojan / Shadowsocks / Hysteria2 / TUIC
- 订阅格式：base64 节点链接 / Clash YAML / sing-box JSON
- 一键启用 TUN 模式（写入配置文件 inbound）
- 一键设置系统代理（注册表 + mixed inbound）
- 启动/停止 sing-box 进程 + 实时日志

## 使用方法

1. 解压后目录结构：
   ```
   singbox-gui/
   ├── singbox-gui.exe   ← 主程序
   ├── bin/
   │   └── sing-box.exe  ← 核心
   ├── data/             ← 自动生成（节点/设置持久化）
   └── config.example.json
   ```

2. 准备一个 sing-box 配置文件（参考 `config.example.json`），
   其中 outbounds 里必须有一个 `"tag": "proxy"` 的出站。

3. 启动 `singbox-gui.exe`，点击顶部配置栏选择你的配置文件。

4. 导入节点或拉取订阅，右键节点 → **应用此节点**，
   程序会将该节点写入配置文件的 `proxy` outbound。

5. 按需开启底部三个开关：
   - **TUN 模式**：向配置文件写入 tun inbound（需要管理员权限）
   - **系统代理**：设置 Windows 系统代理为 `127.0.0.1:2080`
   - **启动核心**：运行 `bin/sing-box.exe`

## 注意

- TUN 模式需要以**管理员身份**运行程序
- 系统代理自动添加常见内网地址到绕过列表
- 程序退出时会自动停止 sing-box 进程

## 从源码编译

```bash
# 安装依赖
go install github.com/wailsapp/wails/v2/cmd/wails@latest
cd frontend && npm install && cd ..

# 开发模式
wails dev

# 编译
wails build -platform windows/amd64 -ldflags "-H windowsgui"
```

## GitHub Actions 自动编译

推送 tag 即可触发自动编译并发布 Release：

```bash
git tag v1.0.0
git push origin v1.0.0
```
