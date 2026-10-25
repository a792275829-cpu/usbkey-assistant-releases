# USBKey 助手

macOS 原生 USBKey 助手，提供设备与证书状态、网页登录桥接、硬件签名、数字信封加解密，以及应用内更新。

当前版本为 **1.1.21**，应用后端已完整迁到 Rust。应用运行及应用包构建不再需要 Node.js，也不携带 JavaScript 服务文件；Swift 界面、系统钥匙串和既有 C 硬件协议保留。已发布版本的记录以 [CHANGELOG.md](CHANGELOG.md) 为准。

## 当前支持

- Apple 芯片 Mac，构建部署目标为 macOS 12.0。
- FT3000GM HID 设备、公有证书枚举、多设备选择、证书持有者与到期时间显示。
- 受保护 PIN 认证及硬件 RSA-2048 签名/解密；私钥保留在 USBKey 内。
- 与现有网站调用兼容的 JSON-RPC、分离式 CMS 签名和 AES-CBC 数字信封。
- 仅监听本机的 HTTPS/WSS 服务、Origin 与子协议限制、设备拔插通知。
- Swift 管理已保存的证书密码；Rust 管理认证租约、缓存失效、硬件进程超时与回收。
- GitHub Releases 更新检查、下载及 SHA-256 校验。

只实现现有业务需要的接口，不代表兼容原厂所有设备或所有中间件接口。

## 构建应用

需要 Xcode 命令行工具和 Rust/Cargo。Rust 依赖版本已锁定，首次构建需要下载依赖并编译静态链接的 OpenSSL。

```sh
SKIP_PACKAGE=1 make app
make package
```

应用产物在 `build/release/`，对外发布的安装镜像是 `dist/<名称>-<版本>-apple-silicon.dmg`（拖拽安装），同一目录还会生成用于旧客户端升级的 `.pkg`；`BUILD_PKG=0 make package` 只产出镜像。构建会检查 Apple 芯片架构、系统动态库依赖、第三方许可证，以及包内不存在 Node/JavaScript 运行时。构建不会安装应用、改变系统证书信任或发布 GitHub Release。

构建所需的数据文件只有 `vendor/netca/netca-trust.sqlite`（60 KB，随仓库提交）。逆向分析与取证产物放在本地 `work/`，不纳入版本库，构建也不再依赖它，详见 [work/README.md](work/README.md)。

## 开发与验证

```sh
make test
make test-assistant-layout
make test-assistant-restart
```

开发对照测试仍使用 Node.js 和 Python：旧 JavaScript 实现仅作为兼容性对照，不进入应用包。测试包括 Rust 状态/进程测试、临时 TLS 和仿真硬件下的端到端测试、CMS 字节对照，以及 OpenSSL/旧实现之间的数字信封互操作。

准备本地 TLS 证书后，可独立启动 Rust 桥：

```sh
make tls
make bridge
```

该命令会枚举实际设备。独立运行时未连接 Swift 钥匙串管道，保存密码功能需要通过主应用使用。TLS 信任与实物验证流程见 [安装说明](docs/INSTALL_APPLE_SILICON.md)。

本版本已进行离线兼容验证与应用构建检查，尚未进行实物 PIN/签名/解密、真实钥匙串读写、目标网站及完整安装升级复测。

实现边界与迁移记录见 [Rust 后端说明](docs/RUST_TRANSPORT.md)，发布流程见 [更新说明](docs/GITHUB_UPDATES.md)。
