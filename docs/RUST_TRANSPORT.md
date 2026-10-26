# Rust 后端

## 组件边界

应用默认使用两个 Rust 程序，不再提供旧 Node worker 入口。Swift 负责界面、系统钥匙串和应用更新，C 工具负责 FT3000GM 硬件协议。

```text
浏览器 / Swift 主应用
         │ HTTPS / WSS（仅 127.0.0.1）
         ▼
usbkey-transport（Rust）
         ├─ TLS/HTTP/WSS、状态快照、控制请求期限
         ├─ PIN 缓存、认证租约、单次硬件授权
         ├─ C 硬件工具和系统密码弹窗的超时与回收
         │ 继承的 Unix socket，子进程 fd 3
         ▼
usbkey-worker（Rust）
         ├─ RPC、证书解析与筛选、多设备选择
         ├─ CMS 签名、数字信封加解密
         ├─ 串行业务队列、设备订阅与通知
         └─ stdin/stdout 私有管道 → Swift 钥匙串
```

私有通道不落盘，不经过 HTTP；worker 启动时验证 fd 3 是已连接的 Unix 套接字。PIN 仅通过私有通道和 C 工具标准输入传递，不写入参数、环境变量或诊断日志。Rust 对缓存及受控输入缓冲执行清零。worker 或私有通道异常时 transport 退出；应用退出、父进程消失或 worker 崩溃时停止并回收活动工具。

## 网络与队列

- 保留 `/health`、`/status`、`/selection`、`/pin-cache/clear`、既有 RPC 信封、错误码和字段别名。
- WSS 校验网站 Origin 与 `crypto-jsonrpc-protocol` 子协议；管理接口拒绝带 Origin 的请求。
- WebSocket 消息/帧上限 1 MiB，内部响应及写缓冲上限 16 MiB；管理 POST 请求体上限 1 KiB、读取时限 5 秒。
- 最多 128 个 WebSocket，每连接收发队列各 64 项，内部等待请求最多 64 项。慢客户端发送超时后断开。
- RPC、设备选择、密码清理和监测使用串行业务队列。断线后跳过尚未执行的该连接 RPC；已开始的硬件操作可能完成，不重放或自动重试。
- `/status` 最多等待 3 秒；队列忙时返回最近快照及 `stale: true`，没有快照则返回 503。并发读者合并扫描，HTTP 等待结束后后台结果仍更新缓存。
- `/selection` 和 `/pin-cache/clear` 最多排队 10 秒。worker 执行前确认 `controlId` 仍有效，过期请求不执行；获准开始后等待真实结果。Swift 等待上限覆盖最长 120 秒的钥匙串交互。
- 设备枚举缓存 1 秒；状态、选择和监测强制重新枚举。每秒监测仅在存在 `MonitorDevice` 订阅时运行；无订阅时不轮询硬件。

## 硬件与认证

只允许固定探测、证书、PIN 状态、签名和解密操作，逐项校验设备标识和输入格式。只读工具上限 10 秒，签名/解密 15 秒，系统密码弹窗 120 秒；stdout 上限 1 MiB，PIN 状态 stdout 与 stderr 上限 64 KiB。并行读取 stdout/stderr，超限或超时终止进程组并等待回收；正常回收后不再向旧进程号发信号。执行器队列容量 64，保留 C 工具跨进程锁。

Rust 管理 60 秒短期缓存、5 分钟认证租约及设备/证书集合绑定。每次认证创建令牌和状态代次；设备切换、拔插、证书集合变化、读取失败或主动清除会撤销旧代次。启动硬件前在同一状态锁下复核令牌、设备和 PIN，每个令牌最多进行一次无 PIN 解密和一次携带 PIN 的操作，仅明确返回需要认证时允许后者。

业务操作及公钥自检全部成功后才提交租约或保存密码；错误 PIN 保留剩余次数映射，不重试。未收尾令牌超过 10 分钟清除。`ClearPwdCache` 只清短期缓存并保留有效租约；应用中的清除保存密码操作还会撤销租约并清空钥匙串记录。Swift `pin-store-v1` 协议与证书集合账号算法保持不变。

CMS 使用静态链接 OpenSSL 完成基础密码运算，保留兼容 ASN.1 编码：SHA-1/SHA-256、无 signedAttrs、仅叶证书、issuerAndSerialNumber，以及默认 rsaEncryption OID 的差别。`includeCertOption` 接受 0～3 并保持既有叶证书行为，不代表原厂所有选项语义。

## 构建和测试

```sh
SKIP_PACKAGE=1 make app
make test
make test-assistant-layout
make tls
make bridge
```

构建需要 Xcode 命令行工具及 Rust/Cargo，不需要 Python 或 Node。发布工具由 `scripts/ProjectTools.swift` 提供，`scripts/project-tool.sh` 按需编译到 `build/tools/`，用于依赖许可、包结构检查、版本选择及增量补丁。依赖锁定于 `rust-transport/Cargo.lock`，默认使用 `~/.cargo/bin/cargo`，可通过 `CARGO` 指定。

开发端到端测试仍需 Node 作为 TLS/WebSocket 测试客户端；硬件桩用 Swift 编译，Rust 进程单元测试使用系统 shell。旧 JavaScript 后端已删除，兼容性对照使用 `tests/fixtures/legacy-compatibility.json` 的固定证书、CMS 和信封样本，并与系统 OpenSSL 交叉解密；其中私钥仅用于离线测试。测试不读取真实钥匙串。`make test-pin-store` 是单独的真实钥匙串测试，只使用随机测试服务名。

独立 `make bridge` 会枚举实物；未接入 Swift 管道时不能保存钥匙串密码。手动指定路径示例：

```sh
rust-transport/target/release/usbkey-transport \
  --native-worker "$PWD/rust-transport/target/release/usbkey-worker" \
  --probe "$PWD/build/ft3000gm-hid-probe" \
  --signer "$PWD/build/ft3000gm-signer" \
  --port 20443 \
  --cert "$PWD/.local/tls/localhost.crt" \
  --key "$PWD/.local/tls/localhost.key"
```

可选 `--trust-store`、`--log` 指定信任库和审计路径，`--parent-pid` 跟踪主应用。构建检查包内架构、系统动态库依赖、许可，以及不存在 Python/Node/JavaScript 运行文件；构建不会安装或发布应用。

## 排障与验证边界

日志目录为 `~/Library/Logs/广东电力USBKey助手/`。审计采用脱敏字段；transport 标准输出与错误由应用写入 `transport.log`，超过 1 MB 时清空重写。

在日志目录放置 `.capture-certificate-selector-once` 后，被拒绝的证书筛选可一次性记录 `type` 和 `condition` 到 `rejected-certificate-selector.json`，随后删除标记；超过 4 KiB 的单值只记类型和长度，不记证书内容。

离线测试覆盖网络限制、状态期限、证书字段/筛选、12 组 CMS 字节对照、AES-128/256 互操作、PIN 单次错误与租约、多设备及拔插通知、断线/退出清理。macOS 12.0 是构建部署目标，不能据此声称已在 macOS 12 实机复测；实物 PIN/签名/解密、真实钥匙串及目标网站应单独记录验证结果。
