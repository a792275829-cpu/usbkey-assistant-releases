# 应用整体代码评审（2026-10-23）

本报告针对当前工作区源码评审，不是相对某个 Git 提交的差异评审。工作区源码目录当前均显示为未跟踪。初次评审没有改动业务代码，后续修复见文末处理记录；未执行发布、系统安装、系统证书信任修改或真实钥匙串操作。

## 范围与方法

检查 Swift 界面、状态与更新逻辑、钥匙串通道、进程执行器，Rust TLS/WSS 服务、IPC、业务队列、认证状态机、证书选择和 CMS/数字信封处理，C HID 探测与签名助手，以及构建、增量补丁、安装和发布脚本。JavaScript 对照实现用于核查兼容意图。结合现有离线测试及临时仿真助手复现异常路径。

以下三项为本轮确认的问题；没有把硬件或网站未验证路径直接认定为缺陷。

## 1. [P2] 超时后完成的状态查询不能更新快照

位置：`rust-transport/src/main.rs:220–245`，以及 IPC 回复处理 `main.rs:526–529`。

`snapshot` 只在 `status_response()` 的三秒等待内收到成功回复时更新。等待超时会丢弃请求 future，`PendingGuard` 删除 pending 条目。worker 此后即使正常完成扫描，迟到回复也被 IPC reader 丢弃，无法更新快照。

当每次完整扫描都超过三秒时，首次启动后的状态查询会一直返回 503；如果先前有快照，则持续返回旧设备、旧证书与旧选择。慢设备或多设备逐台读取均可能触发。这会影响界面状态、设备下拉框和诊断结果。

复现：以临时 TLS 启动真实 debug transport/worker，仿真四枚设备，每台证书探测等待四秒，各自未超过 helper 的十秒上限。第一次 `/status` 在 3.01 秒返回 503；等待十四秒，确保后台完整扫描结束，再次查询仍在 3.01 秒返回 503。将助手读取延迟改为零后，状态正常返回 200。

建议让状态完成消息独立更新快照，不依赖 HTTP 请求是否仍在等待；同时合并进行中的状态查询，避免反复刷新积累重复扫描。

## 2. [P2] 设备切换返回失败后仍会修改实际选择

位置：`rust-transport/src/main.rs:206–208`，`rust-transport/src/worker_main.rs:522–532`。

控制接口十秒超时只取消父进程的等待，不撤销已经进入 worker 队列的任务。`selection` 与 `clear` 均没有 WebSocket connection，因此 actor 的连接关闭检查也不会跳过它们。排在长时间硬件操作或 PIN 输入后面的切换，会先向界面返回 503，随后仍执行 `core.select()`。

复现：让上述慢速状态扫描占用 actor，随后 POST `/selection` 选择 `b1`。接口在 10.01 秒返回 503；等队列排空，恢复快速扫描，再 GET `/status`，返回 `selectedDeviceId: "b1"`。即请求已被报告失败，实际设备仍被切换；后续未指定证书的签名会使用该选择。清除密码请求也有相同的迟到执行语义。

建议给控制任务传递截止时间/取消标识，在实际变更前检查；若操作已经开始且不能取消，应返回可追踪的处理中状态，使界面最终能确认结果，而不是把等待超时呈现为操作失败。

## 3. [P2] 增量补丁遗漏只有权限变化的文件

位置：`scripts/build_patch.py:153–156`。

`files()` 已收集 SHA-256、大小和 mode，但 `changed` 只比较 SHA-256。因此某个可执行文件内容不变、只从 0644 修为 0755 时，不会进入补丁文件列表。客户端沿用旧权限，仍可能无法启动该助手，却已升级版本号；完整镜像安装则具有正确权限。

复现：创建 1.0.0 与 1.0.1 两个临时应用，其中 `Contents/MacOS/helper` 字节相同、权限分别为 0644 和 0755。调用真实 `scripts/build_patch.py --force` 后，补丁仅包含 `Contents/Info.plist`，遗漏 helper。

建议同时比较文件内容与 mode，并补充权限变更的补丁生成/应用回归验证。

## 实际验证结果

- `make test-process-runner test-assistant-status test-assistant-update test-desktop-entry`：通过。
- `make test-assistant-layout test-assistant-install`：通过；安装测试仅操作临时目录和测试镜像，没有替换真实安装。
- `cargo test --locked --manifest-path rust-transport/Cargo.toml`：整组重跑通过（transport 19 项、worker 1 项）。首轮 transport 为 18/19，`deadline_kills_and_waits_for_helper` 在读取仿真助手 PID 文件时出现 NotFound；该项单独重跑和整组重跑均通过。保留此不稳定性记录，不认定首轮全部通过，也未据此推断生产进程超时逻辑有缺陷。
- `cargo build --locked --manifest-path rust-transport/Cargo.toml`：debug 构建通过。
- `node scripts/test_rust_transport.mjs` 与 `node scripts/test_native_backend.mjs`：通过，包含仿真硬件、私有 IPC、CMS 字节对照与数字信封互操作验证。
- 本报告三项定向离线复现：均确认。

没有执行 `make test` 全量、真实下载校验、真实 PIN 输入/签名/解密、真实钥匙串读写、目标网站登录、管理员授权更新或真实应用卸载。C HID 交互结论限于静态代码检查，不能替代实物验证。

评审阶段仅新增本文档；后续用户要求修复时同步更新 CHANGELOG 的“未发布”部分。

## 修复记录（2026-10-23）

三项问题均已修复：

1. 状态刷新由独立后台任务完成，并发 HTTP 请求共享同一次读取；超过 HTTP 三秒等待仍会更新成功快照并通知等候者。
2. 控制任务在实际开始前经私有 `controlId` 通道向 transport 请求许可。许可确认与超时撤销共用 pending 锁：排队十秒仍未获准的任务返回 503，队列排空后不会执行；已获准的任务等待真实操作结果。Swift 的对应 curl/进程等待同步调整为 150/155 秒，覆盖排队和钥匙串交互。
3. 补丁生成比较完整的文件元数据（内容摘要、大小、权限），将只有执行权限变化的文件也加入文件清单、基线清单及归档。

新增 `tests/BridgeControlTests.py` 三项端到端回归，覆盖迟到状态写入缓存、并发读取合并、超时切换与清理不执行、已开始清理超过十秒仍返回真实结果；仅使用临时 TLS、仿真设备和模拟钥匙串管道。新增 `tests/PatchManifestTests.py` 验证权限变更入包，并在 Swift 安装测试中实际生成、暂存、安装权限补丁，确认 0644 修复为 0755 且应用签名复核通过。两组 Python 测试已加入 Makefile 测试流程。

修复后验证：`make test` 全量通过（包括 transport 19 项、worker 1 项 Rust 单元测试及新增回归），`make test-assistant-layout`、严格 Clippy（所有 targets、warnings 作为错误）、`cargo fmt --check` 均通过。Swift 临时目录安装测试中的真实 DMG 和权限补丁均通过签名复核；不代表真实下载安装包、实际管理员授权或实物/网站验证。没有更新版本号或发布安装包。
