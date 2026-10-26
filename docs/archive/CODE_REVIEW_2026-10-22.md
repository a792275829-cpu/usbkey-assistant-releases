# Rust 后端代码评审（2026-10-22）

## 评审范围

| 文件 | 行数 | 说明 |
| --- | --- | --- |
| `rust-transport/src/main.rs` | 539 | TLS/HTTP、WebSocket、supervisor、IPC |
| `rust-transport/src/worker_main.rs` | 472 | 业务进程入口、RPC actor、审计日志、钥匙串通道 |
| `rust-transport/src/native/rpc.rs` | 524 | JSON-RPC 方法实现 |
| `rust-transport/src/native/auth.rs` | 236 | PIN/认证编排 |
| `rust-transport/src/native/crypto.rs` | 448 | DER 编解码、CMS、数字信封 |
| `rust-transport/src/native/certificates.rs` | 519 | 证书模型、筛选语言、选择 |
| `rust-transport/src/pin_session.rs` | 498 | 认证状态机 |
| `rust-transport/src/device_process.rs` | 543 | 硬件助手进程管理 |

方法：静态通读 + 与迁移前的 Node 实现（`server/`）逐点对照 + 结合 `scripts/test_native_backend.mjs`、`scripts/test_rpc_sessions.mjs` 的断言判断意图。未评审：`src/*.c` 硬件助手、TLS 证书签发流程、安装器脚本。

## 总体结论

迁移质量高于一般重写：PIN 全程走 stdin 不落 argv、`Zeroizing` 覆盖面完整、硬件操作有"单次授权令牌"围栏、子进程独立进程组 + 硬超时 + 输出上限、错误只回固定标识不外泄输出、CMS 逐字节对齐旧实现并有对照测试。下面 3 条值得改，其余为低优先级。

---

## 一、建议处理

### R1 [中] `/status`、`/selection` 会排在长耗时任务后面，且父进程侧没有超时

位置：`worker_main.rs:418-467`（单个串行 actor）、`main.rs:64-85`（`Worker::request` 无超时）、`app/USBKeyAssistant.swift:584`（curl `--max-time 15`）

`jobs_rx` 只有一个消费者：`/status`、`/selection`、`/pin-cache/clear` 和所有 RPC 排在同一个队列里串行执行。签名流程里 PIN 弹窗的最长时限是 120 秒（`device_process.rs:50-58`）。因此：

- PIN 弹窗挂起期间点"刷新"，`/status` 要等弹窗结束才被处理；
- 但 Swift 侧 `curl --max-time 15` 先超时，界面先显示"检查中"，随后落到 `服务未在等待时间内就绪` / "未连接"；
- 用户看到的是"UKey 掉了 / 服务坏了"，实际在等密码输入。这是最容易在实测中遇到、也最容易被误判成硬件故障的一类现象。

建议：`/status` 不排队。维护一份状态快照（每次 `scan()` 或成功 `status()` 后更新），HTTP `/status` 直接读快照返回；同时给 `Worker::request` 加一个与调用方 curl 预算匹配的超时（例如 10s），超时返回 503 而不是无限等。`/selection` 依赖实时枚举，可以保留排队，但同样需要超时。

### R2 [中] 设备枚举没有缓存：空闲时每秒 fork 一次，每次 RPC 还要重新枚举

位置：`worker_main.rs:394-411`（1 秒一次 monitor）、`rpc.rs:34-57`/`76-125`（`inventory`/`devices`）、`rpc.rs:120-125`（`records`）

- 监控任务无条件每秒投递一次 `monitor` job → `scan()` → `probe --list-devices`，即每天约 8.6 万次进程创建，即使没有任何 WebSocket 订阅、没有插入设备。
- 同时 `records()` 不做缓存：`GetCertList`、`GetCertStringAttribute`、`SignedDataSign`、`EnvelopedDataEncrypt/Decrypt` 每次都重新 `--list-devices` + 每台设备一次 `--include-certificate`。一次"取证书 → 取属性 → 签名"大约 5~6 次 probe。
- 因为 actor 串行，扫描还会挤在业务请求前面，插着设备时（HID 枚举变慢）能感知到延迟。

建议：
1. 只在存在 `MonitorDevice` 订阅（或至少一个 WS 连接）时保持 1 秒扫描，否则退到 5–10 秒；
2. `inventory` 加 1 秒级 TTL 缓存，由 `scan()` 负责失效，`records()` 直接复用快照。

### R3 [中] PIN 弹窗换了运行环境且改了标题，本次迁移没有实测

位置：`device_process.rs:163-171`（osascript 命令与标题）、`device_process.rs:176`（`env_clear()`）

与旧实现相比有两处变化：

- `server/pin-session.mjs:7-8` 的标题是"广东电力USBKey助手"，Rust 版改成"USBKey 助手"——属于用户可见文案变更，`CHANGELOG.md` 里没记。
- 旧实现 `execFileAsync` 继承完整环境；Rust 版对 `prompt` 也执行 `command.env_clear()`，只留 `PATH`。`display dialog` 需要连接 GUI 会话，虽然会话归属由 launchd/kernel 决定、通常不受 env 影响，但 `HOME`/`TMPDIR` 被清掉后行为没有实测过。

本次启动的日志（`~/Library/Logs/广东电力USBKey助手/bridge.log` 中 `server_start mode=rust-native-worker`）之后还没有一次真实的签名记录，也就是说这条路径当前是"未验证"状态。

建议：先实测一次弹窗（能弹出、在最前面、中文正常、取消返回"用户取消了…"），确认后把标题变化补进 `CHANGELOG.md`；若想更稳，`env_clear()` 对 `prompt` 例外，保留 `HOME`。

---

## 二、建议改进（低优先级）

### R4 `includeCertOption` 只校验不生效，兼容说明在移植中丢失

`rpc.rs:431-439` 校验 0–3，但 `crypto::signed()`（`crypto.rs:255-261`）无条件把叶子证书放进 `[0]` 字段。旧实现同样如此，`server/rpc.mjs:212-217` 有明确注释说明这是"对齐抓包字节的兼容档，不代表原客户端所有选项都这样"。Rust 版把这个"为什么不实现"的解释丢了，后来人看到会当成 bug 去"修"，一修就破坏 `test_native_backend.mjs` 的逐字节相等断言。

建议：在 `crypto.rs:255` 或调用点补一段同义注释。

### R5 `ProcessGroup` 在子进程已被回收之后仍对 pgid 发 SIGKILL

`device_process.rs:132-139` 的 `Drop` 无条件 `kill(-pgid, SIGKILL)`，而 `execute()` 在 `try_join`（含 `child.wait()`）成功后才 `drop(group)`（`device_process.rs:240`）。此时子进程已回收，若组内没有残留后代，pgid 就处于可被复用状态。窗口极小（需要在 `wait` 与 `kill` 之间正好有进程拿到同一 pid 并新建同名进程组），实践风险可忽略，但属于"能修就修"的写法。

建议：仅在 `result.is_err()` 或已知存在后代（`prompt` 的 osascript 会拉起 System Events）时杀组；或改成先用 `try_wait` 轮询到退出、先杀组再 `wait` 回收。

### R6 `Session.attempts` 没有 TTL

`pin_session.rs:144-147`：`attempts` 只在 `commit`/`finish_without_pin`/`fail` 时移除。64 条上限一到，后续 `begin` 全部返回 `busy`，只能重启进程。当前调用方（本仓库自己的 `auth.rs`）都会配对收尾，暂时打不满；但这是个只会向坏的方向发展的计数器。

建议：`expire()` 里顺带清掉 `epoch` 过期或创建超过 N 分钟的 attempt。

### R7 审计日志每次 open + chmod

`worker_main.rs:98-117`：每个请求写两条（`rpc_request`/`rpc_response`），每次都 `open`+`set_permissions`+`write`+`close`，且是在 async 线程里做同步文件 IO。量级不大，但完全可以省。

建议：进程内保持一个 `File` 句柄（`Mutex<File>`），权限只在创建时设一次。

### R8 每个请求编译两个正则

`certificates.rs:405-408`：`Regex::new` 在 `matching()` 内部，`matching()` 每次请求都会调用。建议 `OnceLock`。

### R9 版本号三处来源

`worker_main.rs:30` 的 `VERSION = "1.1.15"` 与 `app/Info.plist` 的 `1.1.18` 并存。注释说明是"面向上游兼容"的冻结值，但没有任何机制防止有人误改，也没有地方说明"这个值不跟应用版本走"。

建议：加一句"改动前先确认网站是否校验版本"，或把它挪到与 `Cargo.toml` 无关的常量模块。

### R10 调试钩子留在生产路径

`worker_main.rs:118-153` + `rpc.rs:254-260`：只要日志目录里存在 `.capture-certificate-selector-once`，就会把失败请求的证书 selector（`type`/`condition`，单值上限 4KB）写进 `rejected-certificate-selector.json`。有测试覆盖、只写 selector 不写证书内容，风险可控，但它是靠"手动 touch 一个文件"触发的隐式开关。

建议：要么用 `cfg(debug_assertions)` 关掉，要么在 `docs/` 里写清楚这是排障开关。

---

## 三、小问题（nit）

- **N1** `main.rs:199`：`result["status"].as_u64().unwrap_or(503) as u16` 静默截断。worker 目前只回 200/400/503，建议 `u16::try_from(...).unwrap_or(503)` 或限定枚举。
- **N2** `worker_main.rs:270`：`from_raw_fd(3)` 前没有校验 fd 3 是不是 socket。fd 传错时会得到一串 "Bad file descriptor"，而不是一条清楚的启动错误。
- **N3** `requiresSelection` 恒为 `false`（`rpc.rs:226`）：`reconcile()` 会自动选中第一台设备，所以 `devices.len()>1 && selected.is_none()` 永不成立，`AssistantStatus.swift` 里"请选择本次使用的 USBKey"分支不可达。与旧实现一致，界面靠下拉框显示当前选择，功能正常——仅记录，不必改。
- **N4** `app/USBKeyAssistant.swift:461`：transport 的 `stderr` 指向 `nullDevice`，`main.rs:508` 的 "listening on …" 和启动期错误都看不到。建议重定向到日志文件，排障时省事。

---

## 四、确认无问题（避免重复排查）

- PIN 生命周期：`begin/attempt/commit/fail` 的 epoch + binding 双重围栏正确；换设备、证书集变化、`fail` 都会 `invalidate` 并擦除缓冲；`clear_cached` 保留租约是刻意设计（旧版日志同样是 `cacheEntries:1, leasePreserved:true`）。
- 密钥材料：PIN 只经 stdin 进 helper，`Request::drop`/`write_task`/`writer_task`/`wipe()` 都有零化；日志只记元数据，`test_native_backend.mjs` 有"日志中不得出现 PIN 与明文 base64"的断言。
- 证书筛选语言：八个字段、`~` 只允许 `issuercn`、`&&` 与 `||` 拒绝、`invalidity/checkprivkey` 语义与 `server/certificates.mjs:96-97` 一致。
- 信封与签名：SKI 收件人、AES-CBC + PKCS#1 v1.5、解密后用公钥反算校验填充、签名后用公钥自检，都是对的。
- 边界：Origin 精确匹配 + 子协议校验、`Sec-WebSocket-Key` 长度校验、`max_message_size` 1MB、IPC 行上限、`to_bytes` 1KB 上限、`/selection` 要求 JSON 且无 Origin（跨站表单/预检过不去）。

---

## 五、验证缺口（建议本次手测覆盖）

1. PIN 弹窗在 Rust 版下能否正常弹出/置前/取消（R3）。
2. PIN 弹窗挂起时点"刷新"的表现（R1 的现场确认）。
3. 双设备插拔 + 下拉框切换后再签名，确认选中的是期望设备。
4. 签名过程中拔掉 UKey，确认返回"未发现所选 USBKey"且不残留 helper 进程（`pgrep -f ft3000gm-signer`）。
5. 连续 65 次"取消密码"后是否仍可继续使用（R6 的边界，可选）。

## 六、建议优先级

1. R1（可用性，用户最先遇到）
2. R2（资源与延迟，长期跑着影响明显）
3. R3（迁移未验证路径 + 文案变更补记录）
4. R4/R5/R6（写好注释与边界处理即可，不必现在改代码）
5. R7–R10、N1–N4（随手清理）

---

## 七、处理记录（2026-10-22 当日闭环）

| 项 | 状态 | 处理 |
| --- | --- | --- |
| R1 | 已改 | `/status` 3 秒上限 + 最近快照 + `stale:true`；`/selection`、`/pin-cache/clear` 10 秒上限；`test_native_backend.mjs` 增加“签名挂起时状态仍返回”回归 |
| R2 | 已改 | 设备枚举 1 秒 TTL 缓存（`inventory` / `inventory_fresh` / `forget_inventory`）；监控扫描只在有订阅时入队；增加“退订后不再探测”回归 |
| R3 | 已改 | 弹窗标题恢复为“广东电力USBKey助手”，`HOME` 仅对 `prompt` 保留；实物 PIN 弹窗仍需手测（见第五节） |
| R4 | 已改 | `rpc.rs` 与 `crypto::signed` 补充“兼容档”注释：`includeCertOption` 只校验，始终只带叶子证书 |
| R5 | 已改 | `ProcessGroup` 增加 `armed`；子进程已被 `wait()` 回收时不再对 pgid 发 `SIGKILL` |
| R6 | 已改 | `Attempt` 记录创建时刻，`expire()` 清理超过 10 分钟的未收尾令牌；新增单元测试 |
| R7 | 已改 | 审计日志复用单个追加句柄，权限仅创建时设置；写失败时丢弃句柄，下次重开 |
| R8 | 已改 | 两个筛选正则改为 `OnceLock` 进程内编译一次 |
| R9 | 已改 | 冻结版本常量改为带说明的 `VERSION`：与应用版本无关，改动需与网站同步 |
| R10 | 已改（保留开关） | 代码注释说明用途与触发方式，并在 `docs/RUST_TRANSPORT.md` 增加“排障开关”一节；不写入发行版构建差异 |
| N1 | 已改 | 状态码改用 `u16::try_from` |
| N2 | 已改 | 启动前校验 fd 3 为已连接的 Unix 套接字，报错为“私有通道不可用” |
| N3 | 仅记录 | `requiresSelection` 依赖 `reconcile` 自动选中首台设备，保持现状并加注释 |
| N4 | 已改 | transport 的 stderr 写入 `transport.log`（保留最近 1 MB），启动失败可见 |

验证：`cargo test`（19 项）、严格 Clippy、`scripts/test_native_backend.mjs`、`make test` 全量、`make test-assistant-layout`、`make test-assistant-update`、`make test-assistant-install` 通过；另用无 fd 3 与 fd 3 为普通文件两种方式启动 worker，确认新报错文案。仍待手测：实物 PIN 弹窗、双设备切换、签名中拔卡、真实 `/Applications` 下的旧版 PKG 首次升级授权。
