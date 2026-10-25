# 可行性结论

## 结论

可以做 macOS 原生移植，但不是“转换 DLL”。实物确认后，正确的实现是重写两层：

1. 用 macOS IOKit HID 重建飞天 FT3000GM 的设备访问层；设备打开、证书读取、挑战应答式 PIN 验证和 RSA 私钥运算已经实现。
2. 用 macOS 本地服务重建 NETCA WebSocket/JSON-RPC 浏览器接口；网页桥已经覆盖目标登录页的证书读取、`SignedDataSign` 和 `EnvelopedDataEncrypt`。

页面侧可以保持原有 JavaScript 调用协议。Windows GUI、ActiveX、NPAPI、CSP/CNG 注册和 Inno Setup 安装逻辑都不应移植。

## 已从原包确认

| 层 | Windows 文件 | 作用 | macOS 对应实现 |
| --- | --- | --- | --- |
| 浏览器兼容 | `npffax.dll` | Firefox 中承载 ActiveX | 不移植；现代浏览器走 WSS |
| 浏览器桥 | `NetcaWebSocketServer.exe` | loopback WSS 与 JSON-RPC 路由 | 原生 launch agent/菜单栏服务 |
| 通用密码 | `NETCA_CRYPTO_JSONRPC.dll` | 证书、签名、验签、信封接口 | 精简实现站点实际使用的方法 |
| NETCA 设备适配 | Linux `libftsjk1104gprov.so`、`libft3000gmprov.so` | NETCA 通用设备接口到 FT3000GM SKF/USB | 原生适配器 |
| USBKey 设备层 | Linux `libft3000gmprov.so` | `libusb` 到 `096E:0317`，使用 bulk transfer | IOKit USBHost 或 macOS libusb |
| Windows 备用设备 | `NetcaDingXin.dll`、`SKF_T1.dll` | 兼容安装包内的鼎信 `2FD0:1000` | 非本次实物，暂不移植 |
| PDF/签章 | 多个 `.api`、`.ocx`、PDF DLL | PDF 签章和专有文件处理 | 独立的后续阶段 |

实物枚举结果是飞天 `USB TOKEN 3000GM`，制造商 `FT`，VID/PID `096E:0317`。IORegistry 同时显示 USB 和 HID 接口；PC/SC 上下文可用但 reader 列表为空。因此这枚 Key 的主路径不是 CCID/PCSC。

NETCA 5.4.0 Linux ARM64 包恰好含 FT3000GM 配置与实现：设备配置匹配 `vid_096e&pid_0317`，`libft3000gmprov.so` 依赖 `libusb-1.0.so.0`，并使用 `libusb_claim_interface`、`libusb_bulk_transfer` 等函数。Linux ELF 不能直接在 macOS 装载，但其设备匹配、SKF 行为和 USB 访问结构可作为洁净室移植参照。这比原安装包中的鼎信备用驱动更接近实物。

目标网站当前加载 `/portal/netcawebsocket.js` 和 `/portal/netcapki.js`，连接 `wss://127.0.0.1:10443` 或 `wss://127.0.0.1:20443`。本机实测这两个端口均拒绝连接，说明现在缺少的不是网页插件，而是本地 NETCA WSS 服务及其 FT3000GM 后端。

登录页的证书流程已定位：前端取得 USBKey 证书并签名随机数，随后向 `/cert/login` 提交 `verifyCode`、`verifyKey`、`certValue`、`signValue`、加密后的 `certPassword` 和 `random`。这意味着第一阶段只需覆盖证书枚举、随机数签名和 WSS 兼容层，不必先移植 PDF 签章全套功能。

## 已完成的只读设备路径

实物通过 64 字节 HID 报告传输，每帧含总长度、偏移、分片长度和最多 58 字节载荷。当前程序只执行下列公有、只读流程：

1. 选择主目录 `3F00`；
2. 枚举并选择应用目录 `DF_1F01`；
3. 选择并读取元数据文件 `F0FF`，长度 `0x320`；
4. 选择证书文件 `3002`，读取文件并跳过两字节长度头；
5. 用 macOS Security.framework 解析得到的 1622 字节 DER 证书。

实测上述选择和读取均返回 `9000`，且未调用 PIN、认证、签名、密钥生成、证书更新或写入指令。

## 已完成的签名路径

实物证书已确认为 RSA-2048，网站 `algo: 4` 已由其当前 `netcapki.js` 确认为 `SHA256withRSA`。安装包中精确匹配设备的 `FT3000GMProv.dll` 4.3.22.124 导出 `DeviceVerifyPwd` 与 `DeviceSign`，其二进制实现给出了完整的挑战应答和签名 APDU。

macOS 签名助手现按该实现执行 MD5(PIN) 派生、双密钥 3DES-ECB 挑战加密、用户 PIN 验证，以及 RSA PKCS#1 私钥运算。WSS 层构造标准分离式 CMS，内嵌当前证书，并在返回前执行 RSA 公钥验签。

## 仍待真实登录验证的部分

- 用用户本人输入的正确 PIN 完成第一次实物签名，确认设备返回值方向和 PKCS#1 行为与旧驱动一致；
- 确认目标登录业务代码最终读取的成功响应字段。桥同时返回常见的兼容字段，真实请求日志用于收敛；
- 验证 `/cert/login` 服务端接受生成的 CMS。验证码和登录提交始终由用户操作。

## 推荐里程碑

1. 插卡运行 `make probe`，确认 IOKit 中稳定出现 `096E:0317`；当前已通过。
2. 用 IOKit HID 还原只读设备子集；设备发现和 DER 证书加载已经通过。
3. 实现 loopback WSS 的版本探测、`IsInsertKey`、公有证书读取与兼容性 `GetCertList`；已经完成目标页面实测。
4. 实现 PIN 验证与 `SignedDataSign`；实物登录已成功，私钥运算结果会在返回页面前通过证书公钥自检。
5. 实现 `EnvelopedDataEncrypt`；Windows 成功流量确认本网站实际使用 AES-128-CBC、SubjectKeyIdentifier 接收方和 Base64 传输输入，macOS 输出已按该契约重做并通过 OpenSSL 离线解析与解密验证，待目标业务控件复测。
5. 完成 loopback WSS 的证书信任与 Origin 白名单，对接实际电力交易页面；证书信任与白名单已完成，待一次真实登录闭环。
6. 登录与交易签名通过后，再评估 PDF 签章和投标文件加密模块。

## 替代路径

若 NETCA 或飞天能提供 FT3000GM 的 macOS/PKCS#11/SKF SDK，这是最低风险路线。通用的飞天 ePass macOS 驱动不能仅凭品牌名假定兼容；必须明确支持 `096E:0317`/`USB TOKEN 3000GM`。现有 NETCA Linux ARM64 包不能直接在 macOS 运行，但它已经确认支持同一实物型号，是目前最强的可移植证据。
