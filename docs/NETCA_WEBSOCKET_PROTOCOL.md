# NETCA 浏览器协议记录

2026-10-19源码新增认证、返回契约、设备通知和证书选择改进，详见 [实现与验证说明](2026-10-19_前四项兼容改进.md)。这部分新增行为尚未做实物PIN或网站复测。

## 连接

官网测试页的 `netcawebsocket.js` 依次尝试：

```text
wss://127.0.0.1:10443
wss://127.0.0.1:20443
```

WebSocket 子协议为 `crypto-jsonrpc-protocol`。

## 请求信封

```json
{
  "requestVersion": 1,
  "requestOrigin": "45B45638-A006-4cf1-A298-816B376D867E",
  "requestId": 1,
  "requestQuery": {
    "function": "GetVersionInfo1",
    "param": {}
  }
}
```

某些扩展模块还会在 `requestQuery` 中加入 `appName`，例如 `SignatureCreator`、`KeyXClientApp` 或 `CNCABidFile`。

## 响应信封

成功：

```json
{
  "responseVersion": 1,
  "requestVersion": 1,
  "requestOrigin": "45B45638-A006-4cf1-A298-816B376D867E",
  "requestId": 1,
  "responseResult": { "status": 0 },
  "responseEntity": {}
}
```

失败：

```json
{
  "responseVersion": 1,
  "requestVersion": 1,
  "requestOrigin": "45B45638-A006-4cf1-A298-816B376D867E",
  "requestId": 1,
  "responseResult": {
    "status": -11000,
    "msg": "数字证书服务连接失败"
  }
}
```

## 已识别方法

基础登录/签名相关方法包括：

- `GetVersionInfo1`
- `IsInsertKey`
- `GetCertList`
- `GetCertStringAttribute`
- `VerifyKeyPwd`
- `Sign`
- `SignHash`
- `VerifySignature`
- `SignedDataSign`
- `SignedDataVerify`
- `ClearPwdCache`
- `MonitorDevice`

其它模块还暴露 PDF 签章、数字信封、证书更新、设备数据区和 `CNCABidFile` 文件签名/加密接口。第一阶段只实现电力交易页面实际调用的最小集合。

## 当前 macOS 桥

`server/netca_readonly_bridge.mjs` 实现以下方法：

- `GetVersionInfo1`、`GetVersionInfo`、`GetClientVersionInfo`
- `IsInsertKey`
- `GetCertStringAttribute`，仅限 `id: -1` 的公有证书编码读取
- `GetCertList`，返回全部有效设备证书的 `certInfo`，含 `deviceCount/certCount`，保留 `certList/certs` 别名
- `MonitorDevice`，按连接订阅并推送设备插入/拔出事件；断线取消订阅
- `SignedDataSign`，支持登录页的显式 `algo: 4` 和业务报价控件省略 `algo` 的模式。两者都先 Base64 解码 `data.text`，生成无 signedAttrs、只携带叶证书、以 issuerAndSerialNumber 标识签名人的分离式 CMS；登录使用 SHA-256，业务省略算法时按 Windows 成功流量使用 SHA-1。
- `EnvelopedDataEncrypt`，支持目标页两种实测组合：直接提供接收方 RSA 证书并传 `algo: -1`；或传 `cert.type: device`、`CertType='Encrypt'`、`algo: 0`，由桥按 KeyUsage 从 USBKey 选择加密证书。两者都先 Base64 解码 `data.text`，再生成 AES-128-CBC、SubjectKeyIdentifier 接收方格式的 CMS。
- `EnvelopedDataDecrypt`，解析页面返回的 CMS，按 SubjectKeyIdentifier 或颁发者/序列号匹配 `3002` 加密证书，由 FT3000GM 加密私钥解开 RSA-PKCS#1 v1.5 会话密钥，再完成 AES-128/256-CBC 解密。成功响应按 Windows 插件契约返回 `clearValue` 与 `clearEncodeType: "base64"`；不支持把明文写入文件。

本地集成测试已验证 `GetCertStringAttribute` 返回 `responseResult.status: 0` 和证书编码。`SignedDataSign` 的登录与业务两种输出已用 Windows 成功日志中的同一证书和签名值重建，CMS 均逐字节完全相同。`EnvelopedDataEncrypt` 生成标准 CMS EnvelopedData，以证书 SubjectKeyIdentifier 标识接收方，使用 RSA-PKCS#1 v1.5 封装随机 AES-128 密钥；离线测试已用对应 RSA 私钥成功解密并逐字节还原原文。`EnvelopedDataDecrypt` 已通过 AES-128/256 离线测试，并由实物 FT3000GM 完成一次 AES-128 硬件往返解密。成功响应分别返回页面读取的 `encryptValue` / `encryptValueType` 和 `clearValue` / `clearEncodeType`。其它方法统一返回“不支持”。

业务密码控件在数字信封成功后还会调用另一种 `SignedDataSign`：证书编码为空、`cert.type` 为 `device`、条件为 `CertType='Signature'`，省略 `algo` 和 `certPwd`，并传 `useSubjectKeyId: 0`。桥会选择 USBKey 的 `3001` 签名证书，按 Windows 成功流量的业务默认使用 SHA1withRSA，并对 `data.text` 的 Base64 解码结果签名；SignerInfo 使用颁发者和序列号且不含 signedAttrs。FT3000GM 不会跨短生命周期 HID 进程保留用户认证状态，因此 原有1.1.9设计在登录签名成功后建立内存认证租约；当前源码已统一签名/解密流程，租约绑定设备连接和完整证书集合，最近一次成功私钥操作后五分钟到期，用于紧随其后的报价解密和业务签名；网页的 `ClearPwdCache` 清除普通提示缓存，但不立即破坏该登录租约。租约仅存在于助手进程内存，超时、私钥操作失败、设备拔出/变化、证书集合变化或应用退出即清除；按用户要求，成功验证的密码现额外保存在macOS登录钥匙串，无应用层到期时间；不进入普通文件、日志、argv或环境变量。没有有效内存租约时先读取匹配证书集合的钥匙串记录，缺失时才显示macOS隐藏输入对话框。网页ClearPwdCache不删除持久记录，用户可从应用菜单“清除已保存的证书密码”删除。保存的密码被拒绝后只尝试一次并删除旧值。

## EnvelopedDataEncrypt 实测与兼容依据

页面日志确认请求形状如下：

```json
{
  "cert": { "encode": "<Base64 DER>", "type": "", "condition": "" },
  "algo": -1,
  "data": { "text": "<原始待加密字节的 Base64>" }
}
```

旧 DLL 的静态默认路径曾显示算法配置值 6，但用户提供的 Windows 成功流量证明本网站两种实际调用均输出 AES-128-CBC。动态成功流量作为最终兼容依据。目标页面的实际密码控件不附带证书编码，而是要求客户端从设备选取 `CertType='Encrypt'`；桥会解析证书 KeyUsage，排除仅可签名的 `3001`，选择具备 Key Encipherment/Data Encipherment 的 `3002`。macOS 实现返回页面实际读取的 `encryptValue`，并附带 `encData`、`envelopedData`、`envelopedDataEncode`、`cipherText` 和 `value` 兼容别名。

## 广东电力登录页实测顺序

在目标页面填写由用户自行输入的口令和验证码并点击登录后，脱敏审计日志确认调用顺序如下：

1. `GetCertStringAttribute`，`id` 为 `-1`；
2. 桥从 FT3000GM 的 `3002` 文件读出 1622 字节 DER，状态字为 `9000`；
3. 页面收到 2164 字符的 Base64 证书后调用 `SignedDataSign`；
4. `SignedDataSign` 的实测参数为 `algo: 4`、16 字符待签数据、`useSubjectKeyId: true`、`detached: 1`、`includeCertOption: 2`，并带有证书口令字段；
5. 第一轮只读测试按设计返回 `-11001`，页面显示证书认证失败；该失败已用于确认完整调用契约。

## FT3000GM 签名子协议

从安装包内 `FT3000GMProv.dll` 4.3.22.124 的 `DeviceVerifyPwd` 与 `DeviceSign` 还原得到：

1. `00 84 00 00 08` 从 Key 取得 8 字节挑战；
2. 对 PIN 字节计算 MD5，得到 16 字节的旧协议派生密钥；
3. 以双密钥 3DES-ECB、无填充加密挑战；
4. `00 20 00 00 08 || proof` 验证用户 PIN；
5. `00 2A 80 86 ... 80 01 01 21 || DigestInfo` 执行 RSA 私钥运算。

MD5 只属于该老设备的 PIN 挑战应答格式。登录页显式算法 4 使用 SHA-256；报价业务省略算法时，按 Windows 成功流量使用 SHA-1。

日志只记录字段结构和长度。证书口令、验证码、证书正文、待签原文与签名值均不落盘。

## 服务端安全约束

- 仅绑定 `127.0.0.1`，不监听局域网地址。
- 对 WebSocket `Origin` 做白名单校验，不能只信任固定的 `requestOrigin` 字段。
- TLS 私钥只允许当前用户读取；根证书安装必须由用户明确确认。
- PIN 不写日志、不落盘、不放入进程参数或环境变量；错误 PIN 不自动重试。
- 每次签名必须来自白名单 Origin，并由用户在网页输入口令后主动点击登录触发。
- 签名值返回网页前必须通过当前证书的 RSA 公钥自检。
