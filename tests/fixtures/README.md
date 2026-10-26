# 离线测试样本

- `DeviceHelper.swift`：编译成临时硬件桩，模拟证书枚举、PIN 失败与 RSA 操作，不访问 USBKey。
- `portal-certificate-selector.json`：网页使用的证书筛选条件。
- `legacy-compatibility.json`：删除旧 Node 后端之前生成的固定对照，包含测试证书及公开测试私钥、三个签名算法档的 CMS 字节和 AES-128/256 信封。`content` 是对应明文的 Base64；`certificates.*.fields` 是旧实现输出的字段。密钥仅用于离线兼容测试，不能用于任何真实凭据或生产用途。

12 组签名用例是三个算法档分别测试四个 `includeCertOption` 值，固定叶证书行为。固定样本避免测试时再次执行已删除的旧业务实现；系统 OpenSSL 交叉解密另行检查信封可用性。
