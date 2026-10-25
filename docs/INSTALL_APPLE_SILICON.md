# Apple 芯片 Mac 安装说明

## 系统要求

- Apple 芯片（M1、M2、M3、M4 或后续型号）
- macOS 12 或更高版本
- 飞天 FT3000GM USBKey（VID/PID `096E:0317`）
- 无需管理员权限（把应用拖入“应用程序”即可）

## 安装

1. 将 `广东电力USBKey助手-<版本>-apple-silicon.dmg` 复制到目标 Mac。
2. 双击打开镜像，把“广东电力USBKey助手”拖到同一窗口里的“应用程序”文件夹。
3. 推出镜像，从“应用程序”或启动台打开应用。应用位于 `/Applications/广东电力USBKey助手.app`。
4. 插入 USBKey，确认本地服务、USBKey、签名证书和本地证书信任四项均显示正常。
5. 点击“打开广东电力市场登录页”，由用户本人输入证书密码和验证码。

从镜像拖出来的应用归当前登录用户所有，因此后续自动更新不会再要求管理员密码；如果直接从镜像或下载目录双击运行，macOS 会把它放在只读的临时目录里，应用会提示先移动到“应用程序”。

应用会在当前用户目录生成一套仅用于 `localhost`/`127.0.0.1` 的独立 HTTPS 证书和私钥，并把该证书加入系统信任。不同 Mac 不共用本地私钥。USBKey 私钥始终留在硬件内。

旧版本（1.1.18 及更早）发布的是 `.pkg` 安装包，仍可双击安装；这类安装第一次自动更新时会请求一次管理员授权，之后不再请求。

## 未签名版本提示

当前构建机没有 Apple Developer 的 `Developer ID Application` 证书，因此应用使用临时签名，镜像没有正式发行签名或 Apple 公证。

如果系统提示无法验证开发者，可在 Finder 中按住 Control 点击应用后选择“打开”；若仍被拦截，请到“系统设置 → 隐私与安全性”确认打开。正式对外分发前，建议使用 Developer ID 对应用签名并提交 Apple 公证。

## 日志与隐私

- 运行日志：`~/Library/Logs/广东电力USBKey助手/bridge.log`
- 配置目录：`~/Library/Application Support/广东电力USBKey助手/`
- 日志不记录证书密码、验证码、待签原文、证书正文或签名值。
- 应用不会缓存 USBKey 密码。

## 卸载

终端执行：

```sh
sudo "/Applications/广东电力USBKey助手.app/Contents/Resources/uninstall.sh"
```

卸载程序会移除应用、自动启动项、本地 TLS 证书信任和应用配置；运行日志会保留，便于故障复盘。

## 校验安装镜像

同目录的 `.sha256` 文件记录镜像 SHA-256。可执行：

```sh
shasum -a 256 -c "广东电力USBKey助手-<版本>-apple-silicon.dmg.sha256"
```
