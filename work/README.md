# work/ — 本地逆向与取证目录

这个目录保存 NETCA / 网证通客户端逆向分析过程中解包出来的东西：Windows 安装器 payload、DLL、配置、抓包与逐步记录。它**不纳入版本库**（见根目录 `.gitignore`），因为总量约 1.5 GB，且都是可重新解包得到的中间产物。

主要内容：

- `rea-full-client-20261019/`（约 1.0 GB）：REA 客户端完整解包，用于核对网页 SDK 与本地插件的交互。
- `gdpower-enveloped-adapter/`（约 424 MB）：数字信封适配的取证目录，含 `scope.md`、`evidence/`、`findings.md`、`paths.md`、`timeline.md`，以及解包出的 `NETCA_CRYPTO.dll` 等。
- `gdpower-decrypt/`：解密插件的 websocket 服务端解包。
- `login-monitor-*` / `quotation-monitor-*` / `compat-first-four-*`：诊断脚本运行产生的记录。

构建**不再**依赖本目录：应用包内嵌的信任库已经抽取成 `vendor/netca/netca-trust.sqlite`（60 KB，随仓库提交），由 `scripts/build_release.sh` 引用。

如果确实需要重新生成那个信任库：

```sh
cp work/gdpower-enveloped-adapter/extracted-crypto-20260907/commonappdata/NETCA/certs/trust \
   vendor/netca/netca-trust.sqlite
shasum -a 256 vendor/netca/netca-trust.sqlite
```

期望的 SHA-256 是 `cac6ffa9d75178e9ca401aced36c3ff3792dfe91e037e170f7a1ea454fb06b8c`。
