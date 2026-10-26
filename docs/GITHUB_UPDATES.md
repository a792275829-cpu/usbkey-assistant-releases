# GitHub 版本发布与应用更新

发布仓库：https://github.com/a792275829-cpu/usbkey-assistant-releases

该公开仓库保存应用源码、发布说明、安装镜像、增量补丁和校验文件。本地 `releases` remote 指向它。源码不包含本地证书与私钥、构建缓存及逆向取证产物，排除规则见 `.gitignore`。

应用启动、关闭窗口后重新打开时，在后台请求 GitHub `/releases/latest`。只提示版本号更高的正式版本，忽略草稿、预发布、相同版本和旧版本；无网络或 GitHub 限流不影响设备功能。应用菜单“检查更新…”可手动重试并查看错误。版本号支持 `v1.2.3`、`1.2.3` 等 2～4 段数字。

发现更新后，USBKey 标题下面显示红色 `new`。点击查看版本与更新说明。

## 安装方式：拖拽 DMG

发布的是 `USBKeyAssistant-<版本>-apple-silicon.dmg`，打开后把应用拖到“应用程序”文件夹即可，不需要安装器，也不需要管理员密码。

从镜像拖出来的应用归**当前登录用户**所有，后续可在可写的安装目录直接替换。PKG 安装留下的应用通常归 `root:wheel`，v1.1.20 起会根据安装目录的写权限决定是否授权，不再仅凭应用所有权要求密码。

| 安装来源 | 应用所有者 | 更新时授权 |
| --- | --- | --- |
| DMG 拖拽（推荐） | 当前用户 | 不需要 |
| 旧版 PKG | `root:wheel` | v1.1.20 起安装目录可写时不需要 |
| 直接从镜像/下载副本运行 | 只读、随机路径 | 更新时直接安装新版到应用程序目录 |

v1.1.20 起，只要安装目录可写，旧 PKG 的 root 所有应用也直接重命名替换；新副本归当前用户，不再仅因旧包的所有权请求授权。无法直接清理的旧包尽量移入废纸篓，失败时保留备份；安装目录不可写时仍需系统授权。

## 更新流程（点击一次后全自动）

窗口里只有一个“开始更新”按钮，点下去之后依次自动完成：

1. 选择资产：当前版本有对应增量补丁时下载补丁（`…-patch-from-<当前版本>.tar.gz`，通常几百 KB 到几 MB），否则下载完整安装镜像。
2. 下载并校验：核对 GitHub 提供的 asset SHA-256 摘要与字节数，任一不符立即停止。
3. 暂存：补丁解压后逐文件核对清单哈希；安装镜像用 `hdiutil attach -readonly -nobrowse` 只读挂载，取出镜像内的应用后立即卸载，旧版本发布的 PKG 仍用 `pkgutil --expand-full` 兼容处理。
4. 重新签名：对暂存副本执行 adhoc `codesign --force --deep --sign -`，并 `codesign --verify` 复核。
5. 替换：把暂存副本换成当前正在运行的应用（`Bundle.main.bundleURL`，通常是“应用程序”里的安装）；从只读副本运行时直接安装新版到可写的“应用程序”目录。
6. 复核版本：读取替换后 `Info.plist` 的版本号，与发布版本不一致即报错。
7. 自动重启：确认独立重启进程已启动，结束附属更新弹窗，再退出当前进程；辅助进程等待旧进程退出后，以新实例打开安装好的新版。v1.1.21 修复了未结束弹窗导致 AppKit 忽略退出、辅助进程持续等待的问题。

解压、挂载、校验和签名都在授权之前以普通用户身份完成；替换脚本只做 `ditto` + 两次 `mv`，中断时回滚旧版本。

失败时窗口显示原因并保留“重试”；补丁基线不符（本机被改动过、或跨版本升级）不会报错退出，而是自动改用完整镜像重来一次。

### 从镜像或下载目录直接运行

双击镜像里的应用（或双击下载目录里的应用）时，macOS 会把它放到随机的只读目录（AppTranslocation）运行，这样的副本既不能更新，也不该长期使用。应用启动时会提示“请先把应用安装到‘应用程序’”，点“移动并重新打开”即可复制到 `/Applications`（不可写时退到 `~/Applications`）并重启；v1.1.20 起更新窗口仍提供“开始更新”，下载后直接把新版安装到可写的应用程序目录并自动重启，无需先移动旧版。

## 资产命名

- 安装镜像：`USBKeyAssistant-<版本>-apple-silicon.dmg`
- 兼容安装包：`USBKeyAssistant-<版本>-apple-silicon.pkg`（仅供旧客户端识别，新用户请下载镜像）
- 增量补丁：`USBKeyAssistant-<版本>-patch-from-<基线版本>.tar.gz`
- 均附带 `.sha256`

GitHub 会改写中文附件名，因此发布脚本统一生成英文名；本地产物保留中文名称。tag 为 `v<版本>`。更新源由 `app/Info.plist` 的 `GitHubUpdateRepository` 配置，无需在客户端内保存 GitHub token。

PKG 何时可以停发：仍在运行 1.1.18 及更早版本的客户端只会查找 `-apple-silicon.pkg` 资产。等这些机器都升级到带镜像支持的版本后，用 `BUILD_PKG=0 make package` 构建、发布时不带 PKG。

## 增量补丁

`scripts/project-tool.sh patch` 对比“当前构建”与“上一个已发布产物”中的应用，只把有变化的文件打进压缩包，并写入 `patch.json`：

- `version` / `from`：目标版本与基线版本，客户端两项都必须匹配。
- `files`：每个被替换文件的新哈希与权限，安装前逐个校验。
- `base`：被替换文件在基线中的哈希，客户端先比对本机安装，不一致就放弃补丁。
- `remove`：新版本删掉的文件。

基线可以是 `.dmg`（只读挂载）、`.pkg`（展开）或一个现成的 `.app`。补丁只对“正好是基线版本且未被改动”的安装生效，这是有意为之：宁可回退到完整镜像，也不在不确定的字节上做替换。改动面超过镜像体积的 60% 时脚本直接放弃生成补丁。

补丁解包、校验和签名都在用户态完成；替换脚本由运行中的版本在安装时生成，因此旧版本即使没带这个脚本也能被更新。

## 发布下一版本

1. 修改 `app/Info.plist` 的 `CFBundleShortVersionString`。构建脚本默认从此处读取版本。
2. 运行 `make test` 和 `make package`。默认同时产出 DMG 与 PKG，`BUILD_PKG=0` 只产出 DMG，`SKIP_PACKAGE=1` 只构建应用。
3. 编写面向用户的更新说明文件。
4. 运行 `sh scripts/publish_release.sh /绝对路径/更新说明.md`。

发布脚本先校验镜像校验和，再自动挑选 `dist/` 中版本最高的旧产物（优先 `.dmg`）作为补丁基线（可用 `PATCH_FROM=1.1.18` 指定），调用 `ProjectTools.swift`，然后把镜像、补丁及各自 `.sha256`（以及存在时的 PKG）一并上传，最后把草稿发布为最新正式版本。补丁生成失败或体积不划算时会打印原因并只上传完整产物，不影响发布。

不要手工删除 `dist/` 里的历史产物：它们同时充当后续版本的补丁基线。若某个版本改动面过大（例如后端整体从 Node 换成 Rust），该版本只会发布完整产物，下一个版本才会重新出现小补丁。

## 验证

`make test-assistant-update` 覆盖数字版本比较、相同/旧版、草稿/预发布、HTTP 403/404/429/500、无效 JSON/链接、安装包摘要及大小不符（预览版本）；资产选择规则（镜像优先于 PKG、同名基线才用补丁、`forceFull` 走完整产物、没有镜像时回退 PKG）；以及运行位置分类（`/Applications`、`~/Applications`、普通可写目录、AppTranslocation、只读卷）。

`make test-assistant-install` 会真的造一个 DMG：挂载、取出镜像内的应用、重新签名、就地替换到临时目录中的“已安装”应用，再核对版本、文件内容、无残留备份与签名；同时验证版本不符时拒绝安装、以及从只读副本迁移到应用程序目录。

`make test-assistant-layout` 检查更新窗口与主界面布局。`scripts/test_native_backend.mjs` 附带两条后端回归：签名进行中（模拟 5 秒硬件操作）请求 `/status` 必须在 3 秒左右返回上次快照并带 `stale`；最后一个订阅断开后不再产生任何设备探测。

手工生成补丁（在临时目录进行，不触碰“应用程序”）：

```sh
sh scripts/project-tool.sh patch --app /tmp/new/App.app --from /tmp/old/App.app --out /tmp/out --force
```

可选的真实网络验证（下载当前公开镜像并校验，验证后删除临时副本，不执行安装）：

```sh
gh api repos/a792275829-cpu/usbkey-assistant-releases/releases/latest > build/latest-release.json
xcrun swiftc app/AssistantUpdate.swift tests/AssistantUpdateLiveTests.swift -parse-as-library -o build/assistant-update-live-tests
./build/assistant-update-live-tests "$PWD/build/latest-release.json"
```

`make test-assistant-restart` 使用真实 AppKit 更新弹窗复现旧退出逻辑卡住，再调用生产更新完成逻辑，验证旧进程退出以及 LaunchServices 自动打开临时测试应用。测试应用只记录启动标记，不启动硬件服务，也不修改已安装应用。
