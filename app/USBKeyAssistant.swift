import AppKit
import Foundation

private let applicationName = "广东电力USBKey助手"
private let loginURL = URL(string: "https://pm.gd.csg.cn/portal/#/user/login")!

#if !ASSISTANT_UI_TEST
@main
#endif
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private let updater = AssistantUpdater()
    private var availableRelease: GitHubRelease?
    private var updateCheckInProgress = false
    private var manualUpdateRequested = false
    private var updateButton: NSButton!
    private var updateMenuItem: NSMenuItem!
    private var updateWindow: AssistantUpdateWindow?
    private var bridgeProcess: Process?
    private var pinChannel: CertificatePinChannel?
    private var statusRefreshInProgress = false
    private var initialized = false
    private var statusCallbacks: [(AssistantStatus) -> Void] = []
    private var lastStatus: AssistantStatus?
    private var lastServiceFailure: String?
    private var loginOpenInProgress = false
    #if ASSISTANT_UI_TEST
    private var browserLaunchForTesting: (() -> Bool)?
    private var screenSizeForTesting: NSSize?
    #endif
    private var devicePicker: NSPopUpButton!
    private var devicePickerRow: NSStackView!
    private var organizationLabel: NSTextField!
    private var holderLabel: NSTextField!
    private var expiryLabel: NSTextField!
    private var loginButton: NSButton!
    private var diagnosticButton: NSButton!
    private var mainStack: NSStackView!
    private var contentSpacer: NSView!
    private var statusBadgeLabel: NSTextField!
    private var statusBadge: AssistantSurface!
    private var detailLabel: NSTextField!
    private var refreshButton: NSButton!
    private let fileManager = FileManager.default
    private var dataDirectory: URL {
        fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support", isDirectory: true)
            .appendingPathComponent(applicationName, isDirectory: true)
    }
    private var tlsDirectory: URL { dataDirectory.appendingPathComponent("tls", isDirectory: true) }
    private var certificateURL: URL { tlsDirectory.appendingPathComponent("localhost.crt") }
    private var privateKeyURL: URL { tlsDirectory.appendingPathComponent("localhost.key") }
    private var logDirectory: URL {
        fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs", isDirectory: true)
            .appendingPathComponent(applicationName, isDirectory: true)
    }
    private var logURL: URL { logDirectory.appendingPathComponent("bridge.log") }
    // stdout/stderr of the transport process (and of the worker it spawns):
    // "listening on …" and startup failures never reach the audit log.
    private var transportLogURL: URL { logDirectory.appendingPathComponent("transport.log") }
    private var transportLogHandle: FileHandle?

    static func main() {
        let application = NSApplication.shared
        let delegate = AppDelegate()
        application.delegate = delegate
        application.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMainMenu()
        buildWindow()
        checkForUpdates(nil)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                try self.prepareDirectoriesAndTLS()
                DispatchQueue.main.async {
                    self.initialized = true
                    self.loginButton.isEnabled = true
                    self.diagnosticButton.isEnabled = true
                    self.refreshStatus(nil)
                }
            } catch {
                DispatchQueue.main.async {
                    self.lastServiceFailure = "初始化失败"
                    self.statusBadgeLabel.stringValue = "检查失败"
                    self.detailLabel.isHidden = false
                    self.detailLabel.stringValue = "初始化失败：\(error.localizedDescription)"
                    self.diagnosticButton.isEnabled = true
                    self.resizeWindowToFit()
                }
            }
        }

        if CommandLine.arguments.contains("--background") {
            NSApp.setActivationPolicy(.accessory)
        } else {
            showWindow()
            offerRelocationIfNeeded()
        }
    }

    /// A copy launched from the mounted image (or from a quarantined download)
    /// runs read-only. Offer to move it into the application folder; updating
    /// can also install the downloaded new version there automatically.
    private func offerRelocationIfNeeded() {
        guard let guidance = InstallPath.classify(Bundle.main.bundleURL).guidance,
              window.attachedSheet == nil else { return }
        let alert = NSAlert()
        alert.messageText = "建议把应用安装到“应用程序”"
        alert.informativeText = guidance
        alert.addButton(withTitle: "移动并重新打开")
        alert.addButton(withTitle: "稍后")
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self, response == .alertFirstButtonReturn else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let destination = try UpdateInstaller.relocate(Bundle.main.bundleURL)
                    DispatchQueue.main.async {
                        do {
                            try UpdateInstaller.relaunchAfterExit(destination)
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { AssistantUpdateWindow.terminateForRelaunch() }
                        } catch {
                            self.showUpdateMessage("无法重新启动", detail: error.localizedDescription)
                        }
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.showUpdateMessage("无法移动应用", detail: error.localizedDescription)
                    }
                }
            }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow()
        checkForUpdates(nil)
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        stopBridge()
    }

    private func buildMainMenu() {
        let mainMenu = NSMenu()
        let applicationMenuItem = NSMenuItem()
        mainMenu.addItem(applicationMenuItem)

        let applicationMenu = NSMenu(title: applicationName)
        let certificateItem = NSMenuItem(title: "打开本地证书", action: #selector(openCertificate), keyEquivalent: "")
        certificateItem.target = self
        updateMenuItem = NSMenuItem(title: "检查更新…", action: #selector(checkForUpdates(_:)), keyEquivalent: "")
        updateMenuItem.target = self
        applicationMenu.addItem(updateMenuItem)
        applicationMenu.addItem(.separator())
        applicationMenu.addItem(certificateItem)
        let forgetPinItem = NSMenuItem(title: "清除已保存的证书密码", action: #selector(forgetSavedPins), keyEquivalent: "")
        forgetPinItem.target = self
        applicationMenu.addItem(forgetPinItem)
        applicationMenu.addItem(.separator())
        let quitItem = NSMenuItem(
            title: "退出\(applicationName)",
            action: #selector(quitApplication(_:)),
            keyEquivalent: "q"
        )
        quitItem.target = self
        quitItem.keyEquivalentModifierMask = [.command]
        applicationMenu.addItem(quitItem)
        applicationMenuItem.submenu = applicationMenu
        NSApp.mainMenu = mainMenu
    }

    @objc private func checkForUpdates(_ sender: Any?) {
        if sender != nil { manualUpdateRequested = true }
        guard !updateCheckInProgress else { return }
        updateCheckInProgress = true
        updateMenuItem?.title = "正在检查更新…"
        updater.check { [weak self] result in
            guard let self else { return }
            self.updateCheckInProgress = false
            self.updateMenuItem?.title = "检查更新…"
            let manual = self.manualUpdateRequested
            self.manualUpdateRequested = false
            switch result {
            case .success(let release):
                self.availableRelease = release
                self.updateButton.isHidden = release == nil
                if manual {
                    if release != nil { self.showUpdate() }
                    else { self.showUpdateMessage("已是最新版本", detail: "当前版本 v\(AssistantUpdater.currentVersion)") }
                }
            case .failure(let error):
                if manual { self.showUpdateMessage("无法检查更新", detail: error.localizedDescription) }
            }
        }
    }

    @objc private func showUpdate() {
        guard let release = availableRelease, window.attachedSheet == nil else { return }
        let controller = AssistantUpdateWindow(release: release, updater: updater)
        updateWindow = controller
        if let sheet = controller.window {
            window.beginSheet(sheet) { [weak self] _ in self?.updateWindow = nil }
        }
    }

    private func showUpdateMessage(_ title: String, detail: String) {
        guard window.attachedSheet == nil else { return }
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = detail
        alert.addButton(withTitle: "好")
        alert.beginSheetModal(for: window)
    }

    @objc private func quitApplication(_ sender: Any?) {
        NSApp.terminate(sender)
    }

    @objc private func forgetSavedPins() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result = self.run(executable: "/usr/bin/curl", arguments: [
                "--silent", "--show-error", "--fail", "--max-time", "150", "--noproxy", "*",
                "--cacert", self.certificateURL.path, "--request", "POST",
                "--header", "Content-Type: application/json", "--data-binary", "{}",
                "https://127.0.0.1:10443/pin-cache/clear",
            ], timeout: 155)
            DispatchQueue.main.async {
                self.showUpdateMessage(result.status == 0 ? "已清除证书密码" : "无法清除证书密码",
                    detail: result.status == 0 ? "已清除钥匙串中保存的密码及当前会话缓存，下次操作需要重新输入。" : "请确认本地服务正在运行，稍后重试。")
            }
        }
    }

    private func buildWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 840, height: 420),
            styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
            backing: .buffered, defer: false
        )
        window.title = Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ?? applicationName
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.appearance = NSAppearance(named: .aqua)
        window.backgroundColor = AssistantTheme.background
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self

        let content = AssistantSurface(fill: AssistantTheme.background, radius: 0, bordered: false)
        window.contentView = content
        let sidebar = AssistantSurface(fill: AssistantTheme.sidebar, radius: 0, bordered: false)
        sidebar.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(sidebar)
        let sidebarEdge = AssistantTheme.divider(vertical: true)
        content.addSubview(sidebarEdge)
        NSLayoutConstraint.activate([
            sidebar.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            sidebar.topAnchor.constraint(equalTo: content.topAnchor),
            sidebar.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            sidebar.widthAnchor.constraint(equalToConstant: 188),
            sidebarEdge.leadingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            sidebarEdge.topAnchor.constraint(equalTo: content.topAnchor),
            sidebarEdge.bottomAnchor.constraint(equalTo: content.bottomAnchor),
        ])

        let brand = NSStackView(views: [AssistantTheme.symbol("key.horizontal", size: 19, color: AssistantTheme.ink),
                                       AssistantTheme.label("USBKey", size: 16, weight: .semibold)])
        brand.spacing = 9
        brand.alignment = .centerY
        let overviewButton = AssistantButton("设备概览", style: .navigation, symbol: "square.grid.2x2",
                                             target: self, action: #selector(refreshStatus(_:)))
        overviewButton.isSelected = true
        overviewButton.toolTip = "查看并刷新 USBKey 信息"
        let workspaceCaption = AssistantTheme.label("工作区", size: 11, color: AssistantTheme.muted)
        let navigation = AssistantTheme.vertical([workspaceCaption, overviewButton], spacing: 10)
        overviewButton.widthAnchor.constraint(equalTo: navigation.widthAnchor).isActive = true
        updateButton = AssistantButton("new", style: .update, target: self, action: #selector(showUpdate))
        updateButton.isHidden = true
        updateButton.setAccessibilityLabel("发现新版本，查看更新")
        updateButton.toolTip = "发现新版本，点击查看更新说明"
        let branding = AssistantTheme.vertical([brand, updateButton!], spacing: 10)
        let sidebarTop = AssistantTheme.vertical([branding, navigation], spacing: 26)
        sidebarTop.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(sidebarTop)
        NSLayoutConstraint.activate([
            sidebarTop.topAnchor.constraint(equalTo: sidebar.topAnchor, constant: 54),
            sidebarTop.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 16),
            sidebarTop.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -16),
            navigation.widthAnchor.constraint(equalTo: sidebarTop.widthAnchor),
        ])

        diagnosticButton = AssistantButton("一键诊断", style: .navigation, symbol: "stethoscope",
                                           target: self, action: #selector(runDiagnostics))
        diagnosticButton.isEnabled = false
        let openLogButton = AssistantButton("查看日志", style: .navigation, symbol: "doc.text",
                                            target: self, action: #selector(openLog))
        let version = AssistantUpdater.currentVersion
        let appInfo = AssistantTheme.vertical([
            AssistantTheme.label("广东电力 USBKey 助手", size: 11, color: AssistantTheme.muted),
            AssistantTheme.label("v\(version)", size: 11, color: AssistantTheme.muted),
        ], spacing: 5)
        let sidebarRule = AssistantTheme.divider()
        let sidebarBottom = AssistantTheme.vertical([diagnosticButton!, openLogButton, sidebarRule, appInfo], spacing: 6)
        sidebarBottom.setCustomSpacing(16, after: openLogButton)
        sidebarBottom.setCustomSpacing(16, after: sidebarRule)
        sidebarBottom.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(sidebarBottom)
        NSLayoutConstraint.activate([
            sidebarBottom.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 16),
            sidebarBottom.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -16),
            sidebarBottom.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor, constant: -24),
        ])
        for view in [diagnosticButton!, openLogButton, sidebarRule] {
            view.widthAnchor.constraint(equalTo: sidebarBottom.widthAnchor).isActive = true
        }

        refreshButton = AssistantButton("刷新", style: .quiet, symbol: "arrow.clockwise",
                                        target: self, action: #selector(refreshStatus(_:)))
        refreshButton.toolTip = "重新读取设备与证书信息"
        statusBadgeLabel = AssistantTheme.label("检查中", size: 11, weight: .medium, color: AssistantTheme.muted)
        statusBadge = AssistantSurface(fill: AssistantTheme.hover, radius: 12, bordered: false)
        statusBadge.contain(statusBadgeLabel, inset: 6)
        let connection = NSStackView(views: [AssistantTheme.symbol("key.horizontal", size: 16, color: AssistantTheme.ink),
                                            AssistantTheme.label("连接状态", size: 13, weight: .medium),
                                            NSView(), statusBadge!, refreshButton!])
        connection.alignment = .centerY
        connection.spacing = 9
        let organizationCaption = AssistantTheme.label("所属单位", size: 12, color: AssistantTheme.muted)
        organizationLabel = AssistantTheme.label("正在读取 USBKey…", size: 20, weight: .medium)
        organizationLabel.maximumNumberOfLines = 0
        organizationLabel.isSelectable = true
        let organization = AssistantTheme.vertical([organizationCaption, organizationLabel], spacing: 10)
        organizationLabel.widthAnchor.constraint(equalTo: organization.widthAnchor).isActive = true
        holderLabel = AssistantTheme.label("—", size: 15, weight: .medium)
        holderLabel.isSelectable = true
        expiryLabel = AssistantTheme.label("—", size: 14, weight: .medium)
        expiryLabel.isSelectable = true
        let person = identityField("证书持有者", value: holderLabel)
        let expiration = identityField("到期时间 · 北京时间", value: expiryLabel)
        let identity = NSStackView(views: [person, expiration])
        identity.distribution = .fillEqually
        identity.spacing = 24
        identity.alignment = .top
        let rule = AssistantTheme.divider()
        devicePicker = NSPopUpButton(frame: .zero, pullsDown: false)
        devicePicker.target = self
        devicePicker.action = #selector(selectDevice(_:))
        devicePicker.setAccessibilityLabel("选择 USBKey")
        devicePicker.font = NSFont.systemFont(ofSize: 13)
        devicePickerRow = AssistantTheme.vertical([
            AssistantTheme.label("本次使用的 USBKey", size: 12, color: AssistantTheme.muted), devicePicker,
        ], spacing: 8)
        devicePicker.widthAnchor.constraint(equalTo: devicePickerRow.widthAnchor).isActive = true
        devicePickerRow.isHidden = true
        loginButton = AssistantButton("打开网站", style: .primary, symbol: "arrow.up.right",
                                      target: self, action: #selector(openLoginPage))
        loginButton.isEnabled = true
        loginButton.keyEquivalent = "\r"
        let website = AssistantTheme.vertical([
            AssistantTheme.label("广东电力交易平台", size: 13, weight: .medium),
            AssistantTheme.label("pm.gd.csg.cn", size: 11, color: AssistantTheme.muted),
        ], spacing: 5)
        let tools = NSStackView(views: [website, NSView(), loginButton!])
        tools.spacing = 12
        tools.alignment = .centerY
        let footerRule = AssistantTheme.divider()
        detailLabel = AssistantTheme.label("", size: 12, color: AssistantTheme.muted)
        detailLabel.maximumNumberOfLines = 0
        detailLabel.isHidden = true
        contentSpacer = NSView()
        contentSpacer.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .vertical)
        contentSpacer.setContentCompressionResistancePriority(NSLayoutConstraint.Priority(1), for: .vertical)
        contentSpacer.heightAnchor.constraint(greaterThanOrEqualToConstant: 0).isActive = true
        mainStack = AssistantTheme.vertical([
            connection, rule, devicePickerRow, organization, identity, contentSpacer, footerRule, tools, detailLabel,
        ], spacing: 20)
        mainStack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(mainStack)
        NSLayoutConstraint.activate([
            mainStack.leadingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: 36),
            mainStack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -36),
            mainStack.topAnchor.constraint(equalTo: content.topAnchor, constant: 54),
            mainStack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -32),
        ])
        for view in mainStack.views {
            view.widthAnchor.constraint(equalTo: mainStack.widthAnchor).isActive = true
        }
        resizeWindowToFit()
        window.center()
    }

    private func identityField(_ title: String, value: NSTextField) -> NSView {
        let caption = AssistantTheme.label(title, size: 12, color: AssistantTheme.muted)
        let stack = AssistantTheme.vertical([caption, value], spacing: 10)
        value.maximumNumberOfLines = 0
        value.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        return stack
    }

    private func showWindow() {
        NSApp.setActivationPolicy(.regular)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func prepareDirectoriesAndTLS() throws {
        try fileManager.createDirectory(at: tlsDirectory, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        if !fileManager.fileExists(atPath: certificateURL.path) ||
            !fileManager.fileExists(atPath: privateKeyURL.path) {
            let result = run(
                executable: "/usr/bin/openssl",
                arguments: [
                    "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
                    "-keyout", privateKeyURL.path,
                    "-out", certificateURL.path,
                    "-days", "3650", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                    "-addext", "keyUsage=digitalSignature,keyEncipherment",
                    "-addext", "extendedKeyUsage=serverAuth"
                ]
            )
            guard result.status == 0 else {
                throw NSError(domain: applicationName, code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "无法生成本地 HTTPS 证书"])
            }
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: privateKeyURL.path)
        }
    }

    private func bundledExecutable(_ relativePath: String) -> URL? {
        Bundle.main.resourceURL?.appendingPathComponent(relativePath)
    }

    private var runtimeArchitecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unsupported"
        #endif
    }

    private func ensureBridge(completion: @escaping (Bool) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let healthy = self.isPortOpen()
            DispatchQueue.main.async {
                if healthy { self.lastServiceFailure = nil; completion(true); return }
                guard self.launchBridge() else { completion(false); return }
                DispatchQueue.global(qos: .userInitiated).async {
                    var ready = false
                    for _ in 0..<10 {
                        if self.isPortOpen() { ready = true; break }
                        Thread.sleep(forTimeInterval: 0.2)
                    }
                    let result = ready
                    DispatchQueue.main.async {
                        if !result { self.lastServiceFailure = "服务未在等待时间内就绪" }
                        completion(result)
                    }
                }
            }
        }
    }

    private func launchBridge() -> Bool {
        if bridgeProcess?.isRunning == true { return true }
        try? transportLogHandle?.close()
        transportLogHandle = nil
        guard let transportURL = bundledExecutable("bin/usbkey-transport"),
              let workerURL = bundledExecutable("bin/usbkey-worker"),
              let probeURL = bundledExecutable("bin/ft3000gm-hid-probe"),
              let signerURL = bundledExecutable("bin/ft3000gm-signer"),
              let trustStoreURL = bundledExecutable("certs/netca-trust.sqlite"),
              [transportURL, workerURL, probeURL, signerURL, trustStoreURL].allSatisfy({
                  fileManager.fileExists(atPath: $0.path)
              }) else {
            lastServiceFailure = "应用文件不完整"
            return false
        }

        let process = Process()
        process.executableURL = transportURL
        process.arguments = [
            "--native-worker", workerURL.path,
            "--port", "10443",
            "--cert", certificateURL.path,
            "--key", privateKeyURL.path,
            "--probe", probeURL.path,
            "--signer", signerURL.path,
            "--trust-store", trustStoreURL.path,
            "--log", logURL.path,
            "--parent-pid", String(ProcessInfo.processInfo.processIdentifier)
        ]
        let channel = CertificatePinChannel()
        pinChannel = channel
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "USBKEY_PRIVATE_PIN_CHANNEL": "1"]
        process.standardOutput = channel.output
        process.standardInput = channel.input
        let stderrLog = openTransportLog()
        process.standardError = stderrLog ?? FileHandle.nullDevice
        transportLogHandle = stderrLog
        process.terminationHandler = { [weak self] task in
            DispatchQueue.main.async {
                guard let self, self.bridgeProcess === task else { return }
                self.bridgeProcess = nil
                try? self.transportLogHandle?.close()
                self.transportLogHandle = nil
                self.pinChannel?.close(); self.pinChannel = nil
                self.lastServiceFailure = "服务退出（退出码 \(task.terminationStatus)）"
                self.lastStatus = nil
                self.statusBadgeLabel.stringValue = "待确认"
                self.statusBadgeLabel.textColor = AssistantTheme.warning
                self.statusBadge.fill = AssistantTheme.warningLight
                self.statusBadge.needsDisplay = true
                self.organizationLabel.stringValue = "暂时无法读取 USBKey"
                self.holderLabel.stringValue = "—"
                self.expiryLabel.stringValue = "—"
                self.resizeWindowToFit()
            }
        }
        do {
            try process.run()
            bridgeProcess = process
            lastServiceFailure = nil
            return true
        } catch {
            lastServiceFailure = "本地服务启动失败"
            return false
        }
    }

    private func stopBridge() {
        guard let process = bridgeProcess, process.isRunning else { return }
        process.terminate()
        pinChannel?.close(); pinChannel = nil
        bridgeProcess = nil
        try? transportLogHandle?.close()
        transportLogHandle = nil
    }

    /// Keeps the last megabyte of transport diagnostics. Startup problems used to
    /// be discarded because stderr pointed at `nullDevice`.
    private func openTransportLog() -> FileHandle? {
        if !fileManager.fileExists(atPath: transportLogURL.path) {
            fileManager.createFile(atPath: transportLogURL.path, contents: Data(),
                                   attributes: [.posixPermissions: 0o600])
        }
        let attributes = try? fileManager.attributesOfItem(atPath: transportLogURL.path)
        let size = (attributes?[.size] as? NSNumber)?.intValue ?? 0
        if size > 1_048_576 {
            try? Data().write(to: transportLogURL)
        }
        guard let handle = try? FileHandle(forWritingTo: transportLogURL) else { return nil }
        handle.seekToEndOfFile()
        let stamp = ISO8601DateFormatter().string(from: Date())
        handle.write(Data("--- transport start \(stamp) ---\n".utf8))
        return handle
    }

    private func isPortOpen() -> Bool {
        let result = run(executable: "/usr/bin/curl", arguments: [
            "--silent", "--fail", "--max-time", "2", "--noproxy", "*",
            "--cacert", certificateURL.path, "https://127.0.0.1:10443/health"
        ])
        return result.status == 0 && result.output.trimmingCharacters(in: .whitespacesAndNewlines) == "netca-ft3000gm"
    }

    private func isCertificateTrusted() -> Bool {
        guard fileManager.fileExists(atPath: certificateURL.path) else { return false }
        return run(executable: "/usr/bin/security", arguments: [
            "verify-cert", "-c", certificateURL.path, "-p", "ssl", "-s", "localhost"
        ]).status == 0
    }

    private func updateDevicePicker(_ status: BridgeDeviceStatus?) {
        devicePicker.removeAllItems()
        let devices = status?.devices ?? []
        devicePickerRow.isHidden = devices.count <= 1
        devicePicker.isEnabled = devices.count > 1
        guard devices.count > 1 else { return }
        for (index, device) in devices.enumerated() {
            let name = device.holder ?? device.organization ?? "证书暂不可读"
            let suffix = device.deviceId.map { String($0.suffix(6)) } ?? "未知"
            devicePicker.addItem(withTitle: "\(index + 1). \(name) · \(suffix)")
            devicePicker.lastItem?.representedObject = device.deviceId
            if device.deviceId == status?.selectedDeviceId { devicePicker.selectItem(at: index) }
        }
    }

    @objc private func selectDevice(_ sender: NSPopUpButton) {
        guard let deviceId = sender.selectedItem?.representedObject as? String,
              let data = try? JSONSerialization.data(withJSONObject: ["deviceId": deviceId]),
              let body = String(data: data, encoding: .utf8) else { return }
        devicePicker.isEnabled = false
        refreshButton.isEnabled = false
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result = self.run(executable: "/usr/bin/curl", arguments: [
                "--silent", "--show-error", "--fail", "--max-time", "150", "--noproxy", "*",
                "--cacert", self.certificateURL.path, "--request", "POST",
                "--header", "Content-Type: application/json", "--data-binary", body,
                "https://127.0.0.1:10443/selection",
            ], timeout: 155)
            DispatchQueue.main.async {
                if result.status != 0 { self.lastServiceFailure = "所选 USBKey 已断开，请重新选择" }
                self.refreshStatus(nil)
            }
        }
    }

    @objc private func refreshStatus(_ sender: Any?) {
        checkStatus { _ in }
    }

    private func checkStatus(completion: @escaping (AssistantStatus) -> Void) {
        statusCallbacks.append(completion)
        guard !statusRefreshInProgress else { return }
        statusRefreshInProgress = true
        refreshButton.isEnabled = false
        devicePicker.isEnabled = false
        organizationLabel.stringValue = "正在读取 USBKey…"
        holderLabel.stringValue = "—"
        expiryLabel.stringValue = "—"
        detailLabel.isHidden = true
        statusBadgeLabel.stringValue = "检查中"
        statusBadgeLabel.textColor = AssistantTheme.muted
        statusBadge.fill = AssistantTheme.hover
        statusBadge.needsDisplay = true
        resizeWindowToFit()
        if !initialized {
            finishCheck(AssistantStatus(checkedAt: Date(), serviceRunning: false,
                                       certificateTrusted: false, device: nil))
            return
        }
        ensureBridge { [weak self] serviceRunning in
            guard let self else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                let trusted = self.isCertificateTrusted()
                var device: BridgeDeviceStatus?
                if serviceRunning {
                    let result = self.run(executable: "/usr/bin/curl", arguments: [
                        "--silent", "--max-time", "15", "--noproxy", "*", "--cacert", self.certificateURL.path,
                        "https://127.0.0.1:10443/status"
                    ])
                    if result.status == 0,
                       let status = try? JSONDecoder().decode(BridgeDeviceStatus.self, from: Data(result.output.utf8)),
                       status.service == "netca-ft3000gm" { device = status }
                }
                let status = AssistantStatus(checkedAt: Date(), serviceRunning: serviceRunning,
                                             certificateTrusted: trusted, device: device)
                DispatchQueue.main.async {
                    self.finishCheck(status)
                }
            }
        }
    }

    private func finishCheck(_ status: AssistantStatus) {
        lastStatus = status
        statusRefreshInProgress = false
        refreshButton.isEnabled = true
        let connected = status.device?.deviceFound == true
        let deviceCount = status.device?.deviceCount ?? 1
        statusBadgeLabel.stringValue = connected ? (deviceCount > 1 ? "已连接 \(deviceCount) 枚" : "已连接") : status.device == nil ? "待确认" : "未连接"
        updateDevicePicker(status.device)
        statusBadgeLabel.textColor = connected ? AssistantTheme.accent : AssistantTheme.muted
        statusBadge.fill = connected ? AssistantTheme.accentLight : AssistantTheme.hover
        statusBadge.needsDisplay = true
        organizationLabel.stringValue = status.organizationText
        holderLabel.stringValue = status.holderText
        expiryLabel.stringValue = status.expiryText
        detailLabel.isHidden = true
        let callbacks = statusCallbacks
        statusCallbacks.removeAll()
        callbacks.forEach { $0(status) }
        resizeWindowToFit()
    }

    private func resizeWindowToFit() {
        window.contentView?.layoutSubtreeIfNeeded()
        var screenSize = (window.screen ?? NSScreen.main)?.frame.size ?? NSSize(width: 16, height: 10)
        #if ASSISTANT_UI_TEST
        screenSize = screenSizeForTesting ?? screenSize
        #endif
        let ratio = screenSize.width / screenSize.height
        // Measure the rows, excluding the flexible gap, so a full-height layout
        // cannot feed its expanded height back into the next window resize.
        let rows = mainStack.views.filter { !$0.isHidden }
        let rowsHeight = rows.filter { $0 !== contentSpacer }.reduce(CGFloat(0)) { $0 + $1.fittingSize.height }
        let minimumHeight = rowsHeight + CGFloat(max(0, rows.count - 1)) * mainStack.spacing + 86
        let minimumContentSize = NSSize(width: 840, height: max(420, minimumHeight))
        let minimumFrame = window.frameRect(forContentRect: NSRect(origin: .zero, size: minimumContentSize))
        let height = max(minimumFrame.height, minimumFrame.width / ratio)
        var frame = window.frame
        frame.origin.y += frame.height - height
        frame.size = NSSize(width: height * ratio, height: height)
        window.setFrame(frame, display: true)
        window.contentView?.layoutSubtreeIfNeeded()
    }

    func windowDidChangeScreen(_ notification: Notification) {
        guard mainStack != nil else { return }
        resizeWindowToFit()
    }

    @objc private func runDiagnostics() {
        diagnosticButton.isEnabled = false
        checkStatus { [weak self] status in
            guard let self else { return }
            let serviceFailure = self.lastServiceFailure
            DispatchQueue.global(qos: .utility).async {
                let failure = serviceFailure ?? DiagnosticLog.recentFailure(at: self.logURL)
                let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "开发版"
                let summary = status.diagnosticSummary(version: version,
                                                       architecture: self.runtimeArchitecture, recentFailure: failure)
                DispatchQueue.main.async {
                    self.diagnosticButton.isEnabled = true
                    let alert = NSAlert()
                    alert.messageText = "诊断结果"
                    alert.informativeText = "可以复制摘要用于排查问题。"
                    alert.addButton(withTitle: "复制摘要")
                    alert.addButton(withTitle: "查看日志")
                    alert.addButton(withTitle: "关闭")
                    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 480, height: 280))
                    scroll.hasVerticalScroller = true
                    let text = NSTextView(frame: scroll.bounds)
                    text.isVerticallyResizable = true
                    text.isHorizontallyResizable = false
                    text.textContainer?.widthTracksTextView = true
                    text.isEditable = false
                    text.isSelectable = true
                    text.font = .systemFont(ofSize: 12)
                    text.string = summary
                    text.autoresizingMask = [.width]
                    scroll.documentView = text
                    alert.accessoryView = scroll
                    alert.beginSheetModal(for: self.window) { response in
                        if response == .alertFirstButtonReturn {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(summary, forType: .string)
                            self.detailLabel.isHidden = false
                    self.detailLabel.stringValue = "诊断摘要已复制。"
                            self.resizeWindowToFit()
                        } else if response == .alertSecondButtonReturn {
                            self.openLog()
                        }
                    }
                }
            }
        }
    }

    @objc private func openLoginPage() {
        guard !loginOpenInProgress else { return }
        loginOpenInProgress = true
        loginButton.isEnabled = false
        loginButton.title = "正在打开登录页…"
        openBrowser()
    }

    private func finishOpeningBrowser(opened: Bool) {
        loginOpenInProgress = false
        loginButton.isEnabled = true
        loginButton.title = "打开网站"
        detailLabel.isHidden = opened
        detailLabel.stringValue = opened ? "" : "无法打开登录页，请检查浏览器是否已安装。"
        if !opened { NSSound.beep() }
        resizeWindowToFit()
    }

    private func openBrowser() {
        #if ASSISTANT_UI_TEST
        if let launch = browserLaunchForTesting {
            finishOpeningBrowser(opened: launch())
            return
        }
        #endif
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let chromeResult = self.run(
                executable: "/usr/bin/open",
                arguments: ["-b", "com.google.Chrome", loginURL.absoluteString]
            )
            DispatchQueue.main.async {
                let opened = chromeResult.status == 0 || NSWorkspace.shared.open(loginURL)
                self.finishOpeningBrowser(opened: opened)
            }
        }
    }

    @objc private func openLog() {
        if !fileManager.fileExists(atPath: logURL.path) {
            fileManager.createFile(atPath: logURL.path, contents: Data())
        }
        NSWorkspace.shared.open(logURL)
    }

    @objc private func openCertificate() {
        detailLabel.isHidden = false
        if NSWorkspace.shared.open(certificateURL) {
            detailLabel.stringValue = "请在钥匙串访问中将此证书设为始终信任，完成后重新检查。"
        } else {
            detailLabel.stringValue = "无法打开本地证书，请运行一键诊断。"
        }
        resizeWindowToFit()
    }

    #if ASSISTANT_UI_TEST
    func verifyLayoutForTesting() {
        buildWindow()
        let found = BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: true,
            certificateCount: 2, certificateFileId: "3001", signingCertificateFileId: "3001", retries: 10,
            organization: "华能汕头海门发电有限责任公司", holder: "任一鸣", expiresAt: "2029-08-06T02:44:26.000Z")
        let long = BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: true,
            certificateCount: 2, certificateFileId: "3001", signingCertificateFileId: "3001", retries: 10,
            organization: "用于验证完整显示的较长企业名称广东电力市场新能源开发运营管理有限责任公司",
            holder: "测试证书持有者", expiresAt: "2029-08-06T02:44:26.000Z")
        let multiDevices = [
            BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: true, certificateCount: 2,
                certificateFileId: "3001", signingCertificateFileId: "3001", retries: 10,
                organization: "单位一", holder: "测试证书持有者一", deviceId: "a1"),
            BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: true, certificateCount: 2,
                certificateFileId: "3001", signingCertificateFileId: "3001", retries: 10,
                organization: "单位二", holder: "测试证书持有者二", deviceId: "b1"),
        ]
        let multiple = BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: true,
            certificateCount: 4, certificateFileId: "3001", signingCertificateFileId: "3001", retries: 10,
            organization: "单位一", holder: "测试证书持有者一", deviceCount: 2,
            selectedDeviceId: "a1", requiresSelection: false, devices: multiDevices)
        let cases = [
            AssistantStatus(checkedAt: Date(), serviceRunning: true, certificateTrusted: true, device: multiple),
            AssistantStatus(checkedAt: Date(), serviceRunning: true, certificateTrusted: true, device: found),
            AssistantStatus(checkedAt: Date(), serviceRunning: true, certificateTrusted: false, device: found),
            AssistantStatus(checkedAt: Date(), serviceRunning: false, certificateTrusted: false, device: nil),
            AssistantStatus(checkedAt: Date(), serviceRunning: true, certificateTrusted: true,
                device: BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: false,
                    certificateCount: nil, certificateFileId: nil, signingCertificateFileId: nil, retries: nil)),
            AssistantStatus(checkedAt: Date(), serviceRunning: true, certificateTrusted: true, device: long)
        ]
        precondition(updateButton.isHidden)
        let releaseJSON = """
        {"tag_name":"v1.2.0","html_url":"https://github.com/a792275829-cpu/usbkey-assistant-releases/releases/tag/v1.2.0",
         "body":"更新说明\\n\\n• 启动时自动检查 GitHub 新版本。\\n• 支持下载进度、取消和完整性校验。",
         "draft":false,"prerelease":false,"assets":[]}
        """
        availableRelease = try! JSONDecoder().decode(GitHubRelease.self, from: Data(releaseJSON.utf8))
        updateButton.isHidden = false
        window.contentView?.layoutSubtreeIfNeeded()
        let badgeFrame = updateButton.convert(updateButton.bounds, to: window.contentView)
        precondition(badgeFrame.height == 22 && badgeFrame.width < 80)
        let updatePreview = AssistantUpdateWindow(release: availableRelease!, updater: updater)
        updatePreview.window?.contentView?.layoutSubtreeIfNeeded()
        if let directory = ProcessInfo.processInfo.environment["ASSISTANT_LAYOUT_PREVIEW"],
           let content = updatePreview.window?.contentView,
           let bitmap = content.bitmapImageRepForCachingDisplay(in: content.bounds) {
            content.cacheDisplay(in: content.bounds, to: bitmap)
            try? bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: directory).appendingPathComponent("update.png"))
        }
        var browserLaunches = 0
        browserLaunchForTesting = { browserLaunches += 1; return true }
        precondition(loginButton.isEnabled)
        openLoginPage()
        precondition(browserLaunches == 1)
        diagnosticButton.isEnabled = true
        for (index, status) in cases.enumerated() {
            finishCheck(status)
            let heightBeforeOpening = window.frame.height
            let previous = browserLaunches
            statusRefreshInProgress = true
            openLoginPage()
            precondition(browserLaunches == previous + 1 && loginButton.isEnabled)
            precondition(detailLabel.isHidden && detailLabel.stringValue.isEmpty,
                         "Opening the website must not leave a success message")
            precondition(abs(window.frame.height - heightBeforeOpening) < 1,
                         "Opening the website must not expand the window")
            statusRefreshInProgress = false
            finishCheck(status)
            resizeWindowToFit()
            window.contentView?.layoutSubtreeIfNeeded()
            guard let content = window.contentView else { preconditionFailure("Missing content view") }
            let mainFrame = mainStack.convert(mainStack.bounds, to: content)
            precondition(abs(content.bounds.maxY - mainFrame.maxY - 54) < 1 && abs(mainFrame.minY - 32) < 1,
                         "Device information must fill the workspace from header to footer")
            let loginFrame = loginButton.convert(loginButton.bounds, to: content)
            precondition(abs(loginFrame.minY - 32) < 1, "Website action must stay at the bottom of the workspace")
            if let screen = window.screen ?? NSScreen.main {
                precondition(abs(window.frame.width / window.frame.height - screen.frame.width / screen.frame.height) < 0.005,
                             "Window proportions must match the current screen")
            }
            for view in mainStack.views where !view.isHidden {
                let frame = view.convert(view.bounds, to: content)
                precondition(frame.minY >= -1 && frame.maxY <= content.bounds.height + 1 &&
                             frame.minX >= -1 && frame.maxX <= content.bounds.width + 1, "Window clips a control")
            }
            if (status.device?.devices?.count ?? 0) > 1 {
                precondition(!devicePickerRow.isHidden && devicePicker.numberOfItems == 2)
                precondition(devicePicker.itemTitles.allSatisfy { !$0.contains("请选择") })
                precondition(devicePicker.selectedItem?.representedObject as? String == status.device?.selectedDeviceId)
                precondition(statusBadgeLabel.stringValue.contains("2 枚"))
            }
            precondition(organizationLabel.stringValue == status.organizationText)
            precondition(holderLabel.stringValue == status.holderText)
            precondition(expiryLabel.stringValue == status.expiryText)
            if let directory = ProcessInfo.processInfo.environment["ASSISTANT_LAYOUT_PREVIEW"],
               let bitmap = content.bitmapImageRepForCachingDisplay(in: content.bounds) {
                content.cacheDisplay(in: content.bounds, to: bitmap)
                if let data = bitmap.representation(using: .png, properties: [:]) {
                    try? data.write(to: URL(fileURLWithPath: directory).appendingPathComponent("state-\(index).png"))
                }
            }
        }
        browserLaunchForTesting = { false }
        openLoginPage()
        precondition(!detailLabel.isHidden && detailLabel.stringValue.contains("无法打开登录页"))
        precondition(loginButton.isEnabled)
        browserLaunchForTesting = { true }
        openLoginPage()
        precondition(detailLabel.isHidden && detailLabel.stringValue.isEmpty,
                     "A successful retry must clear the browser error")
        for size in [NSSize(width: 1920, height: 1080), NSSize(width: 2560, height: 1600)] {
            screenSizeForTesting = size
            for status in cases {
                finishCheck(status)
                precondition(abs(window.frame.width / window.frame.height - size.width / size.height) < 0.005,
                             "Screen proportions must survive device and certificate changes")
                guard let content = window.contentView else { preconditionFailure("Missing content view") }
                let frame = mainStack.convert(mainStack.bounds, to: content)
                precondition(content.bounds.insetBy(dx: -1, dy: -1).contains(frame), "Window clips its content")
            }
        }
        screenSizeForTesting = nil
    }
    #endif

    private func run(executable: String, arguments: [String], timeout: TimeInterval = 15) -> ProcessResult {
        ProcessRunner.run(executable: executable, arguments: arguments, timeout: timeout)
    }
}
