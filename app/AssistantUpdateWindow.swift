import AppKit

final class AssistantUpdateWindow: NSWindowController {
    private let updater: AssistantUpdater
    private let release: GitHubRelease
    private let status = AssistantTheme.label("点击“开始更新”，完成后自动重启到新版本。", size: 12, color: AssistantTheme.muted)
    private let progress = NSProgressIndicator()
    private var primary: AssistantButton!
    private var cancelButton: AssistantButton!
    private var working = false
    private let installedVersion = AssistantUpdater.currentVersion
    private let location = InstallPath.classify(Bundle.main.bundleURL)

    init(release: GitHubRelease, updater: AssistantUpdater) {
        self.release = release
        self.updater = updater
        let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 540, height: 580),
                             styleMask: [.titled], backing: .buffered, defer: false)
        panel.title = "软件更新"
        panel.appearance = NSAppearance(named: .aqua)
        panel.isReleasedWhenClosed = false
        super.init(window: panel)
        let content = AssistantSurface(fill: AssistantTheme.background, radius: 0, bordered: false)
        panel.contentView = content
        primary = AssistantButton("开始更新", style: .primary, symbol: "arrow.down.circle", target: self, action: #selector(performUpdate))
        cancelButton = AssistantButton("稍后", style: .quiet, target: self, action: #selector(dismiss))
        cancelButton.keyEquivalent = "\u{1b}"
        let releaseButton = AssistantButton("发布页面", style: .quiet, symbol: "arrow.up.right", target: self, action: #selector(openRelease))
        let title = AssistantTheme.label("发现新版本 \(release.tag_name)", size: 22, weight: .semibold)
        title.maximumNumberOfLines = 2
        let versions = AssistantTheme.label("当前 v\(installedVersion)  →  \(release.tag_name)  ·  \(Self.delivery(plan: release.plan(installed: installedVersion)))",
                                            size: 12, color: AssistantTheme.muted)
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        let notes = NSTextView(frame: NSRect(x: 0, y: 0, width: 480, height: 240))
        notes.isEditable = false
        notes.isSelectable = true
        notes.drawsBackground = false
        notes.font = .systemFont(ofSize: 13)
        notes.textColor = AssistantTheme.ink
        notes.textContainerInset = NSSize(width: 0, height: 8)
        notes.isHorizontallyResizable = false
        notes.isVerticallyResizable = true
        notes.autoresizingMask = [.width]
        notes.textContainer?.widthTracksTextView = true
        notes.string = release.body?.isEmpty == false ? String(release.body!.prefix(100_000)) : "此版本没有提供更新说明。"
        scroll.documentView = notes
        scroll.heightAnchor.constraint(equalToConstant: 230).isActive = true
        progress.style = .bar
        progress.isIndeterminate = false
        progress.maxValue = 1
        progress.isHidden = true
        let actions = NSStackView(views: [releaseButton, NSView(), cancelButton!, primary!])
        actions.spacing = 10
        let stack = AssistantTheme.vertical([title, versions, AssistantTheme.divider(), scroll, progress, status, actions], spacing: 14)
        content.contain(stack, inset: 28)
        for view in [title, versions, scroll, progress, status, actions] {
            view.translatesAutoresizingMaskIntoConstraints = false
            view.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        if !location.canUpdateInPlace {
            status.stringValue = "点击“开始更新”，自动安装到“应用程序”并重启，无需先手动移动。"
        }
        if release.plan(installed: installedVersion) == nil {
            primary.isEnabled = false
            status.stringValue = UpdateError.missingInstaller.localizedDescription
        }
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private static func delivery(plan: UpdatePlan?) -> String {
        guard let plan else { return "Apple 芯片" }
        let size = ByteCountFormatter.string(fromByteCount: plan.asset.size, countStyle: .file)
        switch plan.kind {
        case .patch: return "增量补丁 \(size)"
        case .diskImage: return "安装镜像 \(size)"
        case .package: return "完整安装包 \(size)"
        }
    }

    @objc private func openRelease() { NSWorkspace.shared.open(release.html_url) }
    @objc private func dismiss() {
        if working { updater.cancel() }
        if let window, let parent = window.sheetParent { parent.endSheet(window) }
    }

    /// One click: download, verify, stage, install and relaunch. Nothing else is
    /// required — the application is user-owned once it has been dragged out of
    /// the disk image, so replacing it needs no administrator password.
    @objc private func performUpdate() {
        guard !working else { return }
        guard let plan = release.plan(installed: installedVersion) else {
            status.stringValue = UpdateError.missingInstaller.localizedDescription
            return
        }
        working = true
        primary.isEnabled = false
        cancelButton.title = "取消下载"
        progress.isHidden = false
        progress.doubleValue = 0
        begin(plan, fallback: false)
    }

    private func begin(_ plan: UpdatePlan, fallback: Bool) {
        primary.title = "正在下载…"
        cancelButton.title = "取消下载"
        cancelButton.isEnabled = true
        cancelButton.keyEquivalent = "\u{1b}"
        let downloading: String
        switch plan.kind {
        case .patch: downloading = "正在下载增量补丁…"
        case .diskImage: downloading = "正在下载安装镜像…"
        case .package: downloading = "正在下载完整安装包…"
        }
        status.stringValue = fallback ? "补丁与本机安装不一致，改为下载完整安装包…" : downloading
        updater.download(plan.asset, progress: { [weak self] fraction in
            guard let self else { return }
            self.progress.doubleValue = fraction
            self.status.stringValue = fraction >= 1 ? "正在校验更新包…" : "正在下载 · \(Int(fraction * 100))%"
        }, completion: { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.fail(error)
            case .success(let file):
                self.install(plan, file: file)
            }
        })
    }

    private func install(_ plan: UpdatePlan, file: URL) {
        cancelButton.isEnabled = false
        cancelButton.keyEquivalent = ""
        status.stringValue = "校验通过，正在准备安装…"
        progress.doubleValue = 1
        primary.title = "正在安装…"
        let source = Bundle.main.bundleURL
        let target = UpdateInstaller.updateTarget(for: source)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let staged = try UpdateInstaller.stage(archive: file, plan: plan, target: source)
                defer {
                    try? FileManager.default.removeItem(at: staged.deletingLastPathComponent())
                    try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
                }
                let needsAuthorization = UpdateInstaller.replaceNeedsAuthorization(target)
                DispatchQueue.main.async {
                    self.status.stringValue = needsAuthorization
                        ? "正在写入新版本，需要输入管理员密码（仅此一次）。"
                        : "正在写入新版本…"
                    if needsAuthorization { NSApp.activate(ignoringOtherApps: true) }
                }
                try UpdateInstaller.install(staged: staged, target: target, version: plan.version)
                DispatchQueue.main.async { self.finish(plan, target: target) }
            } catch InstallError.patchNotApplicable where plan.kind.isPatch {
                DispatchQueue.main.async {
                    guard let full = self.release.plan(installed: self.installedVersion, forceFull: true) else {
                        self.fail(UpdateError.missingInstaller)
                        return
                    }
                    try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
                    self.begin(full, fallback: true)
                }
            } catch {
                DispatchQueue.main.async { self.fail(error) }
            }
        }
    }

    private func finish(_ plan: UpdatePlan, target: URL) {
        working = false
        progress.doubleValue = 1
        primary.title = "正在重新启动…"
        primary.isEnabled = false
        status.stringValue = "已安装 v\(plan.version)，正在重新启动。"
        do {
            try UpdateInstaller.relaunchAfterExit(target)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { NSApp.terminate(nil) }
        } catch {
            fail(error)
        }
    }

    private func fail(_ error: Error) {
        working = false
        progress.isHidden = true
        primary.isEnabled = true
        primary.title = "重试"
        primary.symbolName = "arrow.clockwise"
        cancelButton.title = "关闭"
        cancelButton.isEnabled = true
        cancelButton.keyEquivalent = "\u{1b}"
        status.stringValue = error.localizedDescription
    }
}
