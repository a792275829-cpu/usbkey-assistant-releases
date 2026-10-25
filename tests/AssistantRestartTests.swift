import AppKit

/// Uses real AppKit sheets, process termination and LaunchServices. The
/// temporary application writes a marker instead of starting a hardware bridge.
@main
enum AssistantRestartTests {
    static let fixtureID = "test.usbkeyassistant.restart"

    static func main() throws {
        if Bundle.main.bundleIdentifier == fixtureID {
            let application = NSApplication.shared
            let delegate = RestartedApplication()
            application.delegate = delegate
            application.setActivationPolicy(.prohibited)
            application.run()
            return
        }
        if CommandLine.arguments.contains("--child") {
            let application = NSApplication.shared
            let delegate = UpdatingApplication()
            application.delegate = delegate
            application.setActivationPolicy(.prohibited)
            application.run()
            return
        }

        let manager = FileManager.default
        let work = manager.temporaryDirectory.appendingPathComponent("USBKeyRestart-\(UUID().uuidString)")
        try manager.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: work) }
        let target = work.appendingPathComponent("New Application.app")
        let contents = target.appendingPathComponent("Contents")
        let binaries = contents.appendingPathComponent("MacOS")
        try manager.createDirectory(at: binaries, withIntermediateDirectories: true)
        let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
        try manager.copyItem(at: executable, to: binaries.appendingPathComponent("RestartFixture"))
        let marker = work.appendingPathComponent("restarted.plist")
        let plist: [String: Any] = [
            "CFBundleIdentifier": fixtureID,
            "CFBundleExecutable": "RestartFixture",
            "CFBundleName": "USBKey Restart Fixture",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.1.21",
            "LSUIElement": true,
            "RestartMarker": marker.path,
        ]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: contents.appendingPathComponent("Info.plist"))
        let signature = ProcessRunner.run(executable: "/usr/bin/codesign",
                                          arguments: ["--force", "--deep", "--sign", "-", target.path])
        precondition(signature.status == 0)

        // Prove the original failure with an attached sheet and real terminate.
        let legacy = ProcessRunner.run(executable: executable.path,
                                       arguments: ["--child", "--legacy", target.path], timeout: 8)
        precondition(legacy.status == 42 && legacy.failure == nil,
                     "Expected the legacy attached-sheet termination to stall: \(legacy)")

        // Exercise the production update completion, including its delayed
        // termination and the real `open -n` launch after the old process exits.
        let fixed = ProcessRunner.run(executable: executable.path,
                                      arguments: ["--child", target.path], timeout: 8)
        precondition(fixed.status == 0 && fixed.failure == nil,
                     "Update process did not terminate: \(fixed)")
        let deadline = Date().addingTimeInterval(15)
        while !manager.fileExists(atPath: marker.path), Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        let data = try Data(contentsOf: marker)
        let result = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        precondition(result["version"] as? String == "1.1.21")
        precondition(URL(fileURLWithPath: result["path"] as! String).resolvingSymlinksInPath().path == target.resolvingSymlinksInPath().path)
        precondition(result["oldExited"] as? Bool == true)
        print("Real AppKit sheet failure reproduced; update completion exits and launches the new application automatically — PASSED")
    }
}

private final class UpdatingApplication: NSObject, NSApplicationDelegate {
    private var parent: NSWindow!
    private var controller: AssistantUpdateWindow!

    func applicationDidFinishLaunching(_ notification: Notification) {
        parent = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 540, height: 580),
                          styleMask: [.titled], backing: .buffered, defer: false)
        let target = URL(fileURLWithPath: CommandLine.arguments.last!)
        try! String(ProcessInfo.processInfo.processIdentifier).write(
            to: target.deletingLastPathComponent().appendingPathComponent("old.pid"), atomically: true, encoding: .utf8)
        let release = try! JSONDecoder().decode(GitHubRelease.self, from: Data("""
        {"tag_name":"v1.1.21","html_url":"https://github.com/a792275829-cpu/usbkey-assistant-releases/releases/tag/v1.1.21",
         "body":"Restart regression fixture","draft":false,"prerelease":false,"assets":[]}
        """.utf8))
        controller = AssistantUpdateWindow(release: release, updater: AssistantUpdater())
        parent.beginSheet(controller.window!)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            precondition(self.parent.attachedSheet != nil)
            if CommandLine.arguments.contains("--legacy") {
                NSApp.terminate(nil)
            } else {
                let asset = GitHubRelease.Asset(name: "fixture.dmg", browser_download_url: target,
                                                size: 1, digest: nil)
                self.controller.finishForTesting(UpdatePlan(kind: .diskImage, asset: asset,
                                                           version: "1.1.21", installed: "1.1.20"), target: target)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { exit(42) }
    }
}

private final class RestartedApplication: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let marker = Bundle.main.object(forInfoDictionaryKey: "RestartMarker") as! String
        let pidPath = URL(fileURLWithPath: marker).deletingLastPathComponent().appendingPathComponent("old.pid")
        let oldPID = Int32(try! String(contentsOf: pidPath, encoding: .utf8))!
        let oldExited = kill(oldPID, 0) == -1 && errno == ESRCH
        let result: [String: Any] = ["version": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as! String,
                                     "path": Bundle.main.bundleURL.path, "oldExited": oldExited]
        let data = try! PropertyListSerialization.data(fromPropertyList: result, format: .xml, options: 0)
        try! data.write(to: URL(fileURLWithPath: marker), options: .atomic)
        NSApp.terminate(nil)
    }
}
