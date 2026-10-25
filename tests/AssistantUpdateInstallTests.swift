import Foundation

/// End-to-end checks for the disk-image delivery path: build a real image, mount
/// it, stage the application out of it and replace an installed copy in place —
/// the same steps the update window performs, without touching /Applications.
@main
enum AssistantUpdateInstallTests {
    static let identifier = UpdateInstaller.bundleIdentifier
    static var root = URL(fileURLWithPath: NSTemporaryDirectory())

    static func run(_ tool: String, _ arguments: [String]) -> String {
        let result = ProcessRunner.run(executable: tool, arguments: arguments, timeout: 300, mergeStderr: true)
        precondition(result.status == 0, "\(tool) failed: \(result.output)")
        return result.output
    }

    /// Minimal but structurally valid bundle: the identifier and version checks
    /// in the installer read the same plist a real build ships.
    static func makeApp(_ url: URL, version: String, marker: String) throws {
        let fileManager = FileManager.default
        let contents = url.appendingPathComponent("Contents")
        try fileManager.createDirectory(at: contents.appendingPathComponent("MacOS"),
                                        withIntermediateDirectories: true)
        try fileManager.createDirectory(at: contents.appendingPathComponent("Resources"),
                                        withIntermediateDirectories: true)
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>CFBundleIdentifier</key><string>\(identifier)</string>
        <key>CFBundleShortVersionString</key><string>\(version)</string>
        <key>CFBundleExecutable</key><string>dummy</string>
        <key>CFBundlePackageType</key><string>APPL</string>
        </dict></plist>
        """
        try plist.write(to: contents.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        let executable = contents.appendingPathComponent("MacOS/dummy")
        try "#!/bin/sh\nexit 0\n".write(to: executable, atomically: true, encoding: .utf8)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable.path)
        try marker.write(to: contents.appendingPathComponent("Resources/marker.txt"),
                         atomically: true, encoding: .utf8)
        // Adhoc signing keeps the bundle valid for the codesign --verify step.
        _ = run("/usr/bin/codesign", ["--force", "--deep", "--sign", "-", url.path])
    }

    static func asset(_ name: String, _ url: URL, size: Int64) -> GitHubRelease.Asset {
        GitHubRelease.Asset(name: name, browser_download_url: url, size: size,
                            digest: "sha256:" + String(repeating: "0", count: 64))
    }

    static func main() throws {
        let fileManager = FileManager.default
        let work = root.appendingPathComponent("usbkey-dmg-tests-\(UUID().uuidString)")
        try fileManager.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: work) }

        // Installed 1.1.18 next to a 1.1.19 build shipped inside a disk image.
        let target = work.appendingPathComponent("installed/广东电力USBKey助手.app")
        try fileManager.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try makeApp(target, version: "1.1.18", marker: "old")
        let source = work.appendingPathComponent("new/广东电力USBKey助手.app")
        try fileManager.createDirectory(at: source.deletingLastPathComponent(), withIntermediateDirectories: true)
        try makeApp(source, version: "1.1.19", marker: "new")

        let imageRoot = work.appendingPathComponent("image-root")
        try fileManager.createDirectory(at: imageRoot, withIntermediateDirectories: true)
        _ = run("/usr/bin/ditto", [source.path, imageRoot.appendingPathComponent("App.app").path])
        try fileManager.createSymbolicLink(at: imageRoot.appendingPathComponent("Applications"),
                                           withDestinationURL: URL(fileURLWithPath: "/Applications"))
        let image = work.appendingPathComponent("USBKeyAssistant-1.1.19-apple-silicon.dmg")
        _ = run("/usr/bin/hdiutil", ["create", "-volname", "USBKey 测试", "-srcfolder", imageRoot.path,
                                     "-fs", "HFS+", "-format", "UDZO", "-ov", image.path])

        // A user-owned installation is replaced without an authorization prompt.
        precondition(!UpdateInstaller.replaceNeedsAuthorization(target))
        let plan = UpdatePlan(kind: .diskImage,
                              asset: asset("USBKeyAssistant-1.1.19-apple-silicon.dmg", image, size: 1),
                              version: "1.1.19", installed: "1.1.18")
        let staged = try UpdateInstaller.stage(archive: image, plan: plan, target: target)
        precondition(UpdateInstaller.version(of: staged) == "1.1.19")
        precondition(UpdateInstaller.identifier(of: staged) == identifier)
        try UpdateInstaller.install(staged: staged, target: target, version: "1.1.19")
        precondition(UpdateInstaller.version(of: target) == "1.1.19")
        let installedMarker = try String(contentsOf: target.appendingPathComponent("Contents/Resources/marker.txt"),
                                         encoding: .utf8)
        precondition(installedMarker == "new")
        // The swap leaves nothing behind in the installation folder.
        let leftovers = try fileManager.contentsOfDirectory(atPath: target.deletingLastPathComponent().path)
        precondition(leftovers == [target.lastPathComponent], "leftovers: \(leftovers)")
        // Signature survives the replacement.
        _ = run("/usr/bin/codesign", ["--verify", "--deep", "--strict", target.path])

        // The image is detached, so the same plan can be staged again.
        let restaged = try UpdateInstaller.stage(archive: image, plan: plan, target: target)
        precondition(UpdateInstaller.version(of: restaged) == "1.1.19")

        // A version mismatch in the image is refused before anything is written.
        let wrongPlan = UpdatePlan(kind: .diskImage,
                                   asset: asset("USBKeyAssistant-9.9.9-apple-silicon.dmg", image, size: 1),
                                   version: "9.9.9", installed: "1.1.19")
        do {
            _ = try UpdateInstaller.stage(archive: image, plan: wrongPlan, target: target)
            preconditionFailure("Version mismatch accepted")
        } catch InstallError.failed {}

        // A patch must carry permission repairs even when the file bytes match.
        let next = work.appendingPathComponent("next/App.app")
        try makeApp(next, version: "1.1.20", marker: "new")
        let helperPath = "Contents/Resources/bin/helper.sh"
        for (app, mode) in [(target, 0o644), (next, 0o755)] {
            let helper = app.appendingPathComponent(helperPath)
            try fileManager.createDirectory(at: helper.deletingLastPathComponent(),
                                            withIntermediateDirectories: true)
            try "#!/bin/sh\nexit 0\n".write(to: helper, atomically: true, encoding: .utf8)
            try fileManager.setAttributes([.posixPermissions: mode], ofItemAtPath: helper.path)
        }
        let builder = URL(fileURLWithPath: fileManager.currentDirectoryPath)
            .appendingPathComponent("scripts/build_patch.py")
        _ = run("/usr/bin/python3", [builder.path, "--from", target.path, "--app", next.path,
                                    "--out", work.path, "--force"])
        let patch = work.appendingPathComponent("USBKeyAssistant-1.1.20-patch-from-1.1.19.tar.gz")
        let patchPlan = UpdatePlan(kind: .patch,
                                  asset: asset(patch.lastPathComponent, patch, size: 1),
                                  version: "1.1.20", installed: "1.1.19")
        let patched = try UpdateInstaller.stage(archive: patch, plan: patchPlan, target: target)
        defer { try? fileManager.removeItem(at: patched.deletingLastPathComponent()) }
        try UpdateInstaller.install(staged: patched, target: target, version: "1.1.20")
        let permissions = try fileManager.attributesOfItem(atPath: target.appendingPathComponent(helperPath).path)
        precondition((permissions[.posixPermissions] as? NSNumber)?.intValue == 0o755,
                     "Permission-only patch change was not applied")
        _ = run("/usr/bin/codesign", ["--verify", "--deep", "--strict", target.path])

        // A read-only copy (as launched from the image) is moved into the
        // application folder instead of being replaced in place.
        let relocated = try UpdateInstaller.relocate(staged, into: work.appendingPathComponent("Applications"))
        precondition(UpdateInstaller.version(of: relocated) == "1.1.19")
        precondition(fileManager.fileExists(atPath: relocated.appendingPathComponent("Contents/Info.plist").path))
        // Moving again is a no-op when the same version is already installed.
        let again = try UpdateInstaller.relocate(staged, into: work.appendingPathComponent("Applications"))
        precondition(again.path == relocated.path)

        print("Disk image staging, permission-only patch installation, in-place replacement and relocation tests PASSED")
    }
}
