// Development and release tools. Never included in the application bundle.
import Foundation
import CryptoKit

let fm = FileManager.default
let project = URL(fileURLWithPath: fm.currentDirectoryPath)
let identifier = "cn.gdpower.usbkeyassistant"
let appName = "广东电力USBKey助手"
struct ToolError: Error, CustomStringConvertible { let description: String; init(_ message: String) { description = message } }
func require(_ condition: Bool, _ message: String) throws { if !condition { throw ToolError(message) } }
@discardableResult func run(_ path: String, _ args: [String], quiet: Bool = false) throws -> String {
    let process = Process(), pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: path); process.arguments = args
    process.standardOutput = pipe
    if quiet { process.standardError = FileHandle.nullDevice }
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
    try require(process.terminationStatus == 0, "Command failed: \(path) (\(process.terminationStatus))")
    return String(decoding: data, as: UTF8.self)
}
func entries(_ root: URL) throws -> [URL] {
    guard let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else { throw ToolError("Cannot enumerate \(root.path)") }
    return enumerator.compactMap { $0 as? URL }
}
func relative(_ file: URL, _ root: URL) -> String {
    let path = file.standardizedFileURL.path
    let prefix = root.resolvingSymlinksInPath().standardizedFileURL.path + "/"
    // Foundation's enumerator resolves /var to /private/var on macOS.
    let canonical = path.hasPrefix(prefix) ? path : file.resolvingSymlinksInPath().path
    precondition(canonical.hasPrefix(prefix), "File lies outside the source directory")
    return String(canonical.dropFirst(prefix.count))
}
func hash(_ file: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
    var digest = SHA256()
    while let data = try handle.read(upToCount: 1_048_576), !data.isEmpty { digest.update(data: data) }
    return digest.finalize().map { String(format: "%02x", $0) }.joined()
}
func plist(_ app: URL) throws -> [String: Any] {
    let data = try Data(contentsOf: app.appendingPathComponent("Contents/Info.plist"))
    guard let value = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { throw ToolError("Invalid application plist") }; return value
}
func option(_ args: [String], _ name: String, fallback: String? = nil) throws -> String {
    if let index = args.firstIndex(of: name), index + 1 < args.count { return args[index + 1] }
    if let fallback { return fallback }; throw ToolError("Missing \(name)")
}
func url(_ path: String) -> URL { URL(fileURLWithPath: path).standardizedFileURL }
func checkBundle(_ app: URL) throws {
    let info = try plist(app), resources = app.appendingPathComponent("Contents/Resources")
    let binaries = ["Contents/MacOS/\(info["CFBundleExecutable"] as? String ?? "")"] + ["usbkey-transport", "usbkey-worker", "ft3000gm-hid-probe", "ft3000gm-signer"].map { "Contents/Resources/bin/\($0)" }
    for name in binaries {
        let file = app.appendingPathComponent(name)
        try require(fm.isExecutableFile(atPath: file.path), "Missing executable: \(file.path)")
        try run("/usr/bin/lipo", ["-verify_arch", "arm64", file.path])
        let lines = try run("/usr/bin/otool", ["-L", file.path]).split(separator: "\n").dropFirst()
        for line in lines {
            let library = line.trimmingCharacters(in: .whitespaces).components(separatedBy: " (")[0]
            try require(library.hasPrefix("/usr/lib/") || library.hasPrefix("/System/Library/"), "External runtime dependency: \(library)")
        }
    }
    for name in ["runtime", "server"] { try require(!fm.fileExists(atPath: resources.appendingPathComponent(name).path), "Legacy directory: \(name)") }
    for file in try entries(app) {
        try require(!["node", "python", "python3"].contains(file.lastPathComponent.lowercased()) && !["js", "mjs", "py", "pyc"].contains(file.pathExtension.lowercased()), "Legacy runtime asset: \(file.path)")
    }
    let notices = try String(contentsOf: resources.appendingPathComponent("THIRD_PARTY_NOTICES.txt"), encoding: .utf8)
    try require(notices.contains("OpenSSL") && notices.contains("Rust standard library"), "Missing license notices")
    print("Native application bundle: arm64, system libraries only, no Node/Python/JavaScript runtime, notices present — PASSED")
}
func notices(_ metadata: URL, _ output: URL, _ sysroot: URL) throws {
    let document = try JSONSerialization.jsonObject(with: Data(contentsOf: metadata)) as! [String: Any]
    let packages = (document["packages"] as! [[String: Any]]).sorted { ($0["name"] as! String, $0["version"] as! String) < ($1["name"] as! String, $1["version"] as! String) }
    var text = "USBKey 助手 — 第三方组件许可\n"
    func licenseName(_ name: String) -> Bool { ["LICENSE", "COPYING", "NOTICE"].contains { name.uppercased().hasPrefix($0) } }
    for package in packages where !(package["source"] is NSNull) {
        let root = url(package["manifest_path"] as! String).deletingLastPathComponent()
        var files = Set<URL>()
        for file in try fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isRegularFileKey]) where licenseName(file.lastPathComponent) { if try file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true { files.insert(file) } }
        for directory in ["licenses", "openssl"] {
            let folder = root.appendingPathComponent(directory)
            if fm.fileExists(atPath: folder.path) {
                for file in try entries(folder) where directory == "licenses" || (file.deletingLastPathComponent() == folder && licenseName(file.lastPathComponent)) {
                    if try file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true { files.insert(file) }
                }
            }
        }
        if let license = package["license_file"] as? String { files.insert(root.appendingPathComponent(license)) }
        text += "\n\(String(repeating: "=", count: 72))\n\(package["name"]!) \(package["version"]!)\nSPDX: \(package["license"] as? String ?? "see license file")\n\(package["repository"] as? String ?? "")\n"
        for file in files.sorted(by: { $0.path < $1.path }) { text += "\n--- \(relative(file, root)) ---\n\(String(decoding: try Data(contentsOf: file), as: UTF8.self))\n" }
    }
    let std = sysroot.appendingPathComponent("share/doc/rust")
    for file in try fm.contentsOfDirectory(at: std, includingPropertiesForKeys: [.isRegularFileKey]).sorted(by: { $0.path < $1.path }) where file.lastPathComponent.hasPrefix("COPYRIGHT") || file.lastPathComponent.hasPrefix("LICENSE") {
        if try file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true { text += "\n--- Rust standard library: \(file.lastPathComponent) ---\n\(String(decoding: try Data(contentsOf: file), as: UTF8.self))\n" }
    }
    try text.write(to: output, atomically: true, encoding: .utf8)
}
struct FileInfo: Equatable { let sha256: String; let mode: String; let size: UInt64 }
func files(_ app: URL) throws -> [String: FileInfo] {
    var result: [String: FileInfo] = [:]
    for file in try entries(app) {
        let path = relative(file, app), values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        if path.hasPrefix("Contents/_CodeSignature/") || file.lastPathComponent == ".DS_Store" || values.isSymbolicLink == true || values.isRegularFile != true { continue }
        let attributes = try fm.attributesOfItem(atPath: file.path)
        result[path] = FileInfo(sha256: try hash(file), mode: String(format: "%04o", (attributes[.posixPermissions] as! NSNumber).intValue & 0o777), size: (attributes[.size] as! NSNumber).uint64Value)
    }; return result
}
func findApp(_ root: URL) throws -> URL {
    for file in try entries(root).sorted(by: { $0.pathComponents.count < $1.pathComponents.count }) where file.pathExtension == "app" {
        if let info = try? plist(file), info["CFBundleIdentifier"] as? String == identifier { return file }
    }; throw ToolError("No matching application in \(root.path)")
}
func patch(_ args: [String]) throws {
    let app = url(try option(args, "--app", fallback: project.appendingPathComponent("build/release/\(appName).app").path))
    let baseline = url(try option(args, "--from")), output = url(try option(args, "--out", fallback: project.appendingPathComponent("dist").path))
    let work = fm.temporaryDirectory.appendingPathComponent("usbkey-patch-\(UUID().uuidString)")
    try fm.createDirectory(at: work, withIntermediateDirectories: true); defer { try? fm.removeItem(at: work) }
    var old = baseline, mounted: URL?
    defer { if let mounted { _ = try? run("/usr/bin/hdiutil", ["detach", mounted.path, "-force"], quiet: true) } }
    switch baseline.pathExtension {
    case "app": break
    case "pkg":
        let expanded = work.appendingPathComponent("baseline")
        try run("/usr/sbin/pkgutil", ["--expand-full", baseline.path, expanded.path]); old = try findApp(expanded)
    case "dmg":
        let mount = work.appendingPathComponent("mount"); try fm.createDirectory(at: mount, withIntermediateDirectories: true)
        try run("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-noautoopen", "-noverify", "-mountpoint", mount.path, baseline.path], quiet: true)
        mounted = mount; old = try findApp(mount)
    default: throw ToolError("Unsupported baseline: \(baseline.path)")
    }
    let info = try plist(app)
    let oldInfo = try plist(old)
    try require(info["CFBundleIdentifier"] as? String == identifier && oldInfo["CFBundleIdentifier"] as? String == identifier, "Unexpected bundle identifier")
    guard let version = info["CFBundleShortVersionString"] as? String, let from = oldInfo["CFBundleShortVersionString"] as? String else { throw ToolError("Missing version") }
    try require(version != from, "Baseline already has current version")
    let current = try files(app), previous = try files(old)
    let changed = current.keys.filter { current[$0] != previous[$0] }.sorted(), removed = previous.keys.filter { current[$0] == nil }.sorted()
    if changed.isEmpty && removed.isEmpty { print("SKIP=identical"); return }
    let manifest: [String: Any] = ["version": version, "from": from, "bundleId": identifier,
        "files": changed.map { ["path": $0, "sha256": current[$0]!.sha256, "mode": current[$0]!.mode] },
        "base": changed.filter { previous[$0] != nil }.map { ["path": $0, "sha256": previous[$0]!.sha256] }, "remove": removed]
    let staging = work.appendingPathComponent("staging"); try fm.createDirectory(at: staging, withIntermediateDirectories: true)
    try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys]).write(to: staging.appendingPathComponent("patch.json"))
    for path in changed {
        let dest = staging.appendingPathComponent(path); try fm.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fm.copyItem(at: app.appendingPathComponent(path), to: dest)
    }
    try fm.createDirectory(at: output, withIntermediateDirectories: true)
    let archive = output.appendingPathComponent("USBKeyAssistant-\(version)-patch-from-\(from).tar.gz")
    // A NUL-delimited file list preserves whitespace and excludes recursive or unlisted entries.
    let list = work.appendingPathComponent("files"); try Data((["patch.json"] + changed).joined(separator: "\0").utf8).write(to: list)
    try run("/usr/bin/tar", ["--no-mac-metadata", "--uid", "0", "--gid", "0", "--uname", "", "--gname", "", "-czf", archive.path, "-C", staging.path, "--null", "--no-recursion", "-T", list.path])
    let size = (try fm.attributesOfItem(atPath: archive.path)[.size] as! NSNumber).uint64Value
    for suffix in ["dmg", "pkg"] {
        let reference = output.appendingPathComponent("\(appName)-\(version)-apple-silicon.\(suffix)")
        if fm.fileExists(atPath: reference.path) {
            let fullSize = (try fm.attributesOfItem(atPath: reference.path)[.size] as! NSNumber).uint64Value
            if !args.contains("--force") && Double(size) > Double(fullSize) * 0.6 { try fm.removeItem(at: archive); try? fm.removeItem(atPath: archive.path + ".sha256"); print("SKIP=patch is \(size) bytes of \(fullSize) bytes"); return }; break
        }
    }
    try "\(hash(archive))  \(archive.lastPathComponent)\n".write(toFile: archive.path + ".sha256", atomically: true, encoding: .utf8)
    print("PATCH=\(archive.path)")
}
func previousVersion(_ directory: URL, _ current: String) throws {
    let regex = try NSRegularExpression(pattern: "-([0-9]+(?:\\.[0-9]+)+)-apple-silicon\\.(dmg|pkg)$")
    let versions = try fm.contentsOfDirectory(atPath: directory.path).compactMap { name -> String? in
        guard let match = regex.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)), let range = Range(match.range(at: 1), in: name) else { return nil }
        return String(name[range])
    }.filter { $0.compare(current, options: .numeric) == .orderedAscending }
    print(versions.max(by: { $0.compare($1, options: .numeric) == .orderedAscending }) ?? "")
}
do {
    let args = Array(CommandLine.arguments.dropFirst())
    guard let command = args.first else { throw ToolError("Usage: project-tool.sh <check-bundle|notices|patch|previous-version> ...") }
    switch command {
    case "check-bundle": try require(args.count == 2, "Expected app path"); try checkBundle(url(args[1]))
    case "notices": try require(args.count >= 3, "Expected metadata and output"); try notices(url(args[1]), url(args[2]), url(option(args, "--sysroot")))
    case "patch": try patch(Array(args.dropFirst()))
    case "previous-version": try require(args.count == 3, "Expected directory and version"); try previousVersion(url(args[1]), args[2])
    default: throw ToolError("Unknown command: \(command)")
    }
} catch { fputs("error: \(error)\n", stderr); exit(1) }
