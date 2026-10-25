import Foundation
import CryptoKit

final class UpdateProtocol: URLProtocol {
    static var status = 200
    static var payload = Data()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        precondition(request.url?.path == "/repos/example/releases/releases/latest")
        precondition(request.value(forHTTPHeaderField: "Accept") == "application/vnd.github+json")
        let response = HTTPURLResponse(url: request.url!, statusCode: Self.status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.payload)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@main
enum AssistantUpdateTests {
    static func main() throws {
        precondition(ReleaseVersion("v1.1.16")! > ReleaseVersion("1.1.9")!)
        precondition(ReleaseVersion("1.2.0")! == ReleaseVersion("1.2")!)
        precondition(ReleaseVersion("1.1.16-beta") == nil)
        precondition(ReleaseVersion("1..2") == nil)
        precondition(ReleaseVersion("latest") == nil)
        precondition(!AssistantUpdater.validRepository("https://github.com/example/repo"))
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [UpdateProtocol.self]
        let updater = AssistantUpdater(repository: "example/releases", apiSession: URLSession(configuration: config))
        func release(_ version: String, prerelease: Bool = false, draft: Bool = false, host: String = "github.com",
                     patchFrom: String? = nil, image: Bool = false) -> Data {
            let digest = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            var assets = """
            {"name":"USBKeyAssistant-2.0.0-apple-silicon.pkg","browser_download_url":"https://github.com/example/releases/releases/download/v2.0.0/test.pkg","size":3,"digest":"\(digest)"}
            """
            if image {
                assets += """
                ,{"name":"USBKeyAssistant-2.0.0-apple-silicon.dmg","browser_download_url":"https://github.com/example/releases/releases/download/v2.0.0/test.dmg","size":3,"digest":"\(digest)"}
                """
            }
            if let patchFrom {
                assets += """
                ,{"name":"USBKeyAssistant-2.0.0-patch-from-\(patchFrom).tar.gz","browser_download_url":"https://github.com/example/releases/releases/download/v2.0.0/patch.tar.gz","size":3,"digest":"\(digest)"}
                """
            }
            return Data("""
            {"tag_name":"\(version)","html_url":"https://\(host)/example/releases/releases/tag/\(version)","body":"Notes",
            "draft":\(draft),"prerelease":\(prerelease),"assets":[\(assets)]}
            """.utf8)
        }
        func check(_ data: Data, status: Int = 200, verify: @escaping (Result<GitHubRelease?, Error>) -> Void) {
            UpdateProtocol.payload = data; UpdateProtocol.status = status
            var done = false
            updater.check { result in verify(result); done = true }
            let deadline = Date().addingTimeInterval(3)
            while !done && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
            precondition(done, "Update check timed out")
        }
        check(release("v2.0.0")) { result in
            guard case .success(let release?) = result else { preconditionFailure("Missing update") }
            precondition(release.installer != nil)
            // Without a disk image the legacy package is still accepted.
            precondition(release.diskImage == nil)
            precondition(release.plan(installed: "1.1.18")?.kind == .package)
        }
        // The disk image is the normal full-install delivery format.
        check(release("v2.0.0", image: true)) { result in
            guard case .success(let release?) = result else { preconditionFailure("Missing update") }
            precondition(release.diskImage != nil)
            precondition(release.installer?.name.hasSuffix(".dmg") == true)
            precondition(release.plan(installed: "1.1.18")?.kind == .diskImage)
            precondition(release.plan(installed: "1.1.18")?.asset.name.hasSuffix(".dmg") == true)
        }
        // A patch is only offered for the exact installed version it was built from.
        check(release("v2.0.0", patchFrom: "1.1.18", image: true)) { result in
            guard case .success(let release?) = result else { preconditionFailure("Missing update") }
            precondition(release.patch(from: "1.1.18") != nil)
            let patch = release.plan(installed: "1.1.18")
            precondition(patch?.kind == .patch)
            precondition(patch?.kind.isPatch == true)
            precondition(patch?.version == "2.0.0")
            precondition(patch?.installed == "1.1.18")
            // A different installed version gets the full image.
            precondition(release.plan(installed: "1.1.17")?.kind == .diskImage)
            precondition(release.plan(installed: "1.1.18", forceFull: true)?.kind == .diskImage)
            precondition(release.plan(installed: "1.1.18")?.asset.digest?.hasPrefix("sha256:") == true)
        }
        // Without a matching patch asset the full installer is used.
        check(release("v2.0.0")) { result in
            guard case .success(let release?) = result else { preconditionFailure("Missing update") }
            precondition(release.patch(from: "1.1.18") == nil)
            precondition(release.plan(installed: "1.1.18")?.kind == .package)
        }
        // Where the running bundle lives decides whether an update can be
        // written in place; only read-only locations need to be moved first.
        let home = URL(fileURLWithPath: "/Users/example", isDirectory: true)
        for (path, expected) in [
            ("/Applications/App.app", InstallPath.systemApplications),
            ("/Users/example/Applications/App.app", InstallPath.userApplications),
            ("/Users/example/Downloads/App.app", InstallPath.other),
            ("/Users/example/build/release/App.app", InstallPath.other),
            ("/Applications/App.app", InstallPath.systemApplications),
            ("/private/var/folders/xy/T/AppTranslocation/1234-5678/d/App.app", InstallPath.translocated),
            ("/Volumes/USBKey 助手/App.app", InstallPath.readOnlyVolume),
        ] {
            let location = InstallPath.classify(URL(fileURLWithPath: path), home: home)
            precondition(location == expected, "\(path) classified as \(location)")
            precondition(location.canUpdateInPlace == (location.guidance == nil))
        }
        precondition(InstallPath.translocated.guidance != nil)
        precondition(InstallPath.readOnlyVolume.guidance != nil)
        precondition(InstallPath.systemApplications.guidance == nil)
        for version in ["v1.0.0", AssistantUpdater.currentVersion] {
            check(release(version)) { result in
                guard case .success(nil) = result else { preconditionFailure("Unexpected downgrade") }
            }
        }
        for data in [release("v2.0.0", prerelease: true), release("v2.0.0", draft: true)] {
            check(data) { result in guard case .success(nil) = result else { preconditionFailure("Preview update") } }
        }
        for status in [403, 404, 429, 500] {
            check(Data(), status: status) { result in guard case .failure = result else { preconditionFailure("HTTP error ignored") } }
        }
        for data in [Data("invalid".utf8), release("invalid"), release("v2.0.0", host: "example.com")] {
            check(data) { result in guard case .failure = result else { preconditionFailure("Invalid release accepted") } }
        }
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        try Data("abc".utf8).write(to: file)
        let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        try AssistantUpdater.verify(file: file, digest: hash, size: 3)
        for (digest, size) in [(String(repeating: "0", count: 64), Int64(3)), (hash, Int64(4))] {
            do {
                try AssistantUpdater.verify(file: file, digest: digest, size: size)
                preconditionFailure("Corrupted installer accepted")
            } catch UpdateError.checksum {}
        }
        print("Update version, GitHub API, release validation and installer integrity tests PASSED")
    }
}
