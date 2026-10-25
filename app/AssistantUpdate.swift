import Foundation
import CryptoKit

struct ReleaseVersion: Comparable {
    let parts: [Int]
    init?(_ value: String) {
        var text = value
        if text.hasPrefix("v") { text.removeFirst() }
        let segments = text.split(separator: ".", omittingEmptySubsequences: false)
        guard (2...4).contains(segments.count), segments.allSatisfy({
            !$0.isEmpty && $0.allSatisfy({ $0.isASCII && $0.isNumber }) && Int($0) != nil
        }) else { return nil }
        parts = segments.map { Int($0)! }
    }
    static func == (lhs: Self, rhs: Self) -> Bool { !(lhs < rhs) && !(rhs < lhs) }
    static func < (lhs: Self, rhs: Self) -> Bool {
        for index in 0..<max(lhs.parts.count, rhs.parts.count) {
            let left = index < lhs.parts.count ? lhs.parts[index] : 0
            let right = index < rhs.parts.count ? rhs.parts[index] : 0
            if left != right { return left < right }
        }
        return false
    }
}

struct GitHubRelease: Decodable {
    struct Asset: Decodable {
        let name: String
        let browser_download_url: URL
        let size: Int64
        let digest: String?
    }
    let tag_name: String
    let html_url: URL
    let body: String?
    let draft: Bool
    let prerelease: Bool
    let assets: [Asset]

    func newer(than current: String) -> Bool {
        guard !draft, !prerelease, let latest = ReleaseVersion(tag_name),
              let installed = ReleaseVersion(current) else { return false }
        return latest > installed
    }
    /// Release version without the leading `v`.
    var version: String { tag_name.hasPrefix("v") ? String(tag_name.dropFirst()) : tag_name }
    /// Drag-and-drop disk image: the distribution format users install from.
    var diskImage: Asset? {
        assets.first { $0.name == "USBKeyAssistant-\(version)-apple-silicon.dmg" }
    }
    /// Flat package, still published for installations that predate the image.
    var package: Asset? {
        assets.first { $0.name == "USBKeyAssistant-\(version)-apple-silicon.pkg" }
    }
    var installer: Asset? { diskImage ?? package }
    /// Incremental archive published for this exact base version.
    func patch(from installed: String) -> Asset? {
        assets.first { $0.name == "USBKeyAssistant-\(version)-patch-from-\(installed).tar.gz" }
    }
    /// Prefer the patch when it applies to the installed version, otherwise the
    /// full installer. A patch that fails its baseline check falls back to this
    /// same decision with `forceFull`.
    func plan(installed: String, forceFull: Bool = false) -> UpdatePlan? {
        if !forceFull, let patch = patch(from: installed) {
            return UpdatePlan(kind: .patch, asset: patch, version: version, installed: installed)
        }
        if let diskImage {
            return UpdatePlan(kind: .diskImage, asset: diskImage, version: version, installed: installed)
        }
        if let package {
            return UpdatePlan(kind: .package, asset: package, version: version, installed: installed)
        }
        return nil
    }
}

enum UpdateKind: Equatable {
    /// Only the changed files, applied on top of the installed bundle.
    case patch
    /// Full application inside a drag-and-drop disk image.
    case diskImage
    /// Full application inside a flat package (legacy releases only).
    case package

    var isPatch: Bool { self == .patch }
}

/// Where the running bundle lives, which decides how an update is written.
///
/// A bundle copied out of a disk image belongs to the user who copied it, so
/// `/Applications/<app>` can be replaced in place without an administrator
/// password. Bundles launched straight from a mounted image or from a
/// quarantined download run inside a read-only AppTranslocation directory and
/// cannot update themselves at all until they are moved.
enum InstallPath: Equatable {
    case systemApplications
    case userApplications
    case other
    case translocated
    case readOnlyVolume

    static func classify(_ bundle: URL,
                         home: URL = FileManager.default.homeDirectoryForCurrentUser) -> InstallPath {
        let path = bundle.resolvingSymlinksInPath().standardizedFileURL.path
        if path.contains("/AppTranslocation/") { return .translocated }
        if path.hasPrefix("/Volumes/") { return .readOnlyVolume }
        if path.hasPrefix("/Applications/") { return .systemApplications }
        let userApplications = home.appendingPathComponent("Applications", isDirectory: true).path
        if path.hasPrefix(userApplications + "/") { return .userApplications }
        return .other
    }

    var canUpdateInPlace: Bool {
        switch self {
        case .translocated, .readOnlyVolume: return false
        case .systemApplications, .userApplications, .other: return true
        }
    }

    /// Explanation shown instead of an update button when the bundle has to be
    /// moved before it can be replaced.
    var guidance: String? {
        switch self {
        case .translocated, .readOnlyVolume:
            return "当前版本是从安装镜像或下载副本直接运行的，无法就地更新。请先把应用移到“应用程序”文件夹。"
        case .systemApplications, .userApplications, .other:
            return nil
        }
    }
}

struct UpdatePlan {
    let kind: UpdateKind
    let asset: GitHubRelease.Asset
    let version: String
    let installed: String
    var downloadName: String { (asset.name as NSString).lastPathComponent }
}

enum UpdateError: LocalizedError {
    case configuration, http(Int), invalidRelease, missingInstaller, checksum, cancelled, busy
    var errorDescription: String? {
        switch self {
        case .configuration: return "尚未配置 GitHub 更新仓库。"
        case .http(403), .http(429): return "GitHub 请求次数已达上限，请稍后重试。"
        case .http(404): return "更新仓库尚未发布正式版本。"
        case .http(let status): return "更新服务返回错误（HTTP \(status)）。"
        case .invalidRelease: return "GitHub 版本信息无效，请稍后重试。"
        case .missingInstaller: return "此版本尚未提供 Apple 芯片安装包，请查看发布页面。"
        case .checksum: return "更新包校验失败，已停止安装。"
        case .cancelled: return "已取消下载。"
        case .busy: return "上次下载正在结束，请稍后重试。"
        }
    }
}

final class AssistantUpdater: NSObject, URLSessionDownloadDelegate {
    static let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.1.18"
    static var repository: String { Bundle.main.object(forInfoDictionaryKey: "GitHubUpdateRepository") as? String ?? "a792275829-cpu/usbkey-assistant-releases" }
    private let repository: String
    private let apiSession: URLSession
    private var downloadSession: URLSession?
    private var task: URLSessionDownloadTask?
    private var downloadCompletion: ((Result<URL, Error>) -> Void)?
    private var progress: ((Double) -> Void)?
    private var expectedDigest: String?
    private var expectedSize: Int64 = 0
    private var downloadName = "USBKeyAssistant.download"

    init(repository: String = AssistantUpdater.repository, apiSession: URLSession = .shared) {
        self.repository = repository
        self.apiSession = apiSession
    }
    var releasesURL: URL? { URL(string: "https://github.com/\(repository)/releases") }
    static func validRepository(_ value: String) -> Bool {
        value.range(of: #"^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$"#, options: .regularExpression) != nil
    }
    private func trustedReleaseURL(_ url: URL) -> Bool {
        url.scheme == "https" && url.host == "github.com" && url.user == nil && url.password == nil &&
            url.path.hasPrefix("/\(repository)/releases/")
    }
    func check(completion: @escaping (Result<GitHubRelease?, Error>) -> Void) {
        guard Self.validRepository(repository), let url = URL(string: "https://api.github.com/repos/\(repository)/releases/latest") else {
            completion(.failure(UpdateError.configuration)); return
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("USBKeyAssistant/\(Self.currentVersion)", forHTTPHeaderField: "User-Agent")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        apiSession.dataTask(with: request) { data, response, error in
            let result: Result<GitHubRelease?, Error>
            do {
                if let error { throw error }
                guard let response = response as? HTTPURLResponse else { throw UpdateError.invalidRelease }
                guard response.statusCode == 200 else { throw UpdateError.http(response.statusCode) }
                let release = try JSONDecoder().decode(GitHubRelease.self, from: data ?? Data())
                guard ReleaseVersion(release.tag_name) != nil, self.trustedReleaseURL(release.html_url) else { throw UpdateError.invalidRelease }
                result = .success(release.newer(than: Self.currentVersion) ? release : nil)
            } catch { result = .failure(error) }
            DispatchQueue.main.async { completion(result) }
        }.resume()
    }
    /// GitHub publishes the SHA-256 and the byte count for every asset; both are
    /// required before an archive is allowed to touch the installation.
    static func signedDigest(_ asset: GitHubRelease.Asset) -> (digest: String, size: Int64)? {
        guard asset.size > 0, let digest = asset.digest,
              digest.range(of: #"^sha256:[a-fA-F0-9]{64}$"#, options: .regularExpression) != nil else { return nil }
        return (String(digest.dropFirst(7)).lowercased(), asset.size)
    }
    func download(_ asset: GitHubRelease.Asset, progress: @escaping (Double) -> Void,
                  completion: @escaping (Result<URL, Error>) -> Void) {
        guard task == nil else { completion(.failure(UpdateError.busy)); return }
        guard trustedReleaseURL(asset.browser_download_url), let signed = Self.signedDigest(asset) else {
            completion(.failure(UpdateError.invalidRelease)); return
        }
        expectedDigest = signed.digest
        expectedSize = signed.size
        downloadName = (asset.name as NSString).lastPathComponent
        self.progress = progress
        downloadCompletion = completion
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 1800
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        downloadSession = session
        task = session.downloadTask(with: asset.browser_download_url)
        task?.resume()
    }
    func cancel() { task?.cancel() }
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        let fraction = min(1, Double(totalBytesWritten) / Double(max(1, expectedSize)))
        DispatchQueue.main.async { self.progress?(fraction) }
    }
    static func verify(file: URL, digest: String, size: Int64) throws {
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        var hash = SHA256()
        var count: Int64 = 0
        while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty {
            count += Int64(data.count)
            hash.update(data: data)
        }
        let actual = hash.finalize().map { String(format: "%02x", $0) }.joined()
        guard actual == digest.lowercased(), count == size else { throw UpdateError.checksum }
    }
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        do {
            guard let response = downloadTask.response as? HTTPURLResponse else { throw UpdateError.invalidRelease }
            guard response.statusCode == 200 else { throw UpdateError.http(response.statusCode) }
            guard let expectedDigest else { throw UpdateError.checksum }
            try Self.verify(file: location, digest: expectedDigest, size: expectedSize)
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent("USBKeyUpdate-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let destination = directory.appendingPathComponent(downloadName)
            try FileManager.default.moveItem(at: location, to: destination)
            finish(.success(destination))
        } catch { finish(.failure(error)) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure((error as NSError).code == NSURLErrorCancelled ? UpdateError.cancelled : error)) }
    }
    private func finish(_ result: Result<URL, Error>) {
        DispatchQueue.main.async {
            let completion = self.downloadCompletion
            self.downloadCompletion = nil
            self.progress = nil
            self.task = nil
            self.downloadSession?.finishTasksAndInvalidate()
            self.downloadSession = nil
            completion?(result)
        }
    }
}
