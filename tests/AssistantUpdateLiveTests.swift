// Opt-in smoke test: reads and downloads the actual public GitHub release; never installs it.
import Foundation

@main
enum AssistantUpdateLiveTests {
    static func main() throws {
        let release = try JSONDecoder().decode(GitHubRelease.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
        let updater = AssistantUpdater()
        var checked = false
        var downloaded = false
        var progressSeen = false
        var failure: Error?
        var lastReported = -1
        updater.check { result in
            if case .failure(let error) = result { failure = error }
            checked = true
        }
        updater.download(release, progress: { fraction in
            precondition((0...1).contains(fraction))
            progressSeen = true
            let step = Int(fraction * 10)
            if step > lastReported {
                lastReported = step
                print("Installer download: \(step * 10)%")
                fflush(stdout)
            }
        }, completion: { result in
            switch result {
            case .success(let url):
                precondition(FileManager.default.fileExists(atPath: url.path))
                try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            case .failure(let error): failure = error
            }
            downloaded = true
        })
        let deadline = Date().addingTimeInterval(600)
        while (!checked || !downloaded) && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        if let failure { throw failure }
        precondition(checked && downloaded && progressSeen, "Live update check/download timed out")
        print("Public GitHub API, installer download, progress and SHA-256 smoke test PASSED (no installation)")
    }
}
