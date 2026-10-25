import Foundation

@main
enum ProcessRunnerTests {
    static func main() {
        let large = ProcessRunner.run(executable: "/usr/bin/awk",
            arguments: ["BEGIN { for (i=0; i<200000; i++) printf \"x\" }"], timeout: 5)
        precondition(large.status == 0 && large.output.utf8.count == 200000,
                     "stdout must be drained before the child exits")
        let missing = ProcessRunner.run(executable: "/nonexistent/gdpower-test", arguments: [])
        precondition(missing.status == -1 && missing.failure != nil)
        let start = Date()
        let timeout = ProcessRunner.run(executable: "/bin/sleep", arguments: ["5"], timeout: 0.1)
        precondition(timeout.failure == "命令执行超时" && Date().timeIntervalSince(start) < 3)
        let bounded = ProcessRunner.run(executable: "/usr/bin/yes", arguments: ["test"], maxOutputBytes: 1024)
        precondition(bounded.failure == "命令输出超出限制" && bounded.output.utf8.count == 1024)
        let failure = ProcessRunner.run(executable: "/usr/bin/false", arguments: [])
        precondition(failure.status != 0 && failure.failure == nil)
        print("ProcessRunner large output, timeout, output limit and failure tests PASSED")
    }
}
