import Foundation
import Darwin

struct ProcessResult {
    let status: Int32
    let output: String
    let failure: String?
}

// Call on a worker queue. stdout is drained while the child runs.
enum ProcessRunner {
    private final class OutputBuffer: @unchecked Sendable {
        let lock = NSLock()
        var data = Data()
        var exceeded = false
    }

    static func run(executable: String, arguments: [String],
                    timeout: TimeInterval = 15, maxOutputBytes: Int = 1024 * 1024,
                    mergeStderr: Bool = false) -> ProcessResult {
        let process = Process()
        let pipe = Pipe()
        let exited = DispatchSemaphore(value: 0)
        let drained = DispatchGroup()
        let output = OutputBuffer()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = mergeStderr ? pipe : FileHandle.nullDevice
        process.terminationHandler = { _ in exited.signal() }
        do {
            try process.run()
        } catch {
            return ProcessResult(status: -1, output: "", failure: error.localizedDescription)
        }
        pipe.fileHandleForWriting.closeFile()
        drained.enter()
        DispatchQueue.global(qos: .utility).async {
            defer { drained.leave() }
            while true {
                let chunk = pipe.fileHandleForReading.availableData
                if chunk.isEmpty { break }
                output.lock.lock()
                let remaining = max(0, maxOutputBytes - output.data.count)
                output.data.append(chunk.prefix(remaining))
                output.exceeded = output.exceeded || chunk.count > remaining
                let exceeded = output.exceeded
                output.lock.unlock()
                if exceeded && process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
        }
        let timedOut = exited.wait(timeout: .now() + timeout) == .timedOut
        if timedOut {
            kill(process.processIdentifier, SIGKILL)
            _ = exited.wait(timeout: .now() + 2)
        }
        // A descendant retaining stdout must not make the caller wait forever.
        let drainTimedOut = drained.wait(timeout: .now() + 2) == .timedOut
        output.lock.lock()
        let text = String(decoding: output.data, as: UTF8.self)
        let exceeded = output.exceeded
        output.lock.unlock()
        let failure = timedOut ? "命令执行超时" : exceeded ? "命令输出超出限制" : drainTimedOut ? "命令输出读取超时" : nil
        return ProcessResult(status: failure == nil ? process.terminationStatus : -1,
                             output: text, failure: failure)
    }
}
