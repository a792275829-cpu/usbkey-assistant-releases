// Simulated hardware for offline backend tests. No real device or Keychain access.
import Foundation
import Darwin
let root = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
let args = Array(CommandLine.arguments.dropFirst()), operation = args.first ?? ""
let device = args.count > 2 ? args[2] : "a1"
let state = try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("state.json"))) as! [String: Any]
let mode = state["mode"] as? String ?? "success"
let input = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self).split(separator: "\n").map(String.init)
func log(_ event: String) throws {
    let path = root.appendingPathComponent("helper.jsonl")
    let record: [String: Any] = ["pid": getpid(), "parent": getppid(), "op": operation, "operation": operation, "device": device, "lines": input.count, "event": event]
    var data = try JSONSerialization.data(withJSONObject: record); data.append(10)
    if !FileManager.default.fileExists(atPath: path.path) { FileManager.default.createFile(atPath: path.path, contents: nil) }
    let handle = try FileHandle(forWritingTo: path); defer { try? handle.close() }; try handle.seekToEnd(); try handle.write(contentsOf: data)
}
func output(_ value: [String: Any]) throws { var data = try JSONSerialization.data(withJSONObject: value); data.append(10); try FileHandle.standardOutput.write(contentsOf: data) }
func rsa(_ key: String, _ arguments: [String], _ data: Data) throws -> Data {
    let process = Process(), stdin = Pipe(), stdout = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    process.arguments = ["rsautl"] + arguments + ["-inkey", root.appendingPathComponent(key).path]
    process.standardInput = stdin; process.standardOutput = stdout; process.standardError = FileHandle.nullDevice
    try process.run(); try stdin.fileHandleForWriting.write(contentsOf: data); try stdin.fileHandleForWriting.close()
    let result = stdout.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
    precondition(process.terminationStatus == 0); return result
}
try log("start")
var result: [String: Any]
switch operation {
case "--list-devices": result = ["devices": (state["devices"] as! [String]).map { ["device_id": $0, "device_type": 47] as [String: Any] }]
case "--include-certificate":
    Thread.sleep(forTimeInterval: state["delay"] as? Double ?? 0)
    if let sign = state["sign"] as? String, let enc = state["enc"] as? String {
        result = ["device_found": true, "device_id": device, "device_type": 47, "certificate_count": 2, "certificate_file_ids": "3001;3002", "container_diagnostics": "0:1240010101300109023002", "certificates": [["file_id": "3001", "encode": sign], ["file_id": "3002", "encode": enc]]]
    } else { result = ["device_found": true, "device_id": device, "certificates": [], "certificate_count": 0] }
case "--pin-status": result = ["retries": 5]
default:
    if operation == "--sign-digest-info" && mode == "hang" { Thread.sleep(forTimeInterval: 60) }
    if operation == "--sign-digest-info" && mode == "slow" { Thread.sleep(forTimeInterval: 5) }
    if operation != "--decrypt-rsa-block-no-pin" && (mode == "badpin" || input.first != "fixture-pin") {
        try output(["pin_verified": false, "verify_sw": "63C2", "retries": 2]); exit(4)
    }
    let data = Data(base64Encoded: input.last!)!
    if operation == "--sign-digest-info" {
        let value = mode == "badSignature" ? Data(repeating: 0, count: 256) : try rsa("sign.key", ["-sign"], data)
        result = ["signed": true, "signature_base64": value.base64EncodedString()]
    } else { result = ["decrypted": true, "rsa_block_base64": try rsa("enc.key", ["-decrypt", "-raw"], data).base64EncodedString()] }
}
try log("done"); try output(result)
