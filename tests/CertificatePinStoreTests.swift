import Foundation

@main struct CertificatePinStoreTests {
    static func main() throws {
        let service = "cn.gdpower.usbkey-assistant.test.\(UUID().uuidString)"
        defer { _ = CertificatePinStore.perform(["operation": "clear"], service: service) }
        let account = String(repeating: "c", count: 64)
        func session(_ operations: [[String: Any]]) throws -> [[String: Any]] {
            let channel = CertificatePinChannel(service: service); defer { channel.close() }
            return try operations.enumerated().map { index, operation in
                var request = operation; request["privateChannel"] = "pin-store-v1"; request["requestId"] = index
                var data = try JSONSerialization.data(withJSONObject: request); data.append(10)
                try channel.output.fileHandleForWriting.write(contentsOf: data)
                var reply = Data()
                while let byte = try channel.input.fileHandleForReading.read(upToCount: 1), !byte.isEmpty {
                    if byte.first == 10 { break }; reply.append(byte)
                }
                let result = try JSONSerialization.jsonObject(with: reply) as! [String: Any]
                precondition(result["requestId"] as? Int == index); precondition(result["privateChannel"] as? String == "pin-store-v1")
                return result
            }
        }
        let first = try session([["operation": "write", "account": account, "pin": "test-only-pin"], ["operation": "read", "account": account]])
        precondition(first[0]["status"] as? Int == 0); precondition(first[1]["pin"] as? String == "test-only-pin")
        let next = try session([["operation": "read", "account": account], ["operation": "remove", "account": account], ["operation": "read", "account": account]])
        precondition(next[0]["pin"] as? String == "test-only-pin"); precondition(next[1]["status"] as? Int == 0); precondition(next[2]["status"] as? Int == -25300)
        print("Native Keychain private-pipe write/read/channel recreation/delete tests PASSED")
    }
}
