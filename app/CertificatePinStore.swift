import Foundation
import Security

// Only the main application owns the keychain identity. The browser cannot
// read these values, and no helper executable offers a credential-read command.
enum CertificatePinStore {
    static func perform(_ input: [String: Any], service: String = "cn.gdpower.usbkey-assistant.certificate-pin.v1") -> [String: Any] {
        guard let operation = input["operation"] as? String,
              ["read", "write", "remove", "clear"].contains(operation) else { return ["status": Int(errSecParam)] }
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        if operation != "clear" {
            guard let account = input["account"] as? String, account.utf8.count == 64,
                  account.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                return ["status": Int(errSecParam)]
            }
            query[kSecAttrAccount as String] = account
        }
        var status: OSStatus
        switch operation {
        case "read":
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecSuccess, let data = result as? Data, let pin = String(data: data, encoding: .utf8) {
                return ["status": 0, "pin": pin]
            }
        case "write":
            guard let pin = input["pin"] as? String, !pin.isEmpty, pin.utf8.count <= 64,
                  !pin.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\0" }) else { return ["status": Int(errSecParam)] }
            let attributes = [kSecValueData as String: Data(pin.utf8)]
            status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if status == errSecItemNotFound {
                query[kSecValueData as String] = Data(pin.utf8)
                query[kSecAttrLabel as String] = "广东电力 USBKey 证书密码"
                status = SecItemAdd(query as CFDictionary, nil)
            }
        default: status = SecItemDelete(query as CFDictionary)
        }
        return ["status": Int(status)]
    }
}

// These anonymous pipes are inherited only by this application's bridge child.
final class CertificatePinChannel {
    let output = Pipe()
    let input = Pipe()
    private let queue = DispatchQueue(label: "cn.gdpower.usbkey.pin-channel")
    private var buffered = Data()
    private let service: String
    init(service: String = "cn.gdpower.usbkey-assistant.certificate-pin.v1") {
        self.service = service
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let self else { return }
            self.queue.async { self.receive(data) }
        }
    }
    private func receive(_ data: Data) {
        buffered.append(data)
        while let end = buffered.firstIndex(of: 10) {
            let line = Data(buffered.prefix(upTo: end))
            buffered.removeSubrange(...end)
            guard line.count <= 8192,
                  let request = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
                  request["privateChannel"] as? String == "pin-store-v1",
                  let id = request["requestId"] as? Int else { continue }
            var reply = CertificatePinStore.perform(request, service: service)
            reply["privateChannel"] = "pin-store-v1"; reply["requestId"] = id
            if var encoded = try? JSONSerialization.data(withJSONObject: reply) {
                encoded.append(10)
                try? input.fileHandleForWriting.write(contentsOf: encoded)
            }
        }
        if buffered.count > 32768 { buffered.removeAll(keepingCapacity: false) }
    }
    func close() { output.fileHandleForReading.readabilityHandler = nil }
    deinit { close() }
}
