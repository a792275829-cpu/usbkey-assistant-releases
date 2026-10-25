import Foundation

@main
enum AssistantStatusTests {
    static func main() throws {
        func status(service: Bool = true, trusted: Bool = true, found: Bool = true,
                    signing: String? = "3001", retries: Int? = 5, queried: Bool = true) -> AssistantStatus {
            AssistantStatus(checkedAt: Date(), serviceRunning: service, certificateTrusted: trusted,
                device: queried ? BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: found,
                    certificateCount: 2, certificateFileId: "3001", signingCertificateFileId: signing,
                    retries: retries) : nil)
        }
        precondition(status().isReady)
        precondition(status(retries: nil).isReady)
        precondition(!status(service: false).isReady)
        precondition(!status(trusted: false).isReady && status(trusted: false).actionTitle == "打开本地证书")
        precondition(!status(found: false).isReady && status(found: false).summary.contains("插入"))
        precondition(!status(signing: nil).isReady && status(signing: nil).summary.contains("签名证书"))
        precondition(!status(retries: 0).isReady && status(retries: 0).summary.contains("锁定"))
        precondition(!status(queried: false).isReady && status(queried: false).summary.contains("查询失败"))
        let identity = BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: true,
            certificateCount: 2, certificateFileId: "3001", signingCertificateFileId: "3001", retries: 10,
            organization: "测试单位", holder: "测试持有者", expiresAt: "2029-08-06T02:44:26.000Z")
        let display = AssistantStatus(checkedAt: Date(), serviceRunning: true, certificateTrusted: true, device: identity)
        precondition(display.organizationText == "测试单位" && display.holderText == "测试持有者")
        precondition(display.expiryText == "2029-08-06 10:44:26", "expiry must use Beijing time")
        let multiple = BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: true,
            certificateCount: 4, certificateFileId: nil, signingCertificateFileId: nil, retries: nil,
            deviceCount: 2, requiresSelection: true, devices: [identity, identity])
        let choosing = AssistantStatus(checkedAt: Date(), serviceRunning: true, certificateTrusted: true, device: multiple)
        precondition(!choosing.isReady && choosing.organizationText.contains("请选择"))
        precondition(choosing.summary.contains("2 枚") && !choosing.summary.contains("未找到"))
        let disconnected = BridgeDeviceStatus(service: "netca-ft3000gm", deviceFound: false,
            certificateCount: nil, certificateFileId: nil, signingCertificateFileId: nil, retries: nil,
            organization: "旧单位", holder: "旧持有者", expiresAt: "2029-08-06T02:44:26.000Z")
        let empty = AssistantStatus(checkedAt: Date(), serviceRunning: true, certificateTrusted: true, device: disconnected)
        precondition(!empty.organizationText.contains("旧") && empty.holderText == "—" && empty.expiryText == "—")
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let log = directory.appendingPathComponent("bridge.log")
        let secret = "SECRET-password-certificate-quotation"
        let lines: [[String: Any]] = [
            ["event": "signer_failure", "pinVerified": false, "password": secret],
            ["event": "rpc_request", "method": secret],
            ["event": "unknown", "message": secret]
        ]
        var bytes = Data(repeating: 120, count: 150000)
        bytes.append(10)
        for line in lines { bytes.append(try JSONSerialization.data(withJSONObject: line)); bytes.append(10) }
        try bytes.write(to: log)
        let reason = DiagnosticLog.recentFailure(at: log)
        precondition(reason == "证书密码验证失败")
        let summary = status().diagnosticSummary(version: "test", architecture: "arm64", recentFailure: reason)
        precondition(summary.contains("证书密码验证失败") && !summary.contains(secret))
        let missing = directory.appendingPathComponent("missing.log")
        precondition(DiagnosticLog.recentFailure(at: missing) == nil)
        print("Readiness conditions and diagnostic privacy tests PASSED")
    }
}
