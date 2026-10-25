import Foundation

struct BridgeDeviceStatus: Decodable {
    let service: String
    let deviceFound: Bool
    let certificateCount: Int?
    let certificateFileId: String?
    let signingCertificateFileId: String?
    let retries: Int?
    let organization: String?
    let holder: String?
    let expiresAt: String?
    let deviceId: String?
    let deviceCount: Int?
    let selectedDeviceId: String?
    let requiresSelection: Bool?
    let devices: [BridgeDeviceStatus]?

    init(service: String, deviceFound: Bool, certificateCount: Int?, certificateFileId: String?,
         signingCertificateFileId: String?, retries: Int?, organization: String? = nil,
         holder: String? = nil, expiresAt: String? = nil, deviceId: String? = nil,
         deviceCount: Int? = nil, selectedDeviceId: String? = nil,
         requiresSelection: Bool? = nil, devices: [BridgeDeviceStatus]? = nil) {
        self.service = service; self.deviceFound = deviceFound
        self.certificateCount = certificateCount; self.certificateFileId = certificateFileId
        self.signingCertificateFileId = signingCertificateFileId; self.retries = retries
        self.organization = organization; self.holder = holder; self.expiresAt = expiresAt
        self.deviceId = deviceId; self.deviceCount = deviceCount
        self.selectedDeviceId = selectedDeviceId; self.requiresSelection = requiresSelection; self.devices = devices
    }
}

struct AssistantStatus {
    let checkedAt: Date
    let serviceRunning: Bool
    let certificateTrusted: Bool
    let device: BridgeDeviceStatus?

    var organizationText: String {
        guard let device else { return "暂时无法读取 USBKey" }
        guard device.deviceFound else { return "插入 USBKey 后显示" }
        if device.requiresSelection == true { return "请选择本次使用的 USBKey" }
        guard let value = device.organization, !value.isEmpty else { return "未读取到所属单位" }
        return value
    }

    var holderText: String {
        guard device?.deviceFound == true else { return "—" }
        if device?.requiresSelection == true { return "选择后显示" }
        guard let value = device?.holder, !value.isEmpty else { return "未读取到" }
        return value
    }

    var expiryText: String {
        guard device?.deviceFound == true else { return "—" }
        if device?.requiresSelection == true { return "—" }
        guard let value = device?.expiresAt else { return "未读取到" }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let date = iso.date(from: value) ?? ISO8601DateFormatter().date(from: value)
        guard let date else { return "未读取到" }
        let format = DateFormatter()
        format.locale = Locale(identifier: "zh_CN")
        format.timeZone = TimeZone(identifier: "Asia/Shanghai")
        format.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return format.string(from: date)
    }

    var isReady: Bool {
        serviceRunning && certificateTrusted && device?.deviceFound == true &&
        device?.requiresSelection != true && device?.signingCertificateFileId != nil && device?.retries != 0
    }

    var summary: String {
        if !serviceRunning { return "本地服务尚未就绪，请重试检查" }
        if !certificateTrusted { return "还差一步：信任本地证书" }
        guard let device else { return "设备状态查询失败，请重试检查" }
        if !device.deviceFound { return "请插入 USBKey 后重试检查" }
        if device.requiresSelection == true { return "检测到 \(device.deviceCount ?? device.devices?.count ?? 0) 枚 USBKey，请先选择一枚" }
        if device.signingCertificateFileId == nil { return "未找到签名证书，请检查 USBKey" }
        if device.retries == 0 { return "USBKey 密码已锁定，请联系证书服务商" }
        return "已就绪，可以登录"
    }

    var actionTitle: String {
        serviceRunning && !certificateTrusted ? "打开本地证书" : "重新检查"
    }

    func diagnosticSummary(version: String, architecture: String, recentFailure: String?) -> String {
        let time = ISO8601DateFormatter().string(from: checkedAt)
        return """
        广东电力 USBKey 助手诊断摘要
        检查时间：\(time)
        应用版本：\(version)
        系统：\(ProcessInfo.processInfo.operatingSystemVersionString)
        架构：\(architecture)
        总体状态：\(summary)
        本地服务：\(serviceRunning ? "正常" : "未就绪")
        本地证书信任：\(certificateTrusted ? "正常" : "未完成")
        USBKey：\(device == nil ? "查询失败" : device?.deviceFound == true ? "已连接" : "未检测到")
        公有证书数量：\(device?.certificateCount.map(String.init) ?? "未知")
        签名证书：\(device?.signingCertificateFileId == nil ? "未确认" : "已找到")
        密码剩余尝试次数：\(device?.retries.map(String.init) ?? "未知")
        最近失败：\(recentFailure ?? "没有可用的失败记录")

        摘要不包含密码、证书正文、签名值或报价内容。
        """
    }
}

// Read only a bounded tail and translate allowed fields; never copy raw log lines.
enum DiagnosticLog {
    static func recentFailure(at url: URL) -> String? {
        guard let file = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? file.close() }
        guard let end = try? file.seekToEnd(),
              (try? file.seek(toOffset: end > 131072 ? end - 131072 : 0)) != nil,
              let data = try? file.read(upToCount: 131072) else { return nil }
        for line in String(decoding: data, as: UTF8.self).split(separator: "\n").reversed() {
            guard let value = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  let event = value["event"] as? String else { continue }
            switch event {
            case "signer_failure":
                if value["pinVerified"] as? Bool == false { return "证书密码验证失败" }
                if value["dfAuthenticated"] as? Bool == false { return "USBKey 应用目录认证失败" }
                return "USBKey 私钥操作失败"
            case "rpc_error": return "页面请求处理失败"
            case "rpc_response":
                if let status = value["status"] as? Int, status != 0 { return "页面请求失败（状态码 \(status)）" }
            case "pin_status_unavailable": return "密码剩余尝试次数查询失败"
            default: continue
            }
        }
        return nil
    }
}
