import Foundation

@main struct CertificatePinStoreTests {
    static func main() throws {
        let service = "cn.gdpower.usbkey-assistant.test.\(UUID().uuidString)"
        defer { _ = CertificatePinStore.perform(["operation": "clear"], service: service) }
        let node = CommandLine.arguments[1]
        let root = CommandLine.arguments[2]
        func run(_ source: String) throws {
            let channel = CertificatePinChannel(service: service)
            defer { channel.close() }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: node)
            process.currentDirectoryURL = URL(fileURLWithPath: root)
            process.arguments = ["--input-type=module", "-e", """
                import assert from 'node:assert/strict';
                import {createKeychainPinStore} from './server/pin-store.mjs';
                const store=createKeychainPinStore();
                const binding='test:'+'C'.repeat(64);
                \(source)
                process.exit(0);
                """]
            process.environment = ["PATH": "/usr/bin:/bin", "USBKEY_PRIVATE_PIN_CHANNEL": "1"]
            process.standardOutput = channel.output
            process.standardInput = channel.input
            try process.run()
            process.waitUntilExit()
            precondition(process.terminationStatus == 0, "Private keychain channel failed")
        }
        try run("await store.write(binding,'test-only-pin'); assert.equal(await store.read(binding),'test-only-pin');")
        try run("assert.equal(await store.read(binding),'test-only-pin'); await store.remove(binding); assert.equal(await store.read(binding),null);")
        print("Native keychain private-pipe write/read/restart/delete tests PASSED")
    }
}
