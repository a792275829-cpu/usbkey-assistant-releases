import AppKit

@main
enum AssistantLayoutTests {
    static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.prohibited)
        AppDelegate().verifyLayoutForTesting()
        print("Assistant layout and unrestricted website opening tests PASSED")
    }
}
