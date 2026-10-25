import AppKit

enum AssistantTheme {
    static let background = color(0xffffff)
    static let sidebar = color(0xf7f7f5)
    static let surface = NSColor.white
    static let ink = color(0x202020)
    static let muted = color(0x777773)
    static let line = color(0xe8e8e5)
    static let hover = color(0xefefec)
    static let accent = color(0x387557)
    static let accentLight = color(0xeff6f0)
    static let primaryFill = color(0x252525)
    static let primaryHover = color(0x404040)
    static let primaryText = NSColor.white
    static let warning = color(0x946b2d)
    static let warningLight = color(0xf8f3e9)
    static func color(_ hex: UInt32) -> NSColor {
        NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
                green: CGFloat((hex >> 8) & 255) / 255,
                blue: CGFloat(hex & 255) / 255, alpha: 1)
    }
    static func label(_ title: String, size: CGFloat, weight: NSFont.Weight = .regular,
                      color: NSColor = ink) -> NSTextField {
        let label = NSTextField(wrappingLabelWithString: title)
        label.font = .systemFont(ofSize: size, weight: weight)
        label.textColor = color
        label.maximumNumberOfLines = 2
        return label
    }
    static func symbol(_ name: String, size: CGFloat, color: NSColor) -> NSImageView {
        let image = NSImageView()
        image.image = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: size, weight: .medium))
        image.contentTintColor = color
        image.translatesAutoresizingMaskIntoConstraints = false
        image.widthAnchor.constraint(equalToConstant: size + 4).isActive = true
        image.heightAnchor.constraint(equalToConstant: size + 4).isActive = true
        return image
    }
    static func vertical(_ views: [NSView], spacing: CGFloat) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = spacing
        return stack
    }
    static func divider(vertical: Bool = false) -> NSView {
        let view = AssistantSurface(fill: line, radius: 0, bordered: false)
        view.translatesAutoresizingMaskIntoConstraints = false
        (vertical ? view.widthAnchor : view.heightAnchor).constraint(equalToConstant: 1).isActive = true
        return view
    }
}

final class AssistantSurface: NSView {
    var fill: NSColor
    let radius: CGFloat
    let bordered: Bool
    init(fill: NSColor = AssistantTheme.surface, radius: CGFloat = 14, bordered: Bool = true) {
        self.fill = fill; self.radius = radius; self.bordered = bordered
        super.init(frame: .zero)
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override var isOpaque: Bool { radius == 0 }
    override func draw(_ dirtyRect: NSRect) {
        fill.setFill()
        let path = NSBezierPath(roundedRect: bordered ? bounds.insetBy(dx: 0.5, dy: 0.5) : bounds,
                               xRadius: radius, yRadius: radius)
        path.fill()
        if bordered { AssistantTheme.line.setStroke(); path.lineWidth = 1; path.stroke() }
    }
    func contain(_ content: NSView, inset: CGFloat) {
        content.translatesAutoresizingMaskIntoConstraints = false
        addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: leadingAnchor, constant: inset),
            content.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -inset),
            content.topAnchor.constraint(equalTo: topAnchor, constant: inset),
            content.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -inset),
        ])
    }
}

final class AssistantButton: NSButton {
    enum Style { case primary, secondary, quiet, navigation, update }
    let style: Style
    var symbolName: String? { didSet { invalidateIntrinsicContentSize(); needsDisplay = true } }
    var isSelected = false { didSet { needsDisplay = true } }
    private var hovering = false
    private var hoverArea: NSTrackingArea?
    init(_ title: String, style: Style = .secondary, symbol: String? = nil, target: AnyObject?, action: Selector) {
        self.style = style; self.symbolName = symbol
        super.init(frame: .zero)
        self.title = title; self.target = target; self.action = action
        isBordered = false
        setButtonType(.momentaryPushIn)
        font = .systemFont(ofSize: 13, weight: style == .primary ? .medium : .regular)
        focusRingType = .exterior
        translatesAutoresizingMaskIntoConstraints = false
        heightAnchor.constraint(equalToConstant: style == .primary ? 40 : (style == .update ? 22 : 36)).isActive = true
        setAccessibilityLabel(title)
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override var intrinsicContentSize: NSSize {
        NSSize(width: (title as NSString).size(withAttributes: [.font: font ?? NSFont.systemFont(ofSize: 12)]).width + (symbolName == nil ? 28 : 48),
               height: style == .primary ? 40 : (style == .update ? 22 : 36))
    }
    override var isEnabled: Bool { didSet { needsDisplay = true } }
    override var title: String { didSet { setAccessibilityLabel(title); invalidateIntrinsicContentSize(); needsDisplay = true } }
    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let hoverArea { removeTrackingArea(hoverArea) }
        let area = NSTrackingArea(rect: bounds, options: [.mouseEnteredAndExited, .activeInKeyWindow, .inVisibleRect], owner: self)
        addTrackingArea(area); hoverArea = area
    }
    override func mouseEntered(with event: NSEvent) { hovering = true; needsDisplay = true }
    override func mouseExited(with event: NSEvent) { hovering = false; needsDisplay = true }
    override func draw(_ dirtyRect: NSRect) {
        let active = isEnabled && (hovering || isHighlighted)
        let fill: NSColor
        let text: NSColor
        switch style {
        case .update:
            fill = active ? AssistantTheme.color(0xb52d39) : AssistantTheme.color(0xd83b48)
            text = .white
        case .primary:
            fill = isEnabled ? (active ? AssistantTheme.primaryHover : AssistantTheme.primaryFill) : AssistantTheme.hover
            text = isEnabled ? AssistantTheme.primaryText : AssistantTheme.muted
        case .secondary:
            fill = active ? AssistantTheme.hover : AssistantTheme.surface
            text = isEnabled ? AssistantTheme.ink : AssistantTheme.muted
        case .quiet:
            fill = active ? AssistantTheme.hover : .clear
            text = isEnabled ? AssistantTheme.muted : AssistantTheme.muted.withAlphaComponent(0.5)
        case .navigation:
            fill = active || isSelected ? AssistantTheme.color(0xeaeae7) : .clear
            text = isEnabled ? AssistantTheme.ink : AssistantTheme.muted
        }
        fill.setFill()
        let radius: CGFloat = style == .primary ? 20 : 8
        let outline = NSBezierPath(roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5), xRadius: radius, yRadius: radius)
        outline.fill()
        if style == .secondary { AssistantTheme.line.setStroke(); outline.lineWidth = 1; outline.stroke() }
        let attributes: [NSAttributedString.Key: Any] = [.font: font ?? NSFont.systemFont(ofSize: 12), .foregroundColor: text]
        let size = (title as NSString).size(withAttributes: attributes)
        let symbolWidth: CGFloat = symbolName == nil ? 0 : 24
        let x = style == .navigation ? 12 : (bounds.width - size.width - symbolWidth) / 2
        (title as NSString).draw(at: NSPoint(x: x + symbolWidth, y: (bounds.height - size.height) / 2), withAttributes: attributes)
        if let name = symbolName,
           let image = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)) {
            let tinted = NSImage(size: NSSize(width: 16, height: 16))
            tinted.lockFocus()
            image.draw(in: NSRect(x: 0, y: 0, width: 16, height: 16))
            text.setFill(); NSRect(x: 0, y: 0, width: 16, height: 16).fill(using: .sourceAtop)
            tinted.unlockFocus()
            tinted.draw(in: NSRect(x: x, y: (bounds.height - 16) / 2, width: 16, height: 16))
        }
        if window?.firstResponder === self {
            AssistantTheme.muted.withAlphaComponent(0.6).setStroke()
            let outline = NSBezierPath(roundedRect: bounds.insetBy(dx: 2, dy: 2), xRadius: radius, yRadius: radius)
            outline.lineWidth = 2; outline.stroke()
        }
    }
}

