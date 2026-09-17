import XCTest

@MainActor
final class AgentGuardWebShieldUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testLaunchShowsLimitedScopeAndConsentGate() {
        let app = XCUIApplication()
        app.launch()

        XCTAssertTrue(element("scope.boundary", in: app).waitForExistence(timeout: 5))
        XCTAssertTrue(element("privacy.toggle", in: app).exists)
        XCTAssertTrue(element("protection.toggle", in: app).exists)
    }

    func testEnablementInstructionsAndClearEntryExist() {
        let app = XCUIApplication()
        app.launch()

        XCTAssertTrue(element("enable.step1", in: app).waitForExistence(timeout: 5))
        let clear = element("audit.clear", in: app)
        for _ in 0 ..< 4 where !clear.isHittable {
            app.swipeUp()
        }
        XCTAssertTrue(clear.waitForExistence(timeout: 3))
    }

    func testPageAuditsAndScrollEnglish() throws {
        try auditPagesAndScroll(language: "en", locale: "en_US")
    }

    func testPageAuditsAndScrollSimplifiedChinese() throws {
        try auditPagesAndScroll(language: "zh-Hans", locale: "zh_CN")
    }

    func testPageAuditsAndScrollTraditionalChinese() throws {
        try auditPagesAndScroll(language: "zh-Hant", locale: "zh_TW")
    }

    private struct VisibleElement {
        let identifier: String
        let label: String
        let frame: CGRect
    }

    private func auditPagesAndScroll(language: String, locale: String) throws {
        continueAfterFailure = true
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(\(language))", "-AppleLocale", locale]
        app.launch()
        XCTAssertTrue(element("status.value", in: app).waitForExistence(timeout: 5))
        // 当前测试验证未签名候选的无记录页面；每段正文和控件都须有连续可见范围。
        var identifiers = ["status.badge", "status.value", "section.protection", "privacy.toggle",
                           "protection.toggle", "protection.note", "section.scope", "scope.boundary",
                           "section.enable", "enable.step1", "enable.step2", "enable.step3", "enable.note",
                           "section.activity", "audit.empty", "audit.clear", "audit.note",
                           "section.privacy", "privacy.note"]
        if element("storage.error", in: app).exists { identifiers.append("storage.error") }
        var coverage: [String: [ClosedRange<CGFloat>]] = [:]
        var heights: [String: CGFloat] = [:]
        var deferred: Set<String> = []
        var reachedEnd = false
        for page in 0 ..< 20 {
            // 完整审计会切换字号并改变滚动位置；每页从相同状态开始。
            if page > 0 {
                app.terminate()
                app.launch()
                XCTAssertTrue(element("status.value", in: app).waitForExistence(timeout: 5))
                for _ in 0 ..< page { scrollOverlappingPage(in: app) }
            }
            let viewport = readableFrame(in: app)
            let snapshots = identifiers.map { identifier in
                let item = element(identifier, in: app)
                XCTAssertTrue(item.exists, "缺少待审计元素：\(identifier)")
                return VisibleElement(identifier: identifier, label: item.label, frame: item.frame)
            }
            attach(app.debugDescription, name: "\(language)-page-\(page)-tree")
            capture(app, name: "\(language)-page-\(page)")
            for item in snapshots where item.frame.height > 0 {
                if let height = heights[item.identifier] {
                    XCTAssertEqual(item.frame.height, height, accuracy: 0.5, "检查前字号或布局发生变化：\(item.identifier)")
                } else {
                    heights[item.identifier] = item.frame.height
                }
                let visible = item.frame.intersection(viewport)
                if !visible.isNull && visible.height > 0 {
                    // 使用元素内部的点坐标；长文也必须逐段覆盖，容差不随文章长度放大。
                    coverage[item.identifier, default: []].append(
                        max(0, visible.minY - item.frame.minY) ...
                        min(item.frame.height, visible.maxY - item.frame.minY)
                    )
                }
            }
            let end = snapshots.last!
            reachedEnd = end.frame.maxY > viewport.minY && end.frame.maxY <= viewport.maxY
            attach("viewport=\(viewport), end=\(end.identifier), frame=\(end.frame)", name: "\(language)-page-\(page)-bounds")
            // 文字识别使用原始页面；其它系统检查可能滚动页面，不能污染像素与辅助功能树的对应。
            try app.performAccessibilityAudit(for: .elementDetection) { issue in
                self.record(issue, name: "\(language)-page-\(page)-element-detection-issue")
                return false
            }
            attach(app.debugDescription, name: "\(language)-page-\(page)-after-element-detection-tree")
            capture(app, name: "\(language)-page-\(page)-after-element-detection")
            // 对比度先在当前字号检查；其余类别可能临时切换字号和滚动位置。
            try app.performAccessibilityAudit(for: .contrast) { issue in
                self.record(issue, name: "\(language)-page-\(page)-issue")
                if self.isInactiveClearContrast(issue) { return true }
                // 部分遮挡的对比度报告必须在完整显示后重查；这不是永久例外。
                if issue.auditType == .contrast, let reported = issue.element {
                    let matches = snapshots.filter { $0.identifier == reported.identifier || $0.label == reported.label }
                    if matches.count == 1, let item = matches.first,
                       item.frame.height <= viewport.height - 24,
                       item.frame.intersects(viewport), !viewport.contains(item.frame) {
                        deferred.insert(item.identifier)
                        self.attach("待完整显示后复查：\(item.identifier), frame=\(item.frame), viewport=\(viewport)",
                                    name: "\(language)-page-\(page)-deferred-contrast")
                        return true
                    }
                }
                return false
            }
            attach(app.debugDescription, name: "\(language)-page-\(page)-after-contrast-tree")
            capture(app, name: "\(language)-page-\(page)-after-contrast")
            try app.performAccessibilityAudit(for: .all.subtracting([.contrast, .elementDetection, .dynamicType])) { issue in
                self.record(issue, name: "\(language)-page-\(page)-stable-issue")
                return false
            }
            // 会变更字号的审计最后执行，不能影响前面的像素和文字识别检查。
            try app.performAccessibilityAudit(for: .dynamicType) { issue in
                self.record(issue, name: "\(language)-page-\(page)-dynamic-type-issue")
                return false
            }
            if reachedEnd { break }
        }
        XCTAssertTrue(reachedEnd, "滚动后仍无法到达说明末尾")
        for identifier in identifiers {
            let ranges = (coverage[identifier] ?? []).sorted { $0.lowerBound < $1.lowerBound }
            var end: CGFloat = 0
            for range in ranges {
                XCTAssertLessThanOrEqual(range.lowerBound, end + 0.5, "可见范围存在缺口：\(identifier)")
                end = max(end, range.upperBound)
            }
            XCTAssertGreaterThanOrEqual(end, (heights[identifier] ?? .infinity) - 0.5, "未覆盖全文：\(identifier)")
            attach("identifier=\(identifier), height=\(heights[identifier] ?? 0), ranges=\(ranges)", name: "\(language)-coverage-\(identifier)")
        }
        for identifier in deferred.sorted() {
            // 复查先回到初始页面，已完整显示的目标无需再滚动，避免从页尾定位时遮挡上方状态。
            app.terminate()
            app.launch()
            XCTAssertTrue(element("status.value", in: app).waitForExistence(timeout: 5))
            let target = element(identifier, in: app)
            moveFullyIntoView(target, in: app)
            let viewport = readableFrame(in: app)
            XCTAssertTrue(viewport.contains(target.frame), "无法完整显示待复查元素：\(identifier)")
            attach("target=\(identifier), frame=\(target.frame), viewport=\(viewport)\n\(app.debugDescription)",
                   name: "\(language)-recheck-\(identifier)-tree")
            capture(app, name: "\(language)-recheck-\(identifier)")
            // 全屏复查该类别。除既有禁用按钮外，任何新报告均直接失败，不再递延。
            try app.performAccessibilityAudit(for: .contrast) { issue in
                self.record(issue, name: "\(language)-recheck-\(identifier)-issue")
                return self.isInactiveClearContrast(issue)
            }
            XCTAssertTrue(readableFrame(in: app).contains(target.frame), "复查过程中目标移出可读窗口")
        }
        attach("covered=\(identifiers.count), deferred=\(deferred.sorted())", name: "\(language)-audit-summary")
    }

    private func scrollOverlappingPage(in app: XCUIApplication) {
        let window = app.windows.firstMatch
        let viewport = readableFrame(in: app)
        let origin = window.coordinate(withNormalizedOffset: CGVector(dx: 0, dy: 0))
        let start = origin.withOffset(CGVector(dx: window.frame.width * 0.55, dy: viewport.maxY - 60))
        let end = origin.withOffset(CGVector(dx: window.frame.width * 0.55,
                                             dy: viewport.maxY - 60 - viewport.height * 0.7 - 10))
        start.press(forDuration: 0.1, thenDragTo: end, withVelocity: .slow, thenHoldForDuration: 0.2)
    }

    private func readableFrame(in app: XCUIApplication) -> CGRect {
        let window = app.windows.firstMatch.frame
        let top = app.navigationBars.firstMatch.frame.maxY
        return CGRect(x: window.minX, y: top, width: window.width, height: window.maxY - 34 - top)
    }

    private func moveFullyIntoView(_ target: XCUIElement, in app: XCUIApplication) {
        let window = app.windows.firstMatch
        for _ in 0 ..< 32 {
            let viewport = readableFrame(in: app).insetBy(dx: 0, dy: 12)
            if viewport.contains(target.frame) { return }
            let distance = viewport.midY - target.frame.midY
            let delta = min(280, max(-280, distance))
            let origin = window.coordinate(withNormalizedOffset: CGVector(dx: 0, dy: 0))
            let startY = delta > 0 ? viewport.minY + 100 : viewport.maxY - 100
            let start = origin.withOffset(CGVector(dx: window.frame.width * 0.55, dy: startY))
            let end = origin.withOffset(CGVector(dx: window.frame.width * 0.55,
                                                 dy: startY + delta + (delta > 0 ? 10 : -10)))
            start.press(forDuration: 0.1, thenDragTo: end, withVelocity: .slow, thenHoldForDuration: 0.2)
        }
    }

    private func isInactiveClearContrast(_ issue: XCUIAccessibilityAuditIssue) -> Bool {
        guard issue.auditType == .contrast, let element = issue.element,
              element.elementType == .button, element.identifier == "audit.clear", !element.isEnabled else { return false }
        attach("已核对禁用的清除按钮；仅此对比度报告按 WCAG 1.4.3 非活动控件例外处理。", name: "inactive-clear-contrast-exception")
        return true
    }

    private func record(_ issue: XCUIAccessibilityAuditIssue, name: String) {
        attach("type=\(issue.auditType.rawValue)\n\(issue.compactDescription)\n\(issue.detailedDescription)\n\(String(describing: issue.element))", name: name)
    }

    private func capture(_ app: XCUIApplication, name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func attach(_ text: String, name: String) {
        let attachment = XCTAttachment(string: text)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func element(_ identifier: String, in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: identifier).firstMatch
    }
}
