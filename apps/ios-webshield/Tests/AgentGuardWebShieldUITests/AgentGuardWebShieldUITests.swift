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

    private func auditPagesAndScroll(language: String, locale: String) throws {
        continueAfterFailure = true
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(\(language))", "-AppleLocale", locale]
        app.launch()
        XCTAssertTrue(element("status.value", in: app).waitForExistence(timeout: 5))

        // 逐屏留存原生树和截图；达到隐私说明后停止，不把屏幕外的 exists 当作可操作。
        for page in 0 ..< 12 {
            // 完整审计会切换字号并改变滚动位置；每页从同一初始状态走到目标位置。
            if page > 0 {
                app.terminate()
                app.launch()
                XCTAssertTrue(element("status.value", in: app).waitForExistence(timeout: 5))
                for _ in 0 ..< page { app.swipeUp() }
            }
            let tree = XCTAttachment(string: app.debugDescription)
            tree.name = "\(language)-page-\(page)-tree"
            tree.lifetime = .keepAlways
            add(tree)
            let screenshot = XCTAttachment(screenshot: app.screenshot())
            screenshot.name = "\(language)-page-\(page)"
            screenshot.lifetime = .keepAlways
            add(screenshot)
            let privacy = app.staticTexts["privacy.note"]
            let storage = app.staticTexts["storage.error"]
            let end = storage.exists ? storage : privacy
            // 说明文字不接受点击；以其末尾进入可读窗口为准，不要求静态文字可点击。
            var reachedEnd = false
            if end.exists {
                let bottom = end.frame.maxY
                let window = app.windows.firstMatch.frame
                let bounds = XCTAttachment(string: "page=\(page), end=\(end.identifier), frame=\(end.frame), window=\(window), navigation=\(app.navigationBars.firstMatch.frame)")
                bounds.name = "\(language)-page-\(page)-bounds"
                bounds.lifetime = .keepAlways
                add(bounds)
                reachedEnd = bottom > app.navigationBars.firstMatch.frame.maxY && bottom < window.maxY - 34
            }
            // 保留所有报告；只有已禁用清除按钮的对比度适用非活动控件例外。
            try app.performAccessibilityAudit(for: .all) { issue in
                let detail = XCTAttachment(string: "\(issue.compactDescription)\n\(issue.detailedDescription)\n\(String(describing: issue.element))")
                detail.name = "\(language)-page-\(page)-issue"
                detail.lifetime = .keepAlways
                self.add(detail)
                if issue.auditType == .contrast,
                   let element = issue.element,
                   element.elementType == .button,
                   element.identifier == "audit.clear",
                   !element.isEnabled {
                    let exception = XCTAttachment(string: "已核对禁用的清除按钮；仅此对比度报告按 WCAG 1.4.3 非活动控件例外处理。")
                    exception.name = "\(language)-page-\(page)-inactive-clear-contrast-exception"
                    exception.lifetime = .keepAlways
                    self.add(exception)
                    return true
                }
                return false
            }
            // 审计会临时变更字号；停止条件取自本轮审计前的实际截图与原生树。
            if reachedEnd { return }
        }
        XCTFail("滚动后仍无法完整到达隐私说明的末尾")
    }

    private func element(_ identifier: String, in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: identifier).firstMatch
    }
}
