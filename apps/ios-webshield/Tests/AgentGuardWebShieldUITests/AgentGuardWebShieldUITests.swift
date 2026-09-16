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

    func testFirstScreenContrastAndScrollEnglish() throws {
        try checkFirstScreenContrastAndScroll(language: "en", locale: "en_US")
    }

    func testFirstScreenContrastAndScrollSimplifiedChinese() throws {
        try checkFirstScreenContrastAndScroll(language: "zh-Hans", locale: "zh_CN")
    }

    func testFirstScreenContrastAndScrollTraditionalChinese() throws {
        try checkFirstScreenContrastAndScroll(language: "zh-Hant", locale: "zh_TW")
    }

    private func checkFirstScreenContrastAndScroll(language: String, locale: String) throws {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(\(language))", "-AppleLocale", locale]
        app.launch()
        XCTAssertTrue(element("status.value", in: app).waitForExistence(timeout: 5))

        // 逐屏留存原生树和截图；达到隐私说明后停止，不把屏幕外的 exists 当作可操作。
        for page in 0 ..< 12 {
            let tree = XCTAttachment(string: app.debugDescription)
            tree.name = "\(language)-page-\(page)-tree"
            tree.lifetime = .keepAlways
            add(tree)
            let screenshot = XCTAttachment(screenshot: app.screenshot())
            screenshot.name = "\(language)-page-\(page)"
            screenshot.lifetime = .keepAlways
            add(screenshot)
            // 回归本次文字对比度修正；滚动保留截图与原生树，供独立字体矩阵核对。
            // 逐页完整审计仍有未解决报告，不能把此用例称作全屏可访问性通过。
            if page == 0 { try app.performAccessibilityAudit(for: .contrast) }
            let privacy = app.staticTexts["privacy.note"]
            let storage = app.staticTexts["storage.error"]
            let end = storage.exists ? storage : privacy
            // 说明文字不接受点击；以其末尾进入可读窗口为准，不要求静态文字可点击。
            if end.exists {
                let bottom = end.frame.maxY
                let window = app.windows.firstMatch.frame
                print("page=\(page), end=\(end.identifier), frame=\(end.frame), window=\(window)")
                if bottom > app.navigationBars.firstMatch.frame.maxY && bottom < window.maxY - 34 { return }
            }
            app.swipeUp()
        }
        XCTFail("滚动后仍无法完整到达隐私说明的末尾")
    }

    private func element(_ identifier: String, in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: identifier).firstMatch
    }
}
