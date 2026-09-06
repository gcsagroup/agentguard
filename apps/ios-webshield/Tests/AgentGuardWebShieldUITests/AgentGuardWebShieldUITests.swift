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

    private func element(_ identifier: String, in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: identifier).firstMatch
    }
}
