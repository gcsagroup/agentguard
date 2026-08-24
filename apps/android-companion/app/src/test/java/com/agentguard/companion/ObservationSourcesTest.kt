package com.agentguard.companion

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The three new observation sources, tested where their judgement lives.
 *
 * Each of these turns something on screen into a claim the engine will act on, so each has a
 * way of being confidently wrong: a host invented out of prose gets checked against the
 * session's host grant and can refuse a legitimate action; a permission dialog misread as
 * granted becomes an over-permissioning finding; a keyboard counted as an overlay buries the
 * real overlay in noise.
 */
class ObservationSourcesTest {

    // ---------- UrlObserver ----------

    @Test
    fun `a bare host in an address bar is recognised`() {
        assertEquals("checkout.stripe.com", UrlObserver.hostOf("checkout.stripe.com"))
        assertEquals("example.co.uk", UrlObserver.hostOf("https://example.co.uk/path?q=1"))
        assertEquals("example.com", UrlObserver.hostOf("HTTPS://Example.COM:8443/x"))
    }

    @Test
    fun `prose and version numbers are not hosts`() {
        // The failure this prevents: "version 2.0" reported as a host, checked against the
        // session's host grant, and refusing an action the user asked for.
        assertNull(UrlObserver.hostOf("version 2.0"))
        assertNull(UrlObserver.hostOf("3.5 stars out of 5"))
        assertNull(UrlObserver.hostOf("Total: 99.00"))
        assertNull(UrlObserver.hostOf("hello"))
        assertNull(UrlObserver.hostOf(""))
        assertNull(UrlObserver.hostOf(null))
        // A bare IPv4 has no dot boundary that means anything to the host rules.
        assertNull(UrlObserver.hostOf("192.168.1.1"))
    }

    @Test
    fun `a backslash terminates the authority the way WHATWG says`() {
        // `https://good.example\@evil.example` is a request to evil.example. A host matcher
        // that stops only at `/` reads it as good.example — the exact confusion the Rust
        // `url_host` was fixed for in the session-scope work.
        assertEquals("evil.example", UrlObserver.hostOf("https://good.example\\@evil.example/"))
        assertEquals("good.example", UrlObserver.hostOf("https://good.example\\path"))
    }

    @Test
    fun `credentials before an at sign do not become the host`() {
        assertEquals("evil.example", UrlObserver.hostOf("https://stripe.com@evil.example/pay"))
    }

    // ---------- PermissionDialogReader ----------

    @Test
    fun `an English permission dialog is classified`() {
        val r = PermissionDialogReader.parse("Allow AgentGuard to access your contacts?")
        assertEquals("contacts", r?.itemKey)
        assertEquals(true, r?.granted)
    }

    @Test
    fun `a Chinese permission dialog is classified`() {
        // The market this is built for shows these dialogs in Chinese. An English-only matcher
        // would report a clean over-permissioning score on every device it shipped to, and a
        // clean score reads as a well-behaved agent.
        val r = PermissionDialogReader.parse("允许「订票助手」访问你的通讯录吗？")
        assertEquals("contacts", r?.itemKey)
        assertEquals(true, r?.granted)
        assertEquals("location", PermissionDialogReader.parse("是否允许获取你的位置信息")?.itemKey)
        assertEquals("microphone", PermissionDialogReader.parse("允許使用麥克風")?.itemKey)
    }

    @Test
    fun `dont allow is a denial and not a grant`() {
        // "Don't allow" contains "allow". Testing for allow first classifies every denial as a
        // grant, and a grant is the finding.
        assertEquals(false, PermissionDialogReader.parse("Don't allow access to your location")?.granted)
        assertEquals(false, PermissionDialogReader.parse("拒绝访问通讯录")?.granted)
    }

    @Test
    fun `an unrecognised dialog produces nothing rather than a default`() {
        assertNull(PermissionDialogReader.parse("Sign in to continue"))
        assertNull(PermissionDialogReader.parse(""))
        assertNull(PermissionDialogReader.parse(null))
    }

    @Test
    fun `only the system permission packages are treated as the dialog`() {
        assertTrue(PermissionDialogReader.isController("com.android.permissioncontroller"))
        assertTrue(PermissionDialogReader.isController("com.google.android.permissioncontroller"))
        // Any app may show a dialog that *says* "allow access to your contacts". Only the
        // system controller's counts, or a malicious app could fabricate permission events
        // about other apps.
        assertTrue(!PermissionDialogReader.isController("com.evil.app"))
        assertTrue(!PermissionDialogReader.isController(null))
    }

    // ---------- WindowSurvey ----------

    @Test
    fun `cover ratio is the fraction of the target that is overlapped`() {
        val target = WindowSurvey.Box(0, 0, 100, 100)
        assertEquals(1.0f, WindowSurvey.coverRatio(WindowSurvey.Box(0, 0, 100, 100), target), 0.001f)
        assertEquals(0.25f, WindowSurvey.coverRatio(WindowSurvey.Box(0, 0, 50, 50), target), 0.001f)
        // A window entirely beside the target overlaps nothing.
        assertEquals(0.0f, WindowSurvey.coverRatio(WindowSurvey.Box(200, 0, 300, 100), target), 0.001f)
        // A window larger than the target still caps at 1: the ratio is of the target, not of
        // the intersection over the union, so a full-screen window over a small dialog reads
        // as complete coverage.
        assertEquals(1.0f, WindowSurvey.coverRatio(WindowSurvey.Box(-50, -50, 500, 500), target), 0.001f)
    }

    @Test
    fun `a zero area target cannot produce a coverage finding`() {
        // A collapsed active window would otherwise divide by zero and, depending on the
        // rounding, report every window on screen as covering it.
        assertEquals(0.0f, WindowSurvey.coverRatio(WindowSurvey.Box(0, 0, 10, 10), WindowSurvey.Box(5, 5, 5, 5)), 0.0f)
    }

    @Test
    fun `a keyboard sized window is below the reporting threshold`() {
        // The published attack covers the decision surface, so it is large by construction.
        // A keyboard occupying the bottom third is legitimate and must not be reported.
        val screen = WindowSurvey.Box(0, 0, 1080, 2400)
        val keyboard = WindowSurvey.Box(0, 1600, 1080, 2400)
        assertTrue(WindowSurvey.coverRatio(keyboard, screen) < WindowSurvey.MIN_COVER_RATIO)
        val fakeSheet = WindowSurvey.Box(0, 200, 1080, 2400)
        assertTrue(WindowSurvey.coverRatio(fakeSheet, screen) >= WindowSurvey.MIN_COVER_RATIO)
    }
}
