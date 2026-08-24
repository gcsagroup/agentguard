package com.agentguard.companion

/**
 * Extracts a host from text observed on screen, for `network_meta`.
 *
 * # Why this exists
 *
 * `PayloadSerializer.networkMeta` had no caller, so `INTEL-DOMAIN`, `SCOPE-HOST` and
 * `FLOW-NWD` — the rules that decide whether the agent may talk to a host at all — never saw
 * a host on Android. The desktop learns hosts from `guard-netmon` flow summaries; a phone
 * companion has no packet visibility, but a browser's address bar is on screen and is read
 * from the accessibility tree like any other text.
 *
 * # What this is not
 *
 * It is not traffic monitoring. A host observed in an address bar is evidence the agent
 * navigated somewhere, not evidence that bytes moved; the emitted hint says so. Treating it as
 * a flow measurement would put a fabricated `bytes` into an exfiltration rule.
 */
object UrlObserver {

    /** Apps whose visible text plausibly contains an address bar. */
    val BROWSER_PACKAGES = setOf(
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "org.mozilla.firefox",
        "com.microsoft.emmx",
        "com.opera.browser",
        "com.brave.browser",
        "com.sec.android.app.sbrowser",
        "com.heytap.browser",
        "com.vivo.browser",
        "com.android.browser",
        "com.UCMobile.intl",
        "com.tencent.mtt",
        "com.quark.browser",
    )

    const val HINT = "url_observed_on_screen"

    /**
     * The host in [text], or `null`.
     *
     * Accepts a bare host as an address bar shows it (`checkout.stripe.com`) as well as a full
     * URL, because Chrome hides the scheme. Requires a dot and a plausible TLD so ordinary
     * prose does not become a host: "version 2.0" and "3.5 stars" must not be reported, and a
     * fabricated host would be checked against the session's host grant and could refuse a
     * legitimate action.
     */
    fun hostOf(text: String?): String? {
        val raw = text?.trim() ?: return null
        if (raw.isEmpty() || raw.length > 2048) return null
        var s = raw
        // Strip a scheme if present.
        val schemeIdx = s.indexOf("://")
        if (schemeIdx in 1..10) {
            s = s.substring(schemeIdx + 3)
        } else if (s.contains(' ')) {
            // A bare host never contains a space; prose usually does. Requiring one token
            // before the dot test is what keeps "version 2.0" out.
            return null
        }
        // Drop credentials, then take the authority up to the first delimiter. `\` terminates
        // the authority too — WHATWG treats it as `/`, and a host matcher that does not is how
        // `https://good.example\@evil.example` reads as `good.example`.
        s = s.substringAfter('@', s)
        s = s.takeWhile { it != '/' && it != '\\' && it != '?' && it != '#' }
        // Drop a port.
        val colon = s.lastIndexOf(':')
        if (colon > 0 && s.drop(colon + 1).all { it.isDigit() }) {
            s = s.take(colon)
        }
        s = s.trim().trimEnd('.').lowercase()
        if (!looksLikeHost(s)) return null
        return s
    }

    private fun looksLikeHost(s: String): Boolean {
        if (s.length < 4 || s.length > 253) return false
        if (!s.contains('.')) return false
        val labels = s.split('.')
        if (labels.size < 2) return false
        if (labels.any { it.isEmpty() || it.length > 63 }) return false
        if (labels.any { l -> l.any { !(it.isLetterOrDigit() || it == '-') } }) return false
        if (labels.any { it.startsWith('-') || it.endsWith('-') }) return false
        val tld = labels.last()
        // A numeric last label means this is a version string or an IPv4 address. Version
        // strings must not become hosts; a bare IPv4 is excluded too, because the host rules
        // match on dot boundaries and an address has none that mean anything.
        if (tld.length < 2 || tld.any { it.isDigit() }) return false
        return true
    }
}
