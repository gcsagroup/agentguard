package com.agentguard.companion

/**
 * Log egress hygiene for the companion (AgentScan §3.8).
 *
 * # Why this file exists, and why its absence was the whole point
 *
 * Iteration 17 built `guard_privacy::log_safe` in Rust, routed four sinks through it, and
 * claimed "one redactor at every egress". `docs/log-hygiene.md` said, in as many words,
 * *"On Android every one of those `println!`s lands in logcat, which is precisely the
 * channel §3.8 is about."*
 *
 * That was false. The companion is pure Kotlin — it does not load the Rust engine — so
 * **none** of those redacted `println!`s ever runs on a phone. What did run was
 * `Log.d(TAG, envelope.toString())` in [GuardAccessibilityService], writing the full JSON
 * of every accessibility batch — raw `node.text` from up to twelve nodes per window change,
 * plus form-field labels — to logcat, unconditionally, in a release build with
 * `isMinifyEnabled = false`.
 *
 * So the iteration about log leakage hardened four desktop developer CLIs, added a rule
 * warning that another app can read logcat, and left the guard's own logcat write
 * untouched. On the one platform where the paper's attack applies, the guard *was* the
 * leak — which is exactly the sentence the gap review had written about this project, and
 * exactly what the mechanism was supposed to stop.
 *
 * # What it does
 *
 * The same two-part rule as the Rust side, kept intentionally simple because it must be
 * obviously correct rather than clever:
 *
 *  - digit runs longer than [MAX_PLAIN_DIGITS] keep their last four characters and lose the
 *    rest, counting **Unicode** digits, so full-width `１２３` and Arabic-indic `١٢٣` are
 *    masked too (the Rust version's `is_ascii_digit` missed both, in a project shipping a
 *    Chinese-language app);
 *  - separator-grouped runs (space, NBSP, `-`, `.`, `,`) are joined before counting, so
 *    `4242 4242 4242 4242`, `4242.4242.4242.4242` and `078-05-1120` are all covered — the
 *    Rust version tolerated only ASCII space and hyphen, and NBSP is what web UIs emit;
 *  - an email's local part is reduced to its first character, for any script;
 *  - anything after a credential keyword (`password`, `token`, `secret`, `authorization`,
 *    `bearer`, `cookie`, `api_key`, `apikey`) up to whitespace is dropped, as is a
 *    JWT-shaped `eyJ…` token.
 *
 * What it keeps: prose, prices, dates, times, short reference numbers, rule ids. A
 * redactor that mangles those makes logs useless, and useless logs get switched off.
 */
object LogSafe {

    /** Longest digit run left intact: a date, a time, a price, a short order number. */
    const val MAX_PLAIN_DIGITS = 8

    private val CREDENTIAL_KEYWORDS = listOf(
        "password", "passwd", "token", "secret", "authorization", "bearer",
        "cookie", "api_key", "apikey", "access_key", "session",
    )

    private const val SEPARATORS = " -.,    "

    /** Redact text about to be written to logcat, a notification, or shared storage. */
    fun redact(text: String): String {
        if (text.isEmpty()) return text
        var s = maskCredentials(text)
        s = maskJwts(s)
        s = maskDigitRuns(s)
        s = maskEmails(s)
        return s
    }

    /** [redact] plus a length cap, so one line cannot carry a whole screen. */
    fun excerpt(text: String, maxChars: Int = 120): String {
        val safe = redact(text)
        if (safe.length <= maxChars) return safe
        return safe.take(maxChars) + "…(+" + (safe.length - maxChars) + " chars)"
    }

    /**
     * A one-line summary of an envelope: shapes and counts, never content.
     *
     * This is what the service logs now. An excerpt of the screen — even redacted — is not
     * worth putting in logcat when the audit trail already has it: the log line exists so a
     * developer can see that events are flowing, and a count does that.
     */
    fun envelopeSummary(envelope: org.json.JSONObject): String {
        val events = envelope.optJSONArray("events")
        val types = LinkedHashMap<String, Int>()
        for (i in 0 until (events?.length() ?: 0)) {
            val t = events!!.optJSONObject(i)?.optString("type") ?: continue
            types[t] = (types[t] ?: 0) + 1
        }
        val shape = types.entries.joinToString(",") { "${it.key}×${it.value}" }
        return "envelope session=${envelope.optString("session_id").take(8)} " +
            "events=${events?.length() ?: 0} [$shape]"
    }

    private fun maskDigitRuns(text: String): String {
        val out = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            if (!text[i].isDigit()) {
                out.append(text[i])
                i++
                continue
            }
            // Collect the run, allowing single separators between digit groups.
            val start = i
            val digits = StringBuilder()
            var j = i
            while (j < text.length) {
                val c = text[j]
                if (c.isDigit()) {
                    digits.append(c)
                    j++
                } else if (SEPARATORS.indexOf(c) >= 0 && j + 1 < text.length && text[j + 1].isDigit()) {
                    j++
                } else {
                    break
                }
            }
            val raw = text.substring(start, j)
            if (digits.length > MAX_PLAIN_DIGITS) {
                out.append(maskKeepTail(raw, 4))
            } else {
                out.append(raw)
            }
            i = j
        }
        return out.toString()
    }

    private fun maskEmails(text: String): String {
        val at = text.indexOf('@')
        if (at <= 0) return text
        val out = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            if (text[i] != '@' || i == 0 || !isLocalChar(text[i - 1])) {
                out.append(text[i])
                i++
                continue
            }
            // Walk back over the already-emitted local part. `out` is only rewound, never
            // re-scanned, so this stays linear however many `@`s the text contains — the
            // Rust version re-collected its whole output buffer per `@` and went quadratic
            // (81 s on 300 KB).
            var back = out.length
            while (back > 0 && isLocalChar(out[back - 1])) back--
            val first = if (back < out.length) out[back] else '•'
            out.setLength(back)
            out.append(first).append("…@")
            i++
        }
        return out.toString()
    }

    private fun maskCredentials(text: String): String {
        var s = text
        for (kw in CREDENTIAL_KEYWORDS) {
            var from = 0
            while (true) {
                val at = s.indexOf(kw, from, ignoreCase = true)
                if (at < 0) break
                var v = at + kw.length
                while (v < s.length && (s[v] == ' ' || s[v] == ':' || s[v] == '=' || s[v] == '"')) v++
                var end = v
                while (end < s.length && !s[end].isWhitespace() && s[end] != '"' && s[end] != ',') end++
                if (end > v) {
                    s = s.substring(0, v) + "•••" + s.substring(end)
                    from = v + 3
                } else {
                    from = at + kw.length
                }
            }
        }
        return s
    }

    private fun maskJwts(text: String): String {
        var s = text
        var from = 0
        while (true) {
            val at = s.indexOf("eyJ", from)
            if (at < 0) break
            var end = at
            while (end < s.length && (s[end].isLetterOrDigit() || s[end] == '.' || s[end] == '_' || s[end] == '-')) end++
            if (end - at >= 20) {
                s = s.substring(0, at) + "eyJ•••" + s.substring(end)
                from = at + 6
            } else {
                from = at + 3
            }
        }
        return s
    }

    private fun isLocalChar(c: Char): Boolean =
        c.isLetterOrDigit() || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'

    private fun maskKeepTail(value: String, keep: Int): String {
        if (value.length <= keep) return "•".repeat(value.length)
        return "•".repeat(value.length - keep) + value.substring(value.length - keep)
    }
}
