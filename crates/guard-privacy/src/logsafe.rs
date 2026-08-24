//! Log egress hygiene (AgentScan §3.8 log leakage).
//!
//! # A guardrail that logs screen text becomes the leak
//!
//! AgentScan reports log leakage against three of the agents it tested. The gap review
//! for this project noted the same risk pointing inward — *"our own logging of AX text is
//! unaudited for this"* — and the previous iteration's review found it live: the semantic
//! firewall reported a **redacted** `••••4242` while the same `Engine::process` call wrote
//! the full PAN into `AuditRecord::event_json`, inside the hash chain, inside the
//! signature, and out through `audit-export`.
//!
//! That one is fixed at the audit path. It was not the only egress. Everything below
//! carried observed text verbatim to somewhere a person or another process can read it:
//!
//! | Sink | What it printed |
//! |---|---|
//! | `StdinConfirm` | `ui: <excerpt>` on **stderr**, i.e. into whatever collects the host's logs |
//! | `sim-capture` / `replay` | `ui={:?}` per event, straight to stdout |
//! | `audit-report` | `human_message`, which rule templates build from event text |
//! | `flow-eval` | an intel finding's `human_message` — found by the scanner, not by me |
//!
//! A guard that is careful in one sink and careless in four has not reduced exposure; it
//! has moved it to the sink nobody audits. So there is one function, every sink calls it,
//! and a source-scanning test fails if a new sink does not.
//!
//! **These are Rust sinks, and every one of them is a developer command.** `StdinConfirm` is
//! never constructed in this repo; the rest are `sim-capture`, `replay`, `audit-report` and
//! `flow-eval`. This module does **not** protect the Android companion: that app is pure
//! Kotlin and does not link the engine, so none of these functions runs on a phone. Its
//! redaction lives in `LogSafe.kt`, and the first version of this iteration shipped this
//! module while the companion was still writing raw accessibility JSON to logcat —
//! documented in `docs/log-hygiene.md` rather than quietly fixed.
//!
//! # Why display masking is stricter than audit masking
//!
//! [`crate::entity::mask_sensitive_runs`] is tuned for the audit row, which is *evidence*:
//! it masks only what could be an account number or credential, and only in fields where a
//! checksum-verified entity was found, because over-masking evidence costs forensic value.
//!
//! A console line and a summary report are not evidence — the audit database is. So
//! [`log_safe`] masks more: every long digit run (grouped or not, in any decimal script),
//! every email's local part (any script), every value after a credential keyword and every
//! JWT, whether or not a checksum confirmed anything. Each of those clauses was narrower
//! than this sentence claimed in the first version — see `docs/log-hygiene.md`'s table of
//! what actually survived. Losing a
//! digit from a console line costs nothing; leaving a national id in a log file that gets
//! attached to a bug report costs the user.
//!
//! What it deliberately keeps readable: prices, dates, times, short reference numbers and
//! all prose. A redactor that mangles `2026-05-02` or `¥128.00` makes logs useless, and
//! useless logs get turned off — the same failure mode as an alert nobody can act on.

use crate::entity::mask_tokens_only;

/// Longest unseparated digit run left intact.
///
/// Eight, so a date (`20260502`), a time, a price and a short order number survive, while
/// a 9-digit SSN, a 10-digit phone number and an 18-digit resident id do not.
const MAX_PLAIN_DIGITS: usize = 8;

/// Separator characters tolerated *inside* a grouped digit run.
///
/// ASCII space and hyphen were the whole list. The consequences were not subtle: a
/// Luhn-valid PAN written `4242.4242.4242.4242`, `4242,4242,4242,4242` or — worst, because
/// it is what web UIs and accessibility flattens actually emit — with a **non-breaking
/// space** reached the log untouched, as did `078-05-1120`, which is the *only* SSN form
/// `entity::scan_ssn` recognises. The doc claimed all of them were masked.
const RUN_SEPARATORS: &[char] = &[
    ' ', '-', '.', ',', '\u{a0}', '\u{2007}', '\u{2009}', '\u{202f}',
];

/// Keywords after which a value is a credential, whatever it looks like.
const CREDENTIAL_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "bearer",
    "cookie",
    "api_key",
    "apikey",
    "access_key",
    "session",
    // With its delimiter, deliberately. Bare `code` is one of the commonest words in a
    // log line — `code: CRIT-001`, `promo code SAVE20` — so masking after every
    // occurrence would mangle exactly the content this threshold exists to keep readable.
    // `code=` is the OAuth query parameter and nothing else.
    "code=",
];

/// Redact text that is about to be printed, logged or summarised.
///
/// Idempotent: masked output contains no long digit runs, no bare `@` local parts, no
/// credential keyword followed by a value and no JWT, so passing it through twice changes
/// nothing. That matters because several sinks compose (a report summarises a message that
/// was already redacted). Verified over random strings seeded with `•`, `…`, `@` and digits
/// from three scripts.
///
/// **Linear**, and that had to be fixed rather than documented: the first cut re-collected
/// its whole output buffer into a `Vec<char>` on every `@`, so text with many of them went
/// quadratic — 300 KB took **81 s**, in the crate whose sibling module says in as many
/// words that a hand-rolled DoS is no better than a regex one. The output is built as a
/// `Vec<char>` and rewound in place instead.
pub fn log_safe(text: &str) -> String {
    // The audit masker's *token* half only — IBAN shapes, credential prefixes, PEM blocks.
    //
    // Not its digit-run half: that one masks every grouped run of 13+ digits with no
    // exemptions, so composing the two put `timestamp_ms=1786508766171` beyond the reach of
    // the exemptions below. The display rule owns digit runs here.
    let staged = mask_tokens_only(text);
    let staged = mask_credentials(&staged);
    let staged = mask_jwts(&staged);
    let chars: Vec<char> = staged.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut i = 0usize;
    while i < chars.len() {
        // Digit runs, counting Unicode digits and tolerating grouping separators.
        //
        // `is_ascii_digit` was the old test, so full-width `１２３４５６７８９` and
        // Arabic-indic `١٢٣٤٥٦٧٨٩` walked straight through — in a project that ships a
        // Chinese-language app and a Chinese resident-id recogniser.
        if is_digit(chars[i]) && (i == 0 || !is_digit(chars[i - 1])) {
            let start = i;
            let mut digits = 0usize;
            let mut j = i;
            while j < chars.len() {
                if is_digit(chars[j]) {
                    digits += 1;
                    j += 1;
                } else if RUN_SEPARATORS.contains(&chars[j])
                    && j + 1 < chars.len()
                    && is_digit(chars[j + 1])
                {
                    j += 1;
                } else if (chars[j] == ')' || chars[j] == ']')
                    && j + 2 < chars.len()
                    && chars[j + 1] == ' '
                    && is_digit(chars[j + 2])
                {
                    // `") "` exactly, for the parenthesised area code — `(415) 555-2671`
                    // is the commonest printed phone form and a single-separator rule
                    // splits it into 3 + 7 digits, both under the threshold.
                    //
                    // Only this pair, and only followed by a digit. Allowing separator
                    // *runs* in general would join `Order 12345678 (ref 9012)` into twelve
                    // digits and mask an order number — the precision this whole threshold
                    // exists to protect.
                    j += 2;
                } else {
                    break;
                }
            }
            if digits > MAX_PLAIN_DIGITS
                && !run_is_exempt(&chars, start)
                && !run_has_unit_suffix(&chars, j)
            {
                let run: String = chars[start..j].iter().collect();
                out.extend(mask_keep_tail(&run, 4).chars());
            } else {
                out.extend(&chars[start..j]);
            }
            i = j;
            continue;
        }
        // Email local parts, any script. `out` is rewound, never re-scanned, which is what
        // keeps this linear in the number of `@`s.
        if chars[i] == '@' && i > 0 && is_local_char(chars[i - 1]) {
            let mut back = out.len();
            while back > 0 && is_local_char(out[back - 1]) {
                back -= 1;
            }
            let first = out.get(back).copied().unwrap_or('•');
            out.truncate(back);
            out.push(first);
            out.push('…');
            out.push('@');
            i += 1;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out.into_iter().collect()
}

/// Keys whose values are engine bookkeeping, not anything about a person.
///
/// Without this the redactor ate the fields this codebase puts on *every* event:
/// `timestamp_ms=1786508766171` became `timestamp_ms=•••••••••6171`, and epoch
/// milliseconds are 13 digits for the next two centuries. A log where every timestamp is
/// masked is the "so noisy it gets switched off" failure the module doc names as its own
/// guiding concern — aimed, in the first cut, at the one field a reader needs to correlate
/// anything.
const BOOKKEEPING_KEYS: &[&str] = &[
    "timestamp_ms",
    "timestamp",
    "ts",
    "seq",
    "bytes",
    "bytes_out",
    "bytes_in",
    "elapsed_ms",
    "duration_ms",
    "count",
    "port",
    "size",
    "limit",
    "offset",
];

/// Currency markers: a large amount is an amount, not an identifier.
const CURRENCY_PREFIXES: &[&str] = &[
    "¥", "$", "€", "£", "₩", "₫", "₹", "rp", "idr", "vnd", "krw", "jpy", "usd", "cny", "total",
];

/// Whether a long digit run should be left readable.
///
/// Three exemptions, each for a class of content a redactor must not eat:
///
/// 1. **A bookkeeping key.** `timestamp_ms=…`, `seq=…`, `bytes_out=…`.
/// 2. **Inside a compound identifier.** A run preceded by `-` or `_` that is itself
///    preceded by an alphanumeric belongs to a token like `ag-1786508766171-0007` (an
///    `evidence_ref`, the handle a report reader correlates by) or a UUID's final group.
///    A card number written `4242-4242-4242-4242` is *not* caught by this, because its run
///    begins after a space — the exemption is about position, not about separators.
/// 3. **A currency amount.** `Rp 100000000` is nine digits and an amount; the doc promises
///    prices stay readable, and that promise was true only at `¥128.00` magnitudes.
fn run_is_exempt(chars: &[char], start: usize) -> bool {
    // (2a) inside a canonical UUID — checked by *shape*, not by "the run is glued to a
    // letter". The looser rule would have exempted `card4242424242424242`, which is the
    // bypass an attacker writes.
    if token_is_uuid(chars, start) {
        return true;
    }
    // (2) inside a compound identifier
    if start >= 2 && matches!(chars[start - 1], '-' | '_') && chars[start - 2].is_alphanumeric() {
        return true;
    }
    // Preceding text, bounded, lowercased once.
    let from = start.saturating_sub(24);
    let before: String = chars[from..start].iter().collect::<String>().to_lowercase();
    let trimmed = before.trim_end_matches([' ', ':', '=', '"']);
    // (1) bookkeeping key
    if BOOKKEEPING_KEYS.iter().any(|k| {
        trimmed.ends_with(k)
            && trimmed[..trimmed.len() - k.len()]
                .chars()
                .next_back()
                .map(|c| !c.is_alphanumeric() && c != '_')
                .unwrap_or(true)
    }) {
        return true;
    }
    // (3) currency
    if CURRENCY_PREFIXES.iter().any(|c| trimmed.ends_with(c)) {
        return true;
    }
    false
}

/// Whether the `[0-9a-f-]` token containing `at` is a canonical UUID (8-4-4-4-12).
fn token_is_uuid(chars: &[char], at: usize) -> bool {
    let hexish = |c: char| c.is_ascii_hexdigit() || c == '-';
    let mut s = at;
    while s > 0 && hexish(chars[s - 1]) {
        s -= 1;
    }
    let mut e = at;
    while e < chars.len() && hexish(chars[e]) {
        e += 1;
    }
    let token: String = chars[s..e].iter().collect();
    let groups: Vec<&str> = token.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&groups)
            .all(|(want, g)| g.len() == *want && g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Units that make a number a measurement rather than an identifier.
const TRAILING_UNITS: &[&str] = &[
    " bytes", " byte", "b ", " kb", " mb", " gb", " ms", "ms ", " s ", " px", " kib", " mib",
];

/// Whether what *follows* the run marks it as a measurement (`1073741824 bytes`).
fn run_has_unit_suffix(chars: &[char], end: usize) -> bool {
    let to = (end + 8).min(chars.len());
    let after: String = chars[end..to].iter().collect::<String>().to_lowercase();
    TRAILING_UNITS.iter().any(|u| after.starts_with(u))
}

/// Decimal digit in any of the scripts a phone or an id is actually written in.
///
/// `is_ascii_digit` was the bug: full-width `１２３` and Arabic-indic `١٢٣` walked straight
/// through, in a project that ships a Chinese-language app and a PRC resident-id
/// recogniser. Explicit blocks rather than `char::is_numeric`, which is the whole `N`
/// category — that would treat `½`, `Ⅶ` and the CJK numeral `一` as digits and mangle
/// ordinary Chinese prose. `char::to_digit` is no use either: it only knows ASCII.
fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
        || matches!(c,
            '\u{ff10}'..='\u{ff19}'   // full-width
            | '\u{0660}'..='\u{0669}' // Arabic-indic
            | '\u{06f0}'..='\u{06f9}' // Extended Arabic-indic
            | '\u{0966}'..='\u{096f}' // Devanagari
        )
}

/// Drop the value after a credential keyword, whatever shape it has.
///
/// The doc claimed "every credential-shaped token" while the implementation was an
/// eleven-prefix allowlist plus a PEM header — so `password=hunter2`,
/// `Authorization: Bearer 2f8a9c1d…`, `Cookie: session=…` and an OAuth `?code=…` all
/// survived. A keyword is weaker evidence than an issuer prefix, which is why this only
/// ever runs on the *display* path, never on the audit row.
fn mask_credentials(text: &str) -> String {
    let mut s = text.to_string();
    let lower_of = |x: &str| x.to_lowercase();
    for kw in CREDENTIAL_KEYWORDS {
        let mut from = 0usize;
        loop {
            let hay = lower_of(&s);
            let Some(rel) = hay[from.min(hay.len())..].find(kw) else {
                break;
            };
            let at = from + rel;
            let mut v = at + kw.len();
            let bytes = s.as_bytes();
            while v < s.len() && matches!(bytes[v], b' ' | b':' | b'=' | b'"') {
                v += 1;
            }
            // `Authorization: Bearer <token>` — the scheme word is not the secret. Without
            // this, `authorization` masked `Bearer` and left the token in the log, which is
            // the failure mode of masking the first thing you find rather than the value.
            const SCHEMES: &[&str] = &["bearer", "basic", "digest", "token"];
            if s.is_char_boundary(v) {
                let rest = &s[v..];
                for scheme in SCHEMES {
                    if rest.len() > scheme.len()
                        && rest.is_char_boundary(scheme.len())
                        && rest[..scheme.len()].eq_ignore_ascii_case(scheme)
                        && rest[scheme.len()..].starts_with(' ')
                    {
                        v += scheme.len() + 1;
                        break;
                    }
                }
            }
            let mut end = v;
            while end < s.len()
                && !s.as_bytes()[end].is_ascii_whitespace()
                && !matches!(s.as_bytes()[end], b'"' | b',' | b';')
            {
                end += 1;
            }
            if end > v && s.is_char_boundary(v) && s.is_char_boundary(end) {
                s = format!("{}•••{}", &s[..v], &s[end..]);
                from = v + 3;
            } else {
                from = at + kw.len();
            }
            if from >= s.len() {
                break;
            }
        }
    }
    s
}

/// Mask JWT-shaped tokens (`eyJ` + base64url), which no issuer prefix covers.
fn mask_jwts(text: &str) -> String {
    let mut s = text.to_string();
    let mut from = 0usize;
    while let Some(rel) = s[from.min(s.len())..].find("eyJ") {
        let at = from + rel;
        let mut end = at;
        let bytes = s.as_bytes();
        while end < s.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'.' | b'_' | b'-'))
        {
            end += 1;
        }
        if end - at >= 20 {
            s = format!("{}eyJ•••{}", &s[..at], &s[end..]);
            from = at + 9;
        } else {
            from = at + 3;
        }
        if from >= s.len() {
            break;
        }
    }
    s
}

/// Local-part character, **any script**. `is_ascii_alphanumeric` left
/// `林元明@lbemobile.com` and `алиса@example.com` untouched while the doc said "every
/// email's local part".
fn is_local_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

/// [`log_safe`] plus a length cap, for a single console line.
///
/// A console line should not be able to dump a whole screen even redacted: the excerpt is
/// there to identify the event, and 2 KB of accessibility tree in a terminal is how the
/// interesting line scrolls away. Note that the cap bounds the *output*, not the work —
/// `log_safe` runs over the whole input first, which is why that function has to be linear.
pub fn log_excerpt(text: &str, max_chars: usize) -> String {
    let safe = log_safe(text);
    let n = safe.chars().count();
    if n <= max_chars {
        return safe;
    }
    let head: String = safe.chars().take(max_chars).collect();
    format!("{head}…(+{} chars)", n - max_chars)
}

/// Same, for an optional field, so call sites stay one expression.
pub fn log_excerpt_opt(text: Option<&String>, max_chars: usize) -> Option<String> {
    text.map(|t| log_excerpt(t, max_chars))
}

fn mask_keep_tail(value: &str, keep: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= keep {
        return "•".repeat(chars.len());
    }
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{}{}", "•".repeat(chars.len() - keep), tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every form a reviewer got through the first version. Each row is a *canonical*
    /// spelling of the thing the doc named as masked, which is what made the gaps bad: the
    /// old test used only the unseparated forms, so it passed while the documented property
    /// was false for the way these values are actually written.
    #[test]
    fn the_canonical_form_of_each_named_class_is_masked() {
        for (input, forbidden) in [
            // Separator-grouped: the only SSN form `entity::scan_ssn` recognises.
            ("SSN 078-05-1120", "078-05-1120"),
            ("call 415-555-2671", "415-555-2671"),
            ("(415) 555-2671", "555-2671"),
            ("415.555.2671", "415.555.2671"),
            ("138 0013 8000", "138 0013 8000"),
            // Separators other than space/hyphen, including a non-breaking space —
            // which is what a web UI and an AX flatten actually emit.
            ("card 4242,4242,4242,4242", "4242,4242,4242,4242"),
            ("card 4242.4242.4242.4242", "4242.4242.4242.4242"),
            ("card 4242\u{a0}4242\u{a0}4242\u{a0}4242", "4242\u{a0}4242"),
            // Non-ASCII digits.
            ("ID １１０１０５１９４９１２３１００２", "１１０１０５１９４９１２３"),
            ("ID ١٢٣٤٥٦٧٨٩٠١٢٣٤", "١٢٣٤٥٦٧٨٩"),
            // Non-ASCII email local parts.
            ("mail 林元明@lbemobile.com", "林元明@"),
            ("mail алиса@example.com", "алиса@"),
            // Credentials with no issuer prefix.
            ("password=hunter2", "hunter2"),
            ("Authorization: Bearer 2f8a9c1d7e6b5a4f3210", "2f8a9c1d7e6b5a4f3210"),
            ("Cookie: session=abc123def456ghi", "abc123def456ghi"),
            ("?code=4/0AY0eXyzAbCdEfGhIjKl", "4/0AY0eXyzAbCdEfGhIjKl"),
            ("aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCY", "wJalrXUtnFEMIK7MDENG"),
            (
                "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
                "eyJhbGciOiJIUzI1NiIs",
            ),
        ] {
            let safe = log_safe(input);
            assert!(
                !safe.contains(forbidden),
                "{input:?} → {safe:?} still contains {forbidden:?}"
            );
        }
    }

    /// The fields this codebase puts on every event must stay readable.
    ///
    /// The first cut masked `timestamp_ms=1786508766171` (epoch ms is 13 digits for the
    /// next two centuries), `evidence_ref=ag-…-0007` (the handle a report reader correlates
    /// by), a UUID's final group, and `Rp 100000000`. A redactor that eats its own project's
    /// log format is the "switched off in a week" failure this module claims to avoid.
    #[test]
    fn the_projects_own_log_fields_survive() {
        for keep in [
            "timestamp_ms=1786508766171",
            "ts=1786508766171 seq=12",
            "evidence_ref=ag-1786508766171-0007",
            "log_id=1c45d8a6-1a24-42e0-83ea-2138307724f7",
            "uuid 550e8400-e29b-41d4-a716-446655440000",
            "Large upload 1073741824 bytes",
            "bytes_out=1073741824",
            "Rp 100000000",
            "Total ¥128000000",
            "commit 9f2a4c1e8b7d6a5f4e3c2b1a09876543",
            "Order 12345678 (ref 9012)",
        ] {
            assert_eq!(log_safe(keep), keep, "{keep:?} was mangled");
        }
        // And the exemptions must not become a bypass: the same digits, presented as a
        // value rather than as bookkeeping, are still masked.
        assert_ne!(
            log_safe("card 4242-4242-4242-4242"),
            "card 4242-4242-4242-4242"
        );
        assert_ne!(log_safe("SSN 078-05-1120"), "SSN 078-05-1120");
        assert_ne!(log_safe("id 11010519491231002"), "id 11010519491231002");
    }

    /// Linear in the number of `@`s.
    ///
    /// The first version re-collected its entire output buffer into a `Vec<char>` on every
    /// `@`: 40 KB of `"a@"` took 1.15 s, 300 KB took **81 s**. `log_excerpt`'s cap does not
    /// help — it bounds the output, not the work — and this crate's sibling module says in
    /// as many words that a hand-rolled DoS is no better than a regex one.
    #[test]
    fn many_at_signs_do_not_go_quadratic() {
        for text in [
            "a@".repeat(60_000),
            "user@host ".repeat(20_000),
            "@".repeat(100_000),
            format!("{}@example.com", "a".repeat(50_000)),
        ] {
            let start = std::time::Instant::now();
            let _ = log_safe(&text);
            assert!(
                start.elapsed().as_millis() < 3_000,
                "{} bytes took {:?}",
                text.len(),
                start.elapsed()
            );
        }
        // Growth must be sub-quadratic: 4× the input must not be ~16× the time.
        let small = "a@".repeat(15_000);
        let big = "a@".repeat(60_000);
        let t0 = std::time::Instant::now();
        let _ = log_safe(&small);
        let s_ms = t0.elapsed().as_secs_f64();
        let t1 = std::time::Instant::now();
        let _ = log_safe(&big);
        let b_ms = t1.elapsed().as_secs_f64();
        assert!(
            b_ms < s_ms * 10.0 + 0.05,
            "4x input took {b_ms:.3}s vs {s_ms:.3}s — superlinear"
        );
    }

    #[test]
    fn secrets_do_not_reach_a_log_line() {
        for (input, forbidden) in [
            ("Saved card 4242 4242 4242 4242", "4242 4242 4242"),
            ("card4242424242424242", "4242424242424242"),
            ("SSN 078051120", "078051120"),
            ("ID 11010519491231002X", "110105194912310"),
            ("phone 13800138000", "13800138000"),
            ("IBAN GB82WEST12345698765432", "WEST1234"),
            ("key sk-abcdefghijklmnopqrstuvwxyz012345", "abcdefghij"),
            ("mail ming.lin@lbemobile.com", "ming.lin@"),
        ] {
            let safe = log_safe(input);
            assert!(
                !safe.contains(forbidden),
                "{input:?} → {safe:?} still contains {forbidden:?}"
            );
        }
    }

    /// A redactor that mangles prices, dates and prose makes logs useless, and useless
    /// logs get switched off. This is the other half of the requirement.
    #[test]
    fn ordinary_log_content_survives_unchanged() {
        for keep in [
            "Booking summary — 2 guests",
            "Total ¥128.00 (tax 12.80)",
            "Check-in 2026-05-02, check-out 2026-05-09",
            "Order 12345678 confirmed at 09:35",
            "Seat 14A gate B7 flight AA1234",
            "确认支付 ¥128.00",
            "[AG_TRANSPARENT_OVERLAY]",
            "CRIT-001 Complete Purchase",
        ] {
            assert_eq!(log_safe(keep), keep, "{keep:?} was altered");
        }
    }

    /// Sinks compose: a report summarises a message that a decision already redacted.
    #[test]
    fn masking_is_idempotent() {
        for input in [
            "Saved card 4242 4242 4242 4242 exp 12/29",
            "mail ming.lin@lbemobile.com and 13800138000",
            "IBAN GB82WEST12345698765432",
        ] {
            let once = log_safe(input);
            assert_eq!(log_safe(&once), once, "{input:?}");
        }
    }

    #[test]
    fn an_excerpt_is_capped_and_says_so() {
        let long = "a".repeat(500);
        let e = log_excerpt(&long, 80);
        assert!(e.starts_with(&"a".repeat(80)));
        assert!(e.ends_with("…(+420 chars)"));
        assert_eq!(log_excerpt("short", 80), "short");
        assert_eq!(log_excerpt_opt(None, 80), None);
    }

    /// Every print sink that touches observed text must go through this module.
    ///
    /// A source-scanning test, and that is a deliberate choice with a stated limit. The
    /// robust alternative is a newtype whose `Display` is redacted, but observed text
    /// arrives in a `HashMap<String, String>` on `GuardEvent`, so there is no type to hang
    /// it on without reshaping the event schema for every adapter. Scanning the source
    /// catches the thing that actually goes wrong — someone adds a `println!` in six months
    /// and nobody remembers this file — and it catches it at `cargo test` rather than in a
    /// user's log.
    ///
    /// What it cannot catch: an alias (`let t = ...get("ui_text"); println!("{t}")`), a
    /// sink that is not a `print` macro (`tracing`, a file write), or a field name added
    /// later. So it is a regression guard, not a proof.
    #[test]
    fn no_print_sink_emits_observed_text_unredacted() {
        const OBSERVED: &[&str] = &[
            "ui_text",
            "ui_excerpt",
            "human_message",
            "clipboard_text",
            "ocr_text",
            "event_json",
        ];
        const REDACTORS: &[&str] = &[
            "log_safe",
            "log_excerpt",
            "log_excerpt_opt",
            "mask_sensitive_runs",
        ];
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        let mut checked = 0usize;
        for dir in ["crates", "adapters", "apps"] {
            for file in rust_files(&root.join(dir)) {
                let Ok(src) = std::fs::read_to_string(&file) else {
                    continue;
                };
                scanned += 1;
                // Test code may print whatever it likes; it is not a shipped sink.
                let test_at = src.find("#[cfg(test)]").unwrap_or(src.len());
                for (at, span) in macro_spans(&src, &["println!", "eprintln!", "print!", "eprint!"])
                {
                    if at >= test_at {
                        continue;
                    }
                    if !OBSERVED.iter().any(|k| span.contains(k)) {
                        continue;
                    }
                    checked += 1;
                    if !REDACTORS.iter().any(|r| span.contains(r)) {
                        offenders.push(format!("{}: {}", file.display(), span.replace('\n', " ")));
                    }
                }
            }
        }
        assert!(scanned > 20, "the scanner found no sources: {scanned}");
        assert!(
            checked >= 3,
            "the scanner found no print sinks touching observed text, so it is proving nothing"
        );
        assert!(
            offenders.is_empty(),
            "print sinks emitting observed text without log_safe/log_excerpt:\n{}",
            offenders.join("\n")
        );
    }

    fn rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return out;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().and_then(|n| n.to_str()) == Some("target") {
                    continue;
                }
                out.extend(rust_files(&p));
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
        out
    }

    /// Whether the byte offset sits inside a `//` line comment.
    fn in_comment(src: &str, at: usize) -> bool {
        let line_start = src[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line = &src[line_start..at];
        line.trim_start().starts_with("//") || line.contains("// ")
    }

    /// Balanced-paren spans of the named macros, with their byte offsets.
    fn macro_spans(src: &str, macros: &[&str]) -> Vec<(usize, String)> {
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        for m in macros {
            let mut from = 0usize;
            while let Some(rel) = src[from..].find(m) {
                let at = from + rel;
                from = at + m.len();
                // `println!` is a prefix of nothing, but `print!` is a suffix of `eprint!`.
                if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
                    continue;
                }
                // The `(` must *immediately* follow the `!`. Scanning forward for the next
                // one made the scanner report a false positive the moment a doc comment
                // mentioned `eprintln!`: it matched the word in prose and then attached the
                // next parenthesis in the file — a function's parameter list — as the
                // "macro span".
                let start = at + m.len();
                if src.as_bytes().get(start) != Some(&b'(') {
                    continue;
                }
                // And a mention inside a comment is not a sink.
                if in_comment(src, at) {
                    continue;
                }
                let mut depth = 0usize;
                let mut end = start;
                for (i, c) in src[start..].char_indices() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = start + i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    if i > 4_000 {
                        break;
                    }
                }
                if end > start {
                    out.push((at, src[start..end].to_string()));
                }
            }
        }
        out
    }

    /// The boundary between "a date survives" and "an identifier does not".
    #[test]
    fn the_digit_threshold_is_where_the_doc_says() {
        assert_eq!(log_safe("20260502"), "20260502", "8 digits: a date");
        assert_eq!(
            log_safe("202605021"),
            "•••••5021",
            "9 digits: an identifier"
        );
    }
}
