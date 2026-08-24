//! Text anomalies and glitch tokens (AgentScan §3.7).
//!
//! AgentScan tests glitch tokens against five agents and lists the class as **unresolved**.
//! The gap review's note for this project was one sentence: *"No detection. A
//! non-printable-run / tokenizer-anomaly check on ingested `ui_text` is cheap."*
//!
//! # What this is about, and why it is a different class from the firewall's
//!
//! `isolation::detect_breakout` catches content claiming to be a different *speaker*.
//! `entity::recognise` catches content that *is* something sensitive. This catches content
//! that is shaped to be read differently by a **model** than by the **person** looking at
//! the same screen:
//!
//! * text a human cannot see at all — the zero-width space, the word joiner, the Unicode
//!   **tag** block and the variation selectors, which are the two current vehicles for
//!   invisible prompt injection;
//! * text a human sees in a different *order* — the two bidi **overrides** behind Trojan
//!   Source;
//! * words that look Latin and are not — a Cyrillic `а` inside `Confirm`, which is how a
//!   lookalike button label is built;
//! * tokenizer stress — combining-mark stacks, and single tokens long enough to be a
//!   payload rather than a word.
//!
//! The unifying property is a **divergence between what is rendered and what is read**.
//! That is worth a finding on its own, because every other check in this project reasons
//! about the text as a string and a human reasons about it as pixels.
//!
//! # What it is not
//!
//! Not general glitch-token detection, and the difference matters. A glitch token is a
//! property of one tokenizer's training data — ` SolidGoldMagikarp` is famous because of
//! what GPT-2's BPE did with it, and the equivalent for another model is a different string
//! nobody has published. [`GLITCH_TOKENS`] is a snapshot of public research, so it is a
//! *tripwire*, not coverage: an attacker who reads the list picks something else. The
//! structural classes above are the part that does not depend on knowing the model.
//!
//! # Precision comes first, again
//!
//! Every rule here had to survive the corpus this project cares about. Six did not, and the
//! first version of this doc claimed precision it did not have — a reviewer fed it real
//! screens and each of these was a finding on ordinary content:
//!
//! * **ZWJ and ZWNJ are not flagged.** `U+200D` builds every family, profession and
//!   flag-with-modifier emoji (15 of 15 tested were findings) and `U+200C` is grammatically
//!   required in Persian.
//! * **The soft hyphen is not flagged.** `&shy;` is how German hyphenates.
//! * **A tag run after `U+1F3F4` is not flagged.** Subdivision flag emoji *are* tag
//!   sequences, so "the tag block has no legitimate use in UI text" — which this doc used to
//!   say — is false.
//! * **Only the two bidi overrides `U+202D`/`U+202E` are flagged.** The plain marks
//!   `U+200E`/`U+200F` are ordinary in every RTL interface, and the *isolates*
//!   `U+2066`–`U+2069` are how ICU and Mozilla Fluent wrap every interpolated value.
//! * **Greek is not a confusable.** Single Greek letters are engineering notation: `Δtime`,
//!   `250 μsec`, `Ωmeter`. Cyrillic only.
//! * **Private-use characters are not flagged**, though they look suspicious: Material
//!   Icons and most icon fonts put their glyphs there, so a run of them is an ordinary
//!   toolbar.
//! * **CJK is never a homoglyph finding.** Chinese and Japanese UI text mixes scripts by
//!   design — a brand name in Latin inside a Chinese sentence is every second screen in this
//!   project's own corpus.
//!
//! One more thing precision needed and did not have: a **latch**. The finding is a property
//! of the screen, not of an event, and as a per-event Alert it produced forty alerts for
//! forty identical UI deltas of a message list containing one emoji. `Engine` reports it once
//! per class per session, the same shape of fix `APP-UNATTESTED` needed for the same reason.
//!
//! The combining-stack threshold of three deserves its own caveat, because the reason first
//! given for it was wrong: [`is_combining`] lists only the generic diacritic blocks, so
//! Devanagari, Thai, Arabic and Hebrew marks are not tested at all and the threshold is
//! irrelevant for every script that was cited to justify it. The class works for
//! `U+0300`-range stacking and nothing else, and `docs/text-anomalies.md` says so rather than
//! implying broader coverage.

use serde::{Deserialize, Serialize};

/// What is wrong with the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    /// Characters a human cannot see: zero-width space, word joiner, tag block, variation
    /// selectors. Not ZWJ/ZWNJ/soft hyphen — see the module doc.
    InvisibleText,
    /// The two bidi **override** controls — the text renders in a different order than it
    /// reads (Trojan Source). Not the isolates, which ICU uses for interpolation.
    BidiOverride,
    /// A predominantly Latin word containing Cyrillic lookalikes.
    Homoglyph,
    /// Three or more stacked combining marks.
    CombiningStack,
    /// A single unbroken token long enough to be a payload rather than a word.
    OversizedToken,
    /// A string from the published glitch-token list.
    GlitchToken,
}

impl AnomalyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvisibleText => "invisible_text",
            Self::BidiOverride => "bidi_override",
            Self::Homoglyph => "homoglyph",
            Self::CombiningStack => "combining_stack",
            Self::OversizedToken => "oversized_token",
            Self::GlitchToken => "glitch_token",
        }
    }

    /// Why this matters, for the finding's message.
    pub fn explain(self) -> &'static str {
        match self {
            Self::InvisibleText => {
                "screen text contains characters a person cannot see; what the agent reads is not what the user was shown"
            }
            Self::BidiOverride => {
                "screen text contains bidirectional override controls, so it renders in a different order than it reads (Trojan Source)"
            }
            Self::Homoglyph => {
                "a word mixes Latin with Cyrillic lookalike letters; it renders as one thing and matches another"
            }
            Self::CombiningStack => {
                "screen text stacks combining marks beyond any script's normal use, which breaks tokenisation and rendering differently"
            }
            Self::OversizedToken => {
                "screen text contains a single unbroken token long enough to be a payload rather than a word"
            }
            Self::GlitchToken => {
                "screen text contains a published glitch token, i.e. a string chosen for how a tokenizer mishandles it"
            }
        }
    }
}

/// One anomaly. Carries a *shape*, never the matched text — the same rule as
/// [`crate::entity::Entity`], and for the same reason: a finding's consumer is a signed
/// audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextAnomaly {
    pub kind: AnomalyKind,
    /// How many characters or occurrences, so an operator can tell one stray mark from a
    /// smuggled paragraph.
    pub count: usize,
}

/// Invisible characters with no legitimate role in rendered text.
///
/// This list started three characters longer and a reviewer showed every one of the
/// removals firing on ordinary screens:
///
/// * **`U+200D` (ZWJ) is gone.** It is how every family emoji, every profession emoji and
///   every flag-with-modifier is built (`👨‍👩‍👧`, `👩‍💻`, `🏳️‍🌈`), and it is *grammatically
///   required* in Persian (`می‌خواهم`). 15 of 15 tested ZWJ emoji were findings.
/// * **`U+200C` (ZWNJ) is gone**, for the Persian reason alone.
/// * **`U+00AD` (soft hyphen) is gone.** `&shy;` is how German hyphenates:
///   `Ver­trags­be­din­gun­gen` was five findings.
///
/// What is left is `U+200B` (zero-width space), the word joiner, a mid-string BOM, the
/// Mongolian vowel separator, and the tag block — none of which a renderer needs to show a
/// person text they can read. Even so the module doc's old claim that the tag block "has no
/// legitimate use in UI text" was wrong: subdivision flag emoji (`🏴󠁧󠁢󠁳󠁣󠁴󠁿`) are tag
/// sequences, which is why [`scan_anomalies`] skips a tag run that follows `U+1F3F4`.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{200b}'               // zero-width space
        | '\u{2060}'             // word joiner
        | '\u{feff}'             // BOM used mid-string
        | '\u{180e}'             // Mongolian vowel separator
        | '\u{2061}'..='\u{2064}' // invisible operators
        | '\u{206a}'..='\u{206f}' // deprecated format controls
        | '\u{fff9}'..='\u{fffb}' // interlinear annotation
        | '\u{3164}'             // Hangul filler
        | '\u{115f}'..='\u{1160}' // Hangul choseong/jungseong fillers
        | '\u{2800}'             // Braille blank
        | '\u{fe00}'..='\u{fe0f}' // variation selectors
        | '\u{e0100}'..='\u{e01ef}' // variation selectors supplement
        | '\u{e0000}'..='\u{e007f}' // tag block — invisible prompt injection
    )
}

/// A tag character, so a flag-emoji tag sequence can be excluded.
fn is_tag_char(c: char) -> bool {
    matches!(c, '\u{e0000}'..='\u{e007f}')
}

/// Variation selectors, which are legitimate immediately after an emoji base.
fn is_variation_selector(c: char) -> bool {
    matches!(c, '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}')
}

/// Bidi controls that *reorder*, as opposed to the ones that merely hint or isolate.
///
/// Narrowed to the two **overrides**. `U+2066`–`U+2069` (the isolates) were in the list and
/// a reviewer pointed out that ICU and Mozilla Fluent wrap **every interpolated value** in
/// FSI…PDI — `Willkommen zurück, <FSI>Sara<PDI>!` was two findings, on every localised app on
/// earth. `U+202A`–`U+202C` (embeddings) are deprecated but legitimate. What is left is
/// `U+202D`/`U+202E`, which exist to make text render in an order it does not read, and are
/// the Trojan Source attack.
fn is_bidi_override(c: char) -> bool {
    matches!(c, '\u{202d}' | '\u{202e}')
}

/// Published glitch tokens. A tripwire, not coverage — see the module doc.
pub const GLITCH_TOKENS: &[&str] = &[
    "solidgoldmagikarp",
    "petertodd",
    "rawdownload",
    "cloneembedreportprint",
    "externaltoevaonly",
    "guiactivebounds",
    "davidjl",
    "attrot",
    "srfattach",
    "embedreportprint",
];

/// A token longer than this is a payload, not a word.
///
/// 2048, after a reviewer pointed out that 256 flagged the very things the old comment
/// listed as legitimate: a real three-part JWT is 261 characters, an AWS presigned URL 331,
/// a `data:` URL 274–462 — and `url` is one of the scanned fields. A threshold justified by
/// examples it fires on is not a threshold.
const MAX_TOKEN_CHARS: usize = 2048;

/// Combining marks stacked this deep are not a script, they are a stress test.
const MAX_COMBINING_STACK: usize = 3;

/// Scan text for anomalies. Single pass, no regex — same constraint as the rest of the
/// firewall: this runs on the accessibility hot path over text an attacker controls.
pub fn scan_anomalies(text: &str) -> Vec<TextAnomaly> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut invisible = 0usize;
    let mut bidi = 0usize;
    let mut combining_worst = 0usize;
    let mut combining_run = 0usize;
    let mut token_worst = 0usize;
    let mut token_len = 0usize;
    // Per-word script mixing.
    let mut word_latin = 0usize;
    let mut word_confusable = 0usize;
    let mut homoglyph_words = 0usize;

    let finish_word = |latin: &mut usize, conf: &mut usize, hits: &mut usize| {
        if *conf > 0 && *latin >= 2 {
            *hits += 1;
        }
        *latin = 0;
        *conf = 0;
    };

    let mut prev: Option<char> = None;
    let mut in_flag_tag_run = false;
    for c in text.chars() {
        // Subdivision flag emoji (`U+1F3F4` + tag letters + `U+E007F`) are tag sequences, so
        // the tag block does have a legitimate use after all. Skip the run rather than the
        // block: an instruction encoded in tag characters *anywhere else* is still the
        // attack.
        if prev == Some('\u{1f3f4}') && is_tag_char(c) {
            in_flag_tag_run = true;
        } else if in_flag_tag_run && !is_tag_char(c) {
            in_flag_tag_run = false;
        }
        // A variation selector immediately after a non-ASCII base is emoji presentation
        // (`❤️`, `🏳️`), not smuggling. A *run* of them, or one after an ASCII letter, is.
        let vs_is_presentation = is_variation_selector(c)
            && prev
                .map(|p| !p.is_ascii() && !is_variation_selector(p))
                .unwrap_or(false);
        if is_invisible(c) && !in_flag_tag_run && !vs_is_presentation {
            invisible += 1;
        }
        prev = Some(c);
        if is_bidi_override(c) {
            bidi += 1;
        }
        // Combining marks (Mn/Mc/Me approximated by the main combining blocks).
        if is_combining(c) {
            combining_run += 1;
            combining_worst = combining_worst.max(combining_run);
        } else {
            combining_run = 0;
        }
        // Unbroken token length.
        if c.is_whitespace() {
            token_len = 0;
        } else {
            token_len += 1;
            token_worst = token_worst.max(token_len);
        }
        // Word-level script mixing.
        if c.is_alphabetic() {
            if is_latin(c) {
                word_latin += 1;
            } else if is_confusable_script(c) {
                word_confusable += 1;
            } else {
                // A CJK or other-script letter ends the *Latin word* being examined, and is
                // never itself a finding: mixed-script text is normal in the corpus this
                // guard watches.
                finish_word(&mut word_latin, &mut word_confusable, &mut homoglyph_words);
            }
        } else {
            finish_word(&mut word_latin, &mut word_confusable, &mut homoglyph_words);
        }
    }
    finish_word(&mut word_latin, &mut word_confusable, &mut homoglyph_words);

    let mut out = Vec::new();
    if invisible > 0 {
        out.push(TextAnomaly {
            kind: AnomalyKind::InvisibleText,
            count: invisible,
        });
    }
    if bidi > 0 {
        out.push(TextAnomaly {
            kind: AnomalyKind::BidiOverride,
            count: bidi,
        });
    }
    if homoglyph_words > 0 {
        out.push(TextAnomaly {
            kind: AnomalyKind::Homoglyph,
            count: homoglyph_words,
        });
    }
    if combining_worst >= MAX_COMBINING_STACK {
        out.push(TextAnomaly {
            kind: AnomalyKind::CombiningStack,
            count: combining_worst,
        });
    }
    if token_worst > MAX_TOKEN_CHARS {
        out.push(TextAnomaly {
            kind: AnomalyKind::OversizedToken,
            count: token_worst,
        });
    }
    let lowered = text.to_lowercase();
    let glitches = GLITCH_TOKENS
        .iter()
        .filter(|g| lowered.contains(*g))
        .count();
    if glitches > 0 {
        out.push(TextAnomaly {
            kind: AnomalyKind::GlitchToken,
            count: glitches,
        });
    }
    out
}

/// Combining marks, by block. `char::is_alphabetic` is no help and std exposes no category
/// query, so the blocks that actually stack are listed.
fn is_combining(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036f}'   // combining diacritics
        | '\u{1ab0}'..='\u{1aff}'
        | '\u{1dc0}'..='\u{1dff}'
        | '\u{20d0}'..='\u{20f0}'
        | '\u{fe20}'..='\u{fe2f}'
    )
}

/// Latin letters, across the blocks a real word can use.
///
/// The first version stopped at `U+024F`, so one IPA or Latin-Extended-Additional character
/// broke the word in two and the homoglyph rule stopped seeing it: `Lоɡin` (with `U+0261`)
/// and `Cоṇfirm` (with `U+1E47`) both carried a Cyrillic `о` and scanned clean.
fn is_latin(c: char) -> bool {
    matches!(c,
        'a'..='z'
        | 'A'..='Z'
        | '\u{00c0}'..='\u{024f}'   // Latin-1 Supplement + Extended-A/B
        | '\u{0250}'..='\u{02af}'   // IPA Extensions
        | '\u{1d00}'..='\u{1d7f}'   // Phonetic Extensions
        | '\u{1e00}'..='\u{1eff}'   // Latin Extended Additional
        | '\u{ff21}'..='\u{ff3a}'   // full-width A-Z
        | '\u{ff41}'..='\u{ff5a}'   // full-width a-z
    )
}

/// Scripts whose letters are drawn like Latin ones. **Cyrillic only.**
///
/// Greek was here and had to go: single Greek letters are mathematical and engineering
/// notation, so `Show Δtime column`, `250 μsec`, `Ωmeter` and `λambda function` were all
/// homoglyph findings. Cyrillic has no such role in Latin-script UI text, which is why it is
/// also the script the published confusable attacks use.
///
/// Not added, deliberately: Armenian, Cherokee, Coptic and the mathematical alphanumerics
/// contain confusables too, and each one costs precision on ordinary multilingual text. The
/// line is drawn where the attacks are, and `docs/text-anomalies.md` says so.
fn is_confusable_script(c: char) -> bool {
    matches!(c, '\u{0400}'..='\u{04ff}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<&'static str> {
        scan_anomalies(text)
            .iter()
            .map(|a| a.kind.as_str())
            .collect()
    }

    #[test]
    fn invisible_text_is_found() {
        assert!(kinds("Confirm\u{200b}\u{200b} payment").contains(&"invisible_text"));
        // The Unicode tag block: today's invisible prompt injection.
        let tagged: String = "Pay now"
            .chars()
            .chain("\u{e0041}\u{e0042}".chars())
            .collect();
        assert!(kinds(&tagged).contains(&"invisible_text"));
        // Variation-selector smuggling — the published scheme next door to the tag block,
        // which the first version missed entirely.
        let vs: String = "Confirm booking"
            .chars()
            .chain("\u{e0100}\u{e0101}\u{e0102}".chars())
            .collect();
        assert!(
            kinds(&vs).contains(&"invisible_text"),
            "{:?}",
            scan_anomalies(&vs)
        );
        assert!(kinds("Confirm\u{2800}\u{2800}").contains(&"invisible_text"));
        assert!(kinds("Confirm\u{3164}").contains(&"invisible_text"));
    }

    /// The characters a renderer *needs*. Every one of these was a finding in the first
    /// version, and each is ordinary on a real screen — which is the difference between a
    /// control and a nuisance.
    #[test]
    fn characters_a_renderer_needs_are_not_findings() {
        for ok in [
            // ZWJ emoji: family, profession, flags-with-modifier.
            "Mum 👨‍👩‍👧 Yesterday",
            "👩‍💻 developer",
            "🏳️‍🌈 pride",
            "🐻‍❄️ polar bear",
            "❤️‍🔥",
            // Subdivision flags are *tag sequences*.
            "🏴󠁧󠁢󠁳󠁣󠁴󠁿 Scotland",
            "🏴󠁧󠁢󠁥󠁮󠁧󠁿 England",
            // Persian ZWNJ is grammatically required.
            "می‌خواهم",
            "جست‌وجو",
            // German soft hyphenation.
            "Ver\u{ad}trags\u{ad}be\u{ad}din\u{ad}gun\u{ad}gen",
            // ICU / Fluent wrap every interpolated value in FSI…PDI.
            "Willkommen zurück, \u{2068}Sara\u{2069}!",
            "\u{2068}3\u{2069} items in cart",
            // Emoji presentation selectors.
            "☀️ 26°C  ⚠️ delayed",
            // Mathematical and engineering notation with Greek letters.
            "Show Δtime column",
            "250 μsec",
            "Ωmeter reading",
            "λambda function",
            // Real JWT (261 chars) and a data URL.
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjIsImF1ZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ] {
            assert!(
                scan_anomalies(ok).is_empty(),
                "{ok:?} → {:?}",
                scan_anomalies(ok)
            );
        }
    }

    #[test]
    fn bidi_overrides_are_found_but_plain_marks_are_not() {
        assert!(kinds("total \u{202e}0001$").contains(&"bidi_override"));
        assert!(kinds("a\u{202d}b").contains(&"bidi_override"));
        // The *isolates* are not overrides: ICU and Fluent use them for interpolation.
        assert!(!kinds("a\u{2066}b\u{2069}").contains(&"bidi_override"));
        // Ordinary RTL text: the marks that only hint direction must stay silent, or every
        // Arabic and Hebrew screen is a finding.
        assert!(scan_anomalies("\u{200f}مرحبا بالعالم\u{200e} 128.00").is_empty());
        assert!(scan_anomalies("\u{200f}שלום עולם").is_empty());
    }

    #[test]
    fn a_latin_word_with_a_cyrillic_lookalike_is_found() {
        // Cyrillic 'а' inside an otherwise Latin word.
        assert!(kinds("Confirm p\u{0430}yment").contains(&"homoglyph"));
        assert!(kinds("boo\u{043a}ing.com").contains(&"homoglyph"));
        // Pure Cyrillic or pure Greek prose is not a finding — it is a language.
        assert!(scan_anomalies("Привет мир").is_empty());
        assert!(scan_anomalies("Καλημέρα κόσμε").is_empty());
    }

    /// The corpus this guard actually watches is multilingual. Mixed scripts are normal.
    #[test]
    fn ordinary_multilingual_ui_text_is_clean() {
        for s in [
            "确认支付 ¥128.00",
            "Booking summary — 2 guests",
            "iPhone 15 Pro 已加入购物车",
            "Grand Hotel 上海 — 预订确认",
            "こんにちは Booking.com",
            "Xin chào — Đặt phòng thành công",
            "नमस्ते बुकिंग",
            "Total: €128,00 (incl. VAT)",
            "[AG_TRANSPARENT_OVERLAY]",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "9f2a4c1e8b7d6a5f4e3c2b1a0987654321fedcba9f2a4c1e8b7d6a5f4e3c2b1a",
        ] {
            assert!(
                scan_anomalies(s).is_empty(),
                "{s:?} → {:?}",
                scan_anomalies(s)
            );
        }
    }

    #[test]
    fn stacked_combining_marks_are_found_but_real_scripts_are_not() {
        assert!(kinds("e\u{0301}\u{0302}\u{0303}\u{0304}").contains(&"combining_stack"));
        // Vietnamese and Devanagari stack one or two.
        assert!(!kinds("Đặt phòng nhanh").contains(&"combining_stack"));
        assert!(!kinds("e\u{0301}").contains(&"combining_stack"));
        assert!(!kinds("o\u{0302}\u{0300}").contains(&"combining_stack"));
    }

    /// The threshold is asserted on **both** sides, at the exact boundary. The first version
    /// pinned neither: raising `MAX_TOKEN_CHARS` by one broke no test, and the false-positive
    /// control it claimed contained "a 256-char token at exactly the threshold" contained no
    /// token longer than 64.
    #[test]
    fn the_oversized_token_boundary_is_pinned_both_ways() {
        assert!(scan_anomalies(&"A".repeat(MAX_TOKEN_CHARS)).is_empty());
        assert!(kinds(&"A".repeat(MAX_TOKEN_CHARS + 1)).contains(&"oversized_token"));
        // A long *sentence* is not a long token.
        assert!(!kinds(&"word ".repeat(2_000)).contains(&"oversized_token"));
        // The things the old threshold's own comment called legitimate, and flagged.
        assert!(
            !kinds(&"a".repeat(331)).contains(&"oversized_token"),
            "presigned URL"
        );
        assert!(
            !kinds(&format!("data:image/png;base64,{}", "A".repeat(440)))
                .contains(&"oversized_token")
        );
    }

    /// Class thresholds and the confusable set, pinned in both directions. A reviewer found
    /// that loosening any of `MAX_TOKEN_CHARS`, `MAX_COMBINING_STACK`, the `latin >= 2`
    /// boundary or the Greek half of the confusable set broke no test at all.
    #[test]
    fn class_boundaries_are_pinned() {
        // Combining stack: exactly at the threshold fires, one below does not.
        let two = "e\u{0301}\u{0302}";
        let three = "e\u{0301}\u{0302}\u{0303}";
        assert!(!kinds(two).contains(&"combining_stack"));
        assert!(kinds(three).contains(&"combining_stack"));
        // Homoglyph needs a *word*: a lone Cyrillic letter beside Latin is not one.
        assert!(!kinds("\u{0430} b").contains(&"homoglyph"));
        assert!(kinds("p\u{0430}y").contains(&"homoglyph"));
        // Greek is deliberately not confusable — single Greek letters are notation.
        assert!(!kinds("Δtime μsec Ωmeter").contains(&"homoglyph"));
        // Latin blocks beyond U+024F still count as Latin, so one exotic letter does not
        // break the word and hide the Cyrillic in it.
        assert!(kinds("L\u{043e}\u{0261}in").contains(&"homoglyph"));
        assert!(kinds("C\u{043e}\u{1e47}firm").contains(&"homoglyph"));
    }

    #[test]
    fn published_glitch_tokens_are_a_tripwire() {
        assert!(kinds(" SolidGoldMagikarp").contains(&"glitch_token"));
        assert!(kinds("please petertodd now").contains(&"glitch_token"));
        assert!(scan_anomalies("solid gold fish").is_empty());
    }

    /// Findings carry a shape, never the text.
    #[test]
    fn a_finding_does_not_carry_the_text() {
        let a = scan_anomalies("Confirm\u{200b}\u{200b}\u{200b} payment");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].count, 3);
        let json = serde_json::to_string(&a[0]).unwrap();
        assert!(!json.contains("Confirm"), "{json}");
    }

    /// Linear: this runs on the accessibility hot path over attacker-controlled text.
    #[test]
    fn adversarial_text_stays_linear() {
        for text in [
            "\u{200b}".repeat(200_000),
            "a\u{0301}".repeat(100_000),
            "Confirm p\u{0430}yment ".repeat(20_000),
            "A".repeat(300_000),
        ] {
            let start = std::time::Instant::now();
            let _ = scan_anomalies(&text);
            assert!(
                start.elapsed().as_millis() < 3_000,
                "{} bytes took {:?}",
                text.len(),
                start.elapsed()
            );
        }
    }
}
