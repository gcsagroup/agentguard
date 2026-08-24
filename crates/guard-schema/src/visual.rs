//! Display identity: app labels and icons (AgentScan §3.6).
//!
//! AgentScan clones a target app's **icon and name** and reports 10/10 (100 %) success
//! against three of the agents it tested — the highest success rate in the paper. The
//! reason is structural and worth stating plainly: an agent driving a GUI decides *which
//! app it is in* by looking at the screen, and everything on the screen is chosen by
//! whoever wrote the app. The label is a string in a manifest. The icon is a file in an
//! APK. Neither is a claim about identity; both are what identity is inferred from.
//!
//! # What this module does, and the one direction it is allowed to work in
//!
//! §3.5 (`AppIdentity`, iteration 13) binds an app to its **signing certificate**, so a
//! forged *package name* fails. That leaves the case where nothing is forged at all: the
//! clone is honestly signed by the attacker, under the attacker's own package name, and
//! simply *looks* like the target. `AppIdentity` calls that `Unregistered` and says
//! nothing — which is what the probe against the shipped engine returned before this
//! module existed:
//!
//! ```text
//! package com.evil.clone, source_app "WeChat"
//!   → APP-FOCUS   LogOnly   "Foreground app: WeChat"
//!   → DL-UNKNOWN  Alert     "deeplink from unregistered app 'WeChat'"
//! ```
//!
//! The guard printed the forged name as if it were the app's name.
//!
//! So the appearance is evidence, and the rule for using it has exactly one direction:
//!
//! > **A forged appearance may only ever raise suspicion. It may never grant trust.**
//!
//! Matching a registered app's label or icon is never a reason to *believe* an app is that
//! app — that would be the mistake this whole project keeps finding in its own code, an
//! attacker-supplied value read as a security control. It is only ever a reason to ask why
//! an app that is not WeChat is dressed as WeChat. [`Appearance::resolve`] therefore takes
//! the *cryptographic* identity as the authority and the appearance as the accusation, and
//! can only ever return "consistent" or "impersonation" — never "verified".
//!
//! # Folding, and why Greek is a confusable here but not in `anomaly.rs`
//!
//! [`fold_label`] reduces a label to a comparison skeleton: invisible characters dropped,
//! combining marks dropped, full-width forms narrowed, a curated set of Cyrillic and Greek
//! lookalikes mapped to Latin, precomposed Latin letters reduced to their base letter,
//! digit-leet mapped (`0`→`o`, `1`→`l`, `3`→`e`, `5`→`s`, `7`→`t`, only for a digit with a
//! letter on **both** sides), case folded, and everything non-alphanumeric removed. `Wе-Сhаt`, `ＷｅＣｈａｔ`, `We Chat`, `Wéchat` and
//! `W3Chat` all fold to `wechat`.
//!
//! Digit-leet applies only to a digit with a **letter on both sides**. The first version
//! folded any digit with no digit neighbour, which mangled `250 μsec` into `2soμsec`; the
//! second required one letter neighbour, which folded `Note 5` into `notes` — exactly equal to
//! a registered `Notes`, and `Word 7` into `wordt`. A trailing digit is a version number, and
//! app names carry those constantly.
//!
//! `guard_privacy::anomaly` refuses to treat Greek as a confusable, because a lone Greek
//! letter is engineering notation (`Δtime`, `250 μsec`) and flagging it produced findings on
//! ordinary screens. That argument does not transfer, and the difference is the direction of
//! the inference. There, a Greek letter *was itself* the finding. Here, folding can only
//! produce a finding by colliding with a **registered app's name**: `Δtime` folds to `δtime`
//! (δ is not in the table — the claim here said `dtime` for one iteration), matches nothing,
//! and is silent. Folding aggressively is safe precisely because
//! the registry is the thing that has to match.
//!
//! # What is deliberately not a match
//!
//! **Containment.** An app whose folded label *contains* a registered name is not a
//! finding, and the counterexample is in this project's own market: WeChat is
//! `com.tencent.mm`, and 企业微信 / "WeChat Work" is `com.tencent.wework` — a different,
//! entirely legitimate app whose English label contains "WeChat". So is every "… for
//! Instagram", "… Lite" and "… Business" in an app store. The cost of that decision is
//! stated rather than hidden: a clone named `WeChat Pay` is **not** caught by the label
//! rule. It is caught by the icon rule, if it cloned the icon, and otherwise not at all.
//!
//! **Short labels.** Labels carrying less than [`MIN_LABEL_WEIGHT`] of information are skipped
//! entirely, which puts four-letter Latin names such as the registry's own `AMap` out of reach
//! of the label rule: French community-agriculture apps are called `AMAP`, and the Serbian name
//! `Амар` folds onto it through the Cyrillic table. Typo matches additionally need
//! [`MIN_NEAR_MISS_CHARS`] characters — 微博 (Weibo) is one character from 微信 (WeChat) and they
//! are competitors, not typos.
//!
//! **All but two edit shapes.** [`LabelMatch::Typo`] covers an adjacent transposition and a
//! doubled letter, and nothing else. A general one-edit rule made `Stride`, `Strive`,
//! `Stripes`, `Stripo`, `Strip`, `WebChat` and `Elemi` into Critical blocks against the shipped
//! registry.
//!
//! **A finding on the icon alone.** Icon evidence is advisory — recorded, never surfaced as an
//! intervention. See [`ICON_MATCH_MAX_DISTANCE`] for the measurement that forced that.
//!
//! **Degenerate icons.** See [`IconHash::is_degenerate`]: a flat icon's difference hash is
//! nearly all zeros and would match every other flat icon, so those refuse to compare.

use std::fmt;

/// Least [`label_weight`] a folded label must carry to be compared at all.
///
/// A floor in *characters* was the first version and it was wrong in the market this
/// project is about: 微信, 美团, 高德 and 支付宝 are two and three characters, so a
/// four-character floor silently switched the label rule off for almost every Chinese app
/// name while every Latin test stayed green. A CJK character carries far more information
/// than a Latin letter, so the floor counts information instead — see [`label_weight`].
///
/// **5, not 4**, and the fourth character of a Latin name is where it bites. At 4 the
/// registry's own `AMap` was protectable, which meant every app whose label folded to `amap`
/// was a Critical block: French community-agriculture apps are named `AMAP`, and the Serbian
/// name `Амар` folds to `amap` through the Cyrillic table. A four-letter Latin word is not a
/// distinctive enough name to accuse anyone over. `AMap` is now protected by its icon and its
/// package, not by its label; [`crate::policy::KnownAppsPolicy`] refuses to load an entry with
/// no protectable face at all, so this cannot be a silent loss of coverage.
pub const MIN_LABEL_WEIGHT: usize = 5;

/// Fewest characters either side must have for a [`LabelMatch::Typo`] to be considered.
///
/// Exact matching has no such floor beyond [`MIN_LABEL_WEIGHT`]. One character of difference
/// in a short name is not a typo, it is a different name — and in CJK it is emphatically a
/// different name: 微博 (Weibo) is one character from 微信 (WeChat) and they are unrelated apps
/// owned by competitors. Five characters keeps every 2–4 character CJK label to exact matching.
pub const MIN_NEAR_MISS_CHARS: usize = 5;

/// Longest folded label that may be compared, as a denial-of-service bound.
///
/// [`label_match`] is O(n·m) in the two folded lengths. A registry name is short, but the
/// *label* arrives from an observed app, so it is attacker-sized. An app manifest can carry
/// a label of essentially any length; without this bound a 1 MB label would run the edit
/// distance against every registry entry on the event hot path.
pub const MAX_FOLDED_LEN: usize = 64;

/// Greatest Hamming distance between two 64-bit icon hashes still counted as the same icon.
///
/// **The first version of this constant claimed "unrelated icons sit near 32 bits apart, so 6 is a
/// wide margin". That is false, and it is now measured by a test in this file** —
/// `the_icon_channel_false_match_rate_is_measured_not_assumed`, which generates its corpus so the
/// figures are reproducible from the artifact rather than from a scratch program. Over 30 glyphs in
/// the dominant real style (one bold mark, dark on white, 192×192): **28 comparable, 378 unrelated
/// pairs, maximum distance 27, 6.6 % within 4 bits, 4 pairs identical** — because an 8×8 difference
/// grid cannot resolve a single stroke, such as the middle bar of an `E`. Widening the hash to 256
/// bits was measured too and does not fix it.
///
/// Meanwhile the *same* icon hashed by two different producers diverges by up to 4 bits, because
/// the companion renders a drawable at 72×72 and the CLI averages from the source resolution. So
/// the same-icon and different-icon distributions **overlap**, and no threshold separates them. 4
/// is the tightest value that still admits the producer divergence.
///
/// That is why icon evidence cannot produce a finding on its own — see [`Evidence::is_advisory`].
/// A perceptual hash is a corroborator here, not a detector.
pub const ICON_MATCH_MAX_DISTANCE: u32 = 4;

/// How an observed label compares to a registered name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LabelMatch {
    /// The folded forms differ by an **adjacent transposition** (`Wechta`) or a **doubled
    /// letter** (`WeChatt`) — the two shapes a finger produces, and nothing else.
    ///
    /// This started as "within one edit" and had to be cut down, because a general one-edit
    /// rule admits roughly 470 neighbours of a six-letter name and a great many of them are
    /// real apps. Measured against the shipped registry, it made every one of these a
    /// Critical block: `Stride` (Stride Health), `Strive`, `Stripes`, `Stripo`, `Strip`
    /// (against `Stripe`), `WebChat` (against `WeChat`), `Elemi` (against `Eleme`).
    /// Substitution, insertion and deletion are therefore **not** matches. The cost is that
    /// `Wechet` — a deliberate one-letter typosquat — is not caught by the label rule.
    Typo,
    /// Folded forms are identical.
    Exact,
}

impl LabelMatch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "identical after folding to",
            Self::Typo => "a transposition or doubled letter away from",
        }
    }
}

/// Reduce a display label to a comparison skeleton. See the module docs.
///
/// Two passes. The first drops, narrows, lowercases and maps letters; the second applies
/// digit-leet, which needs to see a digit's neighbours and so cannot be decided while the
/// neighbours are still being produced. The second pass runs over the *output*, which is
/// capped at [`MAX_FOLDED_LEN`] + 1 characters — one over the limit, so [`label_match`] can
/// still tell that the cap was hit rather than silently comparing a truncation.
pub fn fold_label(label: &str) -> String {
    let mut out: Vec<char> = Vec::with_capacity(32);
    for raw in label.chars() {
        if out.len() > MAX_FOLDED_LEN {
            break;
        }
        if is_droppable(raw) {
            continue;
        }
        let narrowed = narrow_fullwidth(raw);
        // `to_lowercase` first: the Cyrillic and Greek tables below are lowercase-only, and
        // uppercase А (U+0410) lowercases into а (U+0430), which the table then maps.
        for lower in narrowed.to_lowercase() {
            let mapped = fold_letter(lower);
            if mapped.is_alphanumeric() {
                out.push(mapped);
            }
        }
    }
    for i in 0..out.len() {
        if let Some(folded) = fold_leet_digit(&out, i) {
            out[i] = folded;
        }
    }
    out.into_iter().collect()
}

/// Digit-leet for the digit at `i`, or `None` to leave it alone.
///
/// A digit is a letter-substitute only when it has a **letter on both sides**. One letter
/// neighbour was not enough: `Note 5` folds to `note5`, whose `5` has the letter `e` before it
/// and nothing after, so it became `notes` — exactly equal to a registered `Notes`. The same
/// went for `Word 7` → `wordt`, `Line 7` → `linet`, `Photo 3` → `photoe`. A trailing digit is
/// a version or model number, and app names carry those constantly.
///
/// The cost is that a *leading* leet character is no longer folded: `0ffice` stays `0ffice`.
/// `4`→`a` and `8`→`b` are absent from the map as well — weaker shapes, and they collide with
/// version numbers.
fn fold_leet_digit(chars: &[char], i: usize) -> Option<char> {
    let c = chars[i];
    let mapped = match c {
        '0' => 'o',
        '1' => 'l',
        '3' => 'e',
        '5' => 's',
        '7' => 't',
        _ => return None,
    };
    let prev = i.checked_sub(1).map(|j| chars[j]);
    let next = chars.get(i + 1).copied();
    let is_digit = |o: Option<char>| o.is_some_and(|c| c.is_numeric());
    let is_letter = |o: Option<char>| o.is_some_and(|c| c.is_alphabetic());
    if is_digit(prev) || is_digit(next) {
        return None;
    }
    if is_letter(prev) && is_letter(next) {
        Some(mapped)
    } else {
        None
    }
}

/// Characters that carry no shape and so cannot distinguish two labels.
///
/// Dropping ZWJ, ZWNJ and the soft hyphen here is the opposite of what
/// `guard_privacy::anomaly` does, and for the same reason Greek differs: dropping them
/// cannot *create* a finding out of ordinary text, it can only stop an attacker from
/// breaking a string comparison by wedging one into `We<ZWJ>Chat`.
fn is_droppable(c: char) -> bool {
    matches!(c,
        '\u{00ad}'                        // soft hyphen
        | '\u{034f}'                      // combining grapheme joiner
        | '\u{061c}'                      // Arabic letter mark
        | '\u{115f}' | '\u{1160}'         // Hangul choseong/jungseong filler
        | '\u{180b}'..='\u{180e}'         // Mongolian variation selectors + vowel separator
        | '\u{200b}'..='\u{200f}'         // zero-width space/ZWNJ/ZWJ, LRM/RLM
        | '\u{202a}'..='\u{202e}'         // bidi embeddings and overrides
        | '\u{2060}'..='\u{2064}'         // word joiner, invisible operators
        | '\u{2066}'..='\u{2069}'         // bidi isolates
        | '\u{2800}'                      // Braille blank
        | '\u{3164}' | '\u{ffa0}'         // Hangul filler, halfwidth filler
        | '\u{fe00}'..='\u{fe0f}'         // variation selectors
        | '\u{feff}'                      // BOM / zero-width no-break space
        | '\u{fff9}'..='\u{fffb}'         // interlinear annotation
        | '\u{e0000}'..='\u{e007f}'       // tag block
        | '\u{e0100}'..='\u{e01ef}'       // variation selectors supplement
        // Combining marks: a label differing only by a diacritic is the same label for
        // impersonation purposes.
        | '\u{0300}'..='\u{036f}'
        | '\u{1ab0}'..='\u{1aff}'
        | '\u{1dc0}'..='\u{1dff}'
        | '\u{20d0}'..='\u{20f0}'
        | '\u{fe20}'..='\u{fe2f}'
    )
}

/// Full-width forms to their ASCII equivalents, and the ideographic space to a plain one.
///
/// Full-width only. Halfwidth katakana and the halfwidth Hangul forms are *not* narrowed —
/// they have no ASCII equivalent to narrow to, and the doc claimed otherwise for one iteration.
fn narrow_fullwidth(c: char) -> char {
    match c {
        '\u{ff01}'..='\u{ff5e}' => char::from_u32(c as u32 - 0xfee0).unwrap_or(c),
        '\u{3000}' => ' ',
        _ => c,
    }
}

/// Curated confusable → Latin map.
///
/// **Not** the UTS #39 confusables table, which has thousands of entries. This covers the
/// Cyrillic and Greek letters that actually appear in impersonation, plus digit leet.
/// Armenian, Cherokee, Coptic and the mathematical alphanumerics are not covered, and an
/// attacker who reads this list has a way past the label rule — the same honest position
/// `anomaly::GLITCH_TOKENS` takes about its own list.
fn fold_letter(c: char) -> char {
    if let Some(base) = latin_base(c) {
        return base;
    }
    match c {
        // Cyrillic
        'а' => 'a',
        'в' => 'b',
        'е' => 'e',
        'ѕ' => 's',
        'і' => 'i',
        'ј' => 'j',
        'к' => 'k',
        'м' => 'm',
        'н' => 'h',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'т' => 't',
        'у' => 'y',
        'х' => 'x',
        'ԁ' => 'd',
        'һ' => 'h',
        'ӏ' => 'l',
        'ԛ' => 'q',
        'ԝ' => 'w',
        'ѵ' => 'v',
        'ғ' => 'f',
        'ҫ' => 'c',
        'ԍ' => 'g',
        // Greek
        'α' => 'a',
        'β' => 'b',
        'γ' => 'y',
        'ε' => 'e',
        'ζ' => 'z',
        'η' => 'n',
        'ι' => 'i',
        'κ' => 'k',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'υ' => 'u',
        'χ' => 'x',
        'ω' => 'w',
        'ϲ' => 'c',
        'ς' => 's',
        'ϳ' => 'j',
        other => other,
    }
}

/// A precomposed Latin letter reduced to its base letter.
///
/// Covers Latin-1 Supplement and Latin Extended-A (U+00C0–U+017F) — the range an
/// impersonation of a Latin-script name would actually use. Without this, `Wéchat` folded to
/// `wéchat` and matched nothing: dropping *combining* marks is not enough, because the
/// precomposed form `é` (U+00E9) is a single character carrying no combining mark at all.
/// The first version of this module had exactly that hole, and its own test caught it.
///
/// Ligatures fold to their **first** letter only (`æ`→`a`, `œ`→`o`), because this function
/// returns one character. Latin Extended-B and the mathematical alphanumerics are not
/// covered; an attacker who reads this has a way past the label rule, which is the same
/// position [`fold_letter`] takes about its confusable table.
fn latin_base(c: char) -> Option<char> {
    // Indexed from U+00C0, generated from the Unicode NFD decompositions rather than typed
    // by hand. `.` marks a code point with no single Latin base letter — ×, ÷, the ligatures
    // and ß/þ/ð, which the explicit arms above cover.
    const LATIN1: &str = "aaaaaa.ceeeeiiii.nooooo..uuuuy..aaaaaa.ceeeeiiii.nooooo..uuuuy.y";
    const EXT_A: &str = "aaaaaaccccccccdd..eeeeeeeeeegggggggghh..iiiiiiiii...jjkk.llllll....nnnnnn...oooooo..rrrrrrsssssssstttt..uuuuuuuuuuuuwwyyyzzzzzz.";
    match c {
        'æ' | 'Æ' => return Some('a'),
        'œ' | 'Œ' => return Some('o'),
        'ß' => return Some('s'),
        'þ' | 'Þ' => return Some('t'),
        'ð' | 'Ð' => return Some('d'),
        _ => {}
    }
    let (table, base) = match c as u32 {
        0x00c0..=0x00ff => (LATIN1, 0x00c0u32),
        0x0100..=0x017f => (EXT_A, 0x0100u32),
        _ => return None,
    };
    let idx = (c as u32 - base) as usize;
    match table.chars().nth(idx) {
        Some('.') | None => None,
        other => other,
    }
}

/// How much information a folded label carries.
///
/// ASCII alphanumerics count 1; everything else counts 3. The split is crude and it is meant
/// to be: the question is only "is there enough here that an accidental collision is
/// unlikely". Two characters drawn from a 20 000-character script carry about 28 bits; five
/// drawn from 36 carry about 26. Four drawn from 36 carry 20, and that is where `amap`,
/// `uber` and `line` sit — short enough that ordinary unrelated apps land on them.
pub fn label_weight(folded: &str) -> usize {
    folded
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { 1 } else { 3 })
        .sum()
}

/// Compare two folded strings. `None` when they are not the same name.
///
/// Both sides must carry at least [`MIN_LABEL_WEIGHT`] and be at most [`MAX_FOLDED_LEN`]
/// characters. A [`LabelMatch::Typo`] additionally needs [`MIN_NEAR_MISS_CHARS`] characters on
/// both sides.
pub fn label_match(folded: &str, folded_registered: &str) -> Option<LabelMatch> {
    let (a, b) = (folded, folded_registered);
    let (na, nb) = (a.chars().count(), b.chars().count());
    if na > MAX_FOLDED_LEN || nb > MAX_FOLDED_LEN {
        return None;
    }
    if label_weight(a) < MIN_LABEL_WEIGHT || label_weight(b) < MIN_LABEL_WEIGHT {
        return None;
    }
    if a == b {
        return Some(LabelMatch::Exact);
    }
    if na < MIN_NEAR_MISS_CHARS || nb < MIN_NEAR_MISS_CHARS {
        return None;
    }
    if is_transposition(a, b) || is_doubled_letter(a, b) {
        return Some(LabelMatch::Typo);
    }
    None
}

/// Whether `a` and `b` differ only by swapping one adjacent pair.
///
/// `Wechta` for `Wechat`. Kept because it is a shape a finger produces and not a shape an
/// unrelated name has: a transposition preserves the multiset of characters *and* their
/// positions except for one swap, which is a far narrower relation than "one edit".
fn is_transposition(a: &str, b: &str) -> bool {
    let av: Vec<char> = a.chars().collect();
    let bv: Vec<char> = b.chars().collect();
    if av.len() != bv.len() {
        return false;
    }
    let mut diff = Vec::new();
    for i in 0..av.len() {
        if av[i] != bv[i] {
            diff.push(i);
            if diff.len() > 2 {
                return false;
            }
        }
    }
    diff.len() == 2
        && diff[1] == diff[0] + 1
        && av[diff[0]] == bv[diff[1]]
        && av[diff[1]] == bv[diff[0]]
}

/// Whether one string is the other with a single character **duplicated in place**.
///
/// `WeChatt` for `WeChat`. Deliberately not "any insertion": inserting an unrelated character
/// is how `WebChat` becomes a false positive for `WeChat`, and how `Stripes` becomes one for
/// `Stripe`. Duplicating an adjacent character is a keyboard artefact; inserting a new one is
/// usually a different word.
fn is_doubled_letter(a: &str, b: &str) -> bool {
    let (long, short) = if a.chars().count() == b.chars().count() + 1 {
        (a, b)
    } else if b.chars().count() == a.chars().count() + 1 {
        (b, a)
    } else {
        return false;
    };
    let lv: Vec<char> = long.chars().collect();
    let sv: Vec<char> = short.chars().collect();
    let mut i = 0;
    while i < sv.len() && sv[i] == lv[i] {
        i += 1;
    }
    // The extra character at `i` must duplicate one of its neighbours in the longer string.
    if sv[i..] != lv[i + 1..] {
        return false;
    }
    (i > 0 && lv[i] == lv[i - 1]) || (i + 1 < lv.len() && lv[i] == lv[i + 1])
}

/// A 64-bit difference hash of an app icon.
///
/// # The algorithm, pinned
///
/// Every producer must agree bit-for-bit or the comparison is noise, so the definition is
/// normative rather than descriptive:
///
/// 1. render the icon to a **9 × 8** grid (9 columns, 8 rows), 8-bit greyscale;
/// 2. for each row, compare each of the 8 adjacent column pairs: bit set when the **left**
///    sample is strictly brighter than the right;
/// 3. row 0's leftmost comparison is the **most significant** bit; rows follow in order;
/// 4. serialise as 16 lowercase hex characters.
///
/// A difference hash rather than an average hash because it survives the icon-scaling and
/// re-encoding an app store does. It does **not** survive a crop, a rotation, or a
/// deliberate perturbation — see the doc for what that means for the threat model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IconHash(u64);

impl IconHash {
    /// Parse 16 hex characters, **case-insensitively**. Any other length, or a non-hex
    /// character, is `None` rather than a partial hash: a truncated digest compared against a
    /// threshold is how a match gets manufactured.
    ///
    /// Accepting uppercase is deliberate — an operator pasting `0F1E…` from another tool has not
    /// made a security-relevant mistake — and [`Display`](std::fmt::Display) always emits
    /// lowercase, so a round-trip normalises. The docs said "16 lowercase hex characters" while
    /// the code accepted either; the code is right and the docs were narrowed to match it.
    pub fn parse(s: &str) -> Option<Self> {
        let t = s.trim();
        if t.len() != 16 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(t, 16).ok().map(Self)
    }

    pub fn bits(&self) -> u64 {
        self.0
    }

    pub fn distance(&self, other: &Self) -> u32 {
        (self.0 ^ other.0).count_ones()
    }

    /// Whether this hash carries too little information to compare.
    ///
    /// A flat or near-flat icon — one solid colour, or a smooth single-direction gradient —
    /// produces a hash of nearly all zeros or nearly all ones. Two unrelated flat icons then
    /// sit at distance 0 and match perfectly. Requiring at least 8 set and 8 clear bits
    /// costs nothing on a real icon (a logo has structure in both directions) and removes
    /// the one class where this hash is worthless rather than merely imperfect.
    pub fn is_degenerate(&self) -> bool {
        let ones = self.0.count_ones();
        !(8..=56).contains(&ones)
    }

    /// Whether two icons are the same picture. Degenerate hashes never match.
    pub fn matches(&self, other: &Self) -> bool {
        !self.is_degenerate()
            && !other.is_degenerate()
            && self.distance(other) <= ICON_MATCH_MAX_DISTANCE
    }

    /// Compute a hash from packed 4-byte pixels.
    ///
    /// Follows `FrameDigest`'s convention in this repo: raw pixels in, no image codec in the
    /// dependency tree. `bgra` selects the macOS ScreenCaptureKit channel order.
    ///
    /// Alpha is composited onto **white**, not onto black. A launcher icon is mostly
    /// transparent around its glyph; compositing onto transparent black makes the padding the
    /// darkest region, so every icon hashes as "bright glyph on dark ground" and what
    /// distinguishes two icons becomes the shape of the alpha channel rather than the
    /// artwork. White is what a launcher shows.
    ///
    /// Luma is integer Rec. 601, so the result does not depend on floating-point rounding
    /// across platforms — the companion's Kotlin implementation computes the same expression.
    /// The two still resample differently (the companion renders a drawable at 72×72 first,
    /// this box-averages from the source resolution), so agreement is expected to a bit or
    /// two rather than exactly, which is one reason [`ICON_MATCH_MAX_DISTANCE`] is 4 and not 0.
    pub fn from_rgba(pixels: &[u8], width: usize, height: usize, bgra: bool) -> Option<Self> {
        // `checked_mul`, not `width * height * 4`: the multiplication overflowed for
        // `--width 4294967296`, so the guard that is documented to return `None` for a short
        // buffer wrapped to a small number, passed, and then indexed out of bounds. A guard
        // binary that panics stops guarding.
        let needed = width.checked_mul(height).and_then(|n| n.checked_mul(4))?;
        if width < 9 || height < 8 || pixels.len() < needed {
            return None;
        }
        let mut grid = [0u8; 72];
        for row in 0..8 {
            for col in 0..9 {
                let x0 = col * width / 9;
                let x1 = ((col + 1) * width / 9).max(x0 + 1);
                let y0 = row * height / 8;
                let y1 = ((row + 1) * height / 8).max(y0 + 1);
                let mut sum: u64 = 0;
                let mut n: u64 = 0;
                for y in y0..y1 {
                    for x in x0..x1 {
                        let i = (y * width + x) * 4;
                        let (r, g, b, a) = if bgra {
                            (pixels[i + 2], pixels[i + 1], pixels[i], pixels[i + 3])
                        } else {
                            (pixels[i], pixels[i + 1], pixels[i + 2], pixels[i + 3])
                        };
                        let over = |c: u8| -> u64 {
                            (u64::from(c) * u64::from(a) + 255 * (255 - u64::from(a))) / 255
                        };
                        sum += (299 * over(r) + 587 * over(g) + 114 * over(b)) / 1000;
                        n += 1;
                    }
                }
                grid[row * 9 + col] = (sum / n.max(1)) as u8;
            }
        }
        Self::from_grid_9x8(&grid)
    }

    /// Compute a hash from a 9×8 greyscale grid in row-major order.
    ///
    /// Kept here rather than in the CLI so the Rust producer and the Rust comparator cannot
    /// drift apart, and so the Kotlin implementation has one authority to be tested against.
    pub fn from_grid_9x8(grid: &[u8]) -> Option<Self> {
        if grid.len() != 72 {
            return None;
        }
        let mut bits: u64 = 0;
        for row in 0..8 {
            for col in 0..8 {
                let left = grid[row * 9 + col];
                let right = grid[row * 9 + col + 1];
                bits = (bits << 1) | u64::from(left > right);
            }
        }
        Some(Self(bits))
    }
}

impl fmt::Display for IconHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// What the appearance of an app says about it, given what its identity says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Appearance {
    /// Nothing to report: the appearance matched no registered app.
    Consistent,
    /// The appearance matches the app's **own** registry entry, and that entry's claim was
    /// never proved — the package presented no accepted signing certificate.
    ///
    /// Not a finding about the app; a finding about what the guard can and cannot tell. Kept
    /// distinct from [`Self::Consistent`] because collapsing the two is what let a forged
    /// package name silence the whole check.
    Unprovable { registered: String },
    /// The appearance resolves to a registered app that this package is not.
    Impersonation {
        /// The registered app being impersonated.
        registered: String,
        /// What this app actually is — its registered name, or `None` when unregistered.
        actual: Option<String>,
        /// Why the appearance resolved that way.
        evidence: Evidence,
    },
}

/// Which channel carried the impersonation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// The label folds onto the registered name.
    Label(LabelMatch),
    /// The icon hash is within [`ICON_MATCH_MAX_DISTANCE`] of a registered one.
    Icon { distance: u32 },
    /// Both, which is the shape of the paper's attack.
    Both { label: LabelMatch, distance: u32 },
}

impl Evidence {
    /// Whether this evidence is strong enough to justify blocking.
    ///
    /// Label evidence is positive and discrete: the folded name either equals a registered one
    /// or it does not. Icon evidence is a threshold on a perceptual hash whose false-match rate is
    /// measured at **6.6 % over unrelated simple icons** (see [`ICON_MATCH_MAX_DISTANCE`]), so it
    /// can corroborate a label finding and cannot make one.
    pub fn is_conclusive(&self) -> bool {
        matches!(self, Self::Label(_) | Self::Both { .. })
    }

    /// Whether this evidence may only be **recorded**, not surfaced as an intervention.
    ///
    /// True for icon-only evidence. The first version alerted on it at `High`, latched, on
    /// every event — on a channel that false-matches one unrelated simple icon pair in twenty.
    /// An operator who is interrupted by that once stops reading the alerts, and the next
    /// finding is the one that mattered. It is still written to the signed audit record, where
    /// it costs nothing and is there when someone is looking.
    pub fn is_advisory(&self) -> bool {
        matches!(self, Self::Icon { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Label(m) => format!("its display name is {} the registered one", m.as_str()),
            Self::Icon { distance } => format!(
                "its icon is within {distance} of 64 bits of the registered one (advisory: this \
                 channel false-matches unrelated simple icons about one pair in fifteen)"
            ),
            Self::Both { label, distance } => format!(
                "its display name is {} the registered one and its icon is a {distance}/64-bit match",
                label.as_str()
            ),
        }
    }
}

/// What is known about the acting package's *own* identity, independently of its appearance.
///
/// The first version of `resolve` took `Option<&str>` — the registry name the package maps to —
/// and that was the hole. `AppIdentity::app_name()` returns a name for `Unattested` as well as
/// for `Verified`, so a clone that *also* forged the package name (`com.tencent.mm`) matched its
/// "own" entry and came back `Consistent`: forging one more field downgraded a Critical block to
/// a Low log line. A package name is a string the attacker picks — this project's own registry
/// banner says exactly that — so the *provenance* of the name has to travel with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnIdentity<'a> {
    /// The package is in no registry entry.
    Unregistered,
    /// The package belongs to this entry **and presented an accepted signing certificate**.
    Verified(&'a str),
    /// The package claims this entry and has not proved it: no digest, or none on record.
    Claimed(&'a str),
    /// The package claims this entry and the certificate **contradicts** it.
    ///
    /// Behaviourally the same as [`Self::Verified`] here, and that is deliberate rather than an
    /// oversight: the entry is skipped as a candidate either way, because "com.tencent.mm is
    /// impersonating WeChat" is a worse sentence than the `APP-SIGNER-MISMATCH` (Critical, Block)
    /// that has already fired for the same event. Wearing a *third* app's face is still reported.
    ///
    /// The variant exists so the caller states what it knows rather than collapsing a disproven
    /// claim into a verified one at the call site. An earlier version of this doc claimed it
    /// "excuses nothing", which was false — it excused exactly what `Verified` does.
    Disproven(&'a str),
}

impl<'a> OwnIdentity<'a> {
    /// The registered name, for the message. Not permission to excuse anything.
    pub fn name(&self) -> Option<&'a str> {
        match self {
            Self::Unregistered => None,
            Self::Verified(n) | Self::Claimed(n) | Self::Disproven(n) => Some(n),
        }
    }
}

/// The folded strings one [`LabelMatch::Typo`] away from `folded`.
///
/// Lives beside [`label_match`] because it must mirror it exactly: adjacent transpositions and
/// doubled letters **in both directions**, and nothing else. The registry's collision check and
/// the runtime lookup are both built on this, so a drift here means the shipped path stops
/// enforcing the rule the tests exercise. `typo_variants_mirror_label_match` and
/// `face_index_agrees_with_a_brute_force_scan` fail in both directions if that happens — the
/// first version of this comment claimed such a test existed when it did not, and the missing
/// direction was live for exactly that reason.
pub fn typo_variants(folded: &str) -> Vec<String> {
    let cs: Vec<char> = folded.chars().collect();
    if cs.len() < MIN_NEAR_MISS_CHARS || cs.len() > MAX_FOLDED_LEN {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::with_capacity(cs.len() * 3);
    for i in 0..cs.len() - 1 {
        let mut v = cs.clone();
        v.swap(i, i + 1);
        out.push(v.into_iter().collect());
    }
    // Doubling, and **un**-doubling. Only the first direction existed at first, which made the
    // index a strict subset of the rule: `label_match` accepts a doubled letter in either
    // direction, so an observed `Gogle` is one shape away from a registered `Google` — and with
    // only lengthening variants the index had no key for it. A differential test against a
    // brute-force scan found 225 such misses over 59 819 generated registries. `Whatsap`,
    // `Setings` and `Gogle` all went unreported while `Googgle` was caught.
    for i in 0..cs.len() {
        let mut v = cs.clone();
        v.insert(i, cs[i]);
        out.push(v.into_iter().collect());
    }
    for i in 0..cs.len() - 1 {
        if cs[i] == cs[i + 1] {
            let mut v = cs.clone();
            v.remove(i);
            out.push(v.into_iter().collect());
        }
    }
    // Every variant must satisfy the rule it mirrors. A variant that `label_match` would not
    // accept is a key that makes the index *wider* than the rule, which is the dangerous
    // direction; the length guards inside `label_match` are the usual reason.
    out.retain(|v| label_match(v, folded) == Some(LabelMatch::Typo));
    out
}

/// A registry's declared appearances, indexed for constant-time lookup.
///
/// Built once per registry, consulted on every event carrying a `package`. The label channel is
/// a **lookup, not a scan**: the first version compared the observed label against every
/// registered label with [`label_match`], which is 6 000 comparisons per event on a 2 000-app
/// registry and measured 17.7 ms/event — on a path that runs once per accessibility frame. Since
/// `label_match` accepts only equality and the two shapes [`typo_variants`] enumerates, the whole
/// question is answerable by folding the observed label once and looking up its ≤ 129 forms.
///
/// The icon channel stays a scan, because Hamming distance is not a hash lookup — but it is one
/// XOR and one popcount per registered hash, which is nanoseconds each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaceIndex {
    names: Vec<String>,
    /// Folded label (or typo variant) → every app it could match, and how.
    ///
    /// A `Vec`, not a single entry. Two registered labels that do not match *each other* can
    /// still share a variant — `aabcde` and `abbcde` both double into `aabbcde` — and storing one
    /// made the verdict depend on registry order: if the stored app happened to be the observed
    /// app's own entry, the whole label channel went silent even though another entry matched.
    by_label: std::collections::HashMap<String, Vec<(usize, LabelMatch)>>,
    icons: Vec<(usize, IconHash)>,
}

impl FaceIndex {
    /// Build an index from the registry's declared faces.
    ///
    /// Every candidate is kept per key. Load-time validation rejects a registry whose labels match
    /// *each other*, but two labels that do not match each other can still share a variant
    /// (`aabcde` and `abbcde` both double into `aabbcde`), so "at most one app matches" is not an
    /// invariant — an earlier version of this doc asserted it was, and stored one candidate.
    pub fn build<'a>(faces: impl IntoIterator<Item = RegisteredFace<'a>>) -> Self {
        let mut out = Self::default();
        for face in faces {
            let idx = out.names.len();
            out.names.push(face.name.to_string());
            for icon in face.icons {
                out.icons.push((idx, *icon));
            }
            for folded in face.folded {
                if label_weight(folded) < MIN_LABEL_WEIGHT
                    || folded.chars().count() > MAX_FOLDED_LEN
                {
                    continue;
                }
                for v in typo_variants(folded) {
                    let e = out.by_label.entry(v).or_default();
                    if !e.iter().any(|(i, m)| *i == idx && *m == LabelMatch::Typo) {
                        e.push((idx, LabelMatch::Typo));
                    }
                }
                // Exact is the stronger statement for the *same* app, and a string can be both
                // (`aa` doubled is `aaa`, which may itself be a real label), so replace this
                // app's own weaker entry rather than appending beside it.
                let e = out.by_label.entry(folded.clone()).or_default();
                e.retain(|(i, _)| *i != idx);
                e.push((idx, LabelMatch::Exact));
            }
        }
        out
    }

    /// Every app whose declared label this folded string matches.
    fn label_hits(&self, folded: &str) -> &[(usize, LabelMatch)] {
        if label_weight(folded) < MIN_LABEL_WEIGHT || folded.chars().count() > MAX_FOLDED_LEN {
            return &[];
        }
        self.by_label
            .get(folded)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Names in index order, for a differential test against a brute-force scan.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    fn icon_hit(&self, observed: &IconHash) -> Option<(usize, u32)> {
        self.icons
            .iter()
            .filter(|(_, reg)| observed.matches(reg))
            .map(|(i, reg)| (*i, observed.distance(reg)))
            .min_by_key(|(_, d)| *d)
    }

    fn index_of(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|n| n == name)
    }

    pub fn is_empty(&self) -> bool {
        self.by_label.is_empty() && self.icons.is_empty()
    }
}

/// One registered app's appearance, as the registry records it.
///
/// Borrowed rather than owned so `KnownAppsPolicy` can hand these out per event without
/// allocating; the registry is loaded once and the check runs on every focus change.
#[derive(Debug, Clone, Copy)]
pub struct RegisteredFace<'a> {
    pub name: &'a str,
    /// The registered name plus its declared aliases, already folded.
    pub folded: &'a [String],
    pub icons: &'a [IconHash],
}

impl Appearance {
    /// Resolve an observed appearance against the registry.
    ///
    /// `own_name` is the registered app this package **belongs to** — `None` when the package
    /// is not in the registry. That argument is what keeps this check from firing on the normal
    /// path: an app whose appearance matches its own registry entry is consistent by
    /// definition. Android 11+ package visibility makes `getPackageInfo` fail for apps outside
    /// the companion's `<queries>` list, so "looks like WeChat, is `com.tencent.mm`, signer
    /// unreadable" is the *ordinary* case on a real device, and reporting it as impersonation
    /// would make the real app un-runnable — the failure mode `APP-UNATTESTED` was already
    /// carefully built to avoid.
    ///
    /// # The two channels are resolved independently
    ///
    /// This is the second version. The first took the app's own entry as a short-circuit over
    /// the *whole* resolution, so **either** channel matching its own entry silenced the other:
    /// a registered app presenting a cloned label plus its own icon came back `Consistent`, and
    /// so did one presenting its own label plus a cloned icon. That is a silencing primitive an
    /// attacker gets for free, and it contradicted this module's own verdict table.
    ///
    /// So the label channel is excused only by an own-entry **label** match, and the icon
    /// channel only by an own-entry **icon** match. A registered app keeping one of its faces
    /// while wearing another app's other face is still an impersonation, which is what the
    /// paper's attack looks like when the clone is properly signed.
    pub fn resolve<'a>(
        label: Option<&str>,
        icon: Option<&IconHash>,
        own: OwnIdentity<'_>,
        registry: impl IntoIterator<Item = RegisteredFace<'a>>,
    ) -> Self {
        Self::resolve_indexed(label, icon, own, &FaceIndex::build(registry))
    }

    /// [`Self::resolve`] against a prebuilt [`FaceIndex`], which is what a registry uses on the
    /// event path.
    pub fn resolve_indexed(
        label: Option<&str>,
        icon: Option<&IconHash>,
        own: OwnIdentity<'_>,
        index: &FaceIndex,
    ) -> Self {
        let own_name = own.name();
        let own_idx = own_name.and_then(|n| index.index_of(n));
        let folded = label.map(fold_label).unwrap_or_default();
        let hits: &[(usize, LabelMatch)] = if folded.is_empty() {
            &[]
        } else {
            index.label_hits(&folded)
        };
        // The own entry excuses only itself; the best *other* candidate is the finding. Picking
        // one hit and then asking whether it was the own entry made the verdict depend on
        // registry order.
        let own_label_matched = hits.iter().any(|(i, _)| Some(*i) == own_idx);
        let label_finding = hits
            .iter()
            .filter(|(i, _)| Some(*i) != own_idx)
            .max_by_key(|(_, m)| *m)
            .copied();
        let icon_hit = icon.and_then(|obs| index.icon_hit(obs));

        // Per channel: does it point at the app's *own* entry, or at another one? A channel
        // pointing at the own entry is excused — but only that channel. The first version
        // short-circuited the whole resolution on either channel matching its own entry, so a
        // registered app keeping one of its faces silenced a clone of the other, which is a
        // silencing primitive an attacker gets for free.
        let own_icon_matched = icon_hit.is_some_and(|(i, _)| Some(i) == own_idx);
        let icon_finding = icon_hit.filter(|(i, _)| Some(*i) != own_idx);

        // A label finding names the impersonated app; the icon corroborates only when it points
        // at the *same* app. Only one decision can be returned, so the conclusive channel wins.
        if let Some((idx, m)) = label_finding {
            let registered = index.names[idx].clone();
            let evidence = match icon_finding {
                Some((icon_idx, distance)) if icon_idx == idx => {
                    Evidence::Both { label: m, distance }
                }
                _ => Evidence::Label(m),
            };
            return Self::Impersonation {
                registered,
                actual: own_name.map(str::to_string),
                evidence,
            };
        }
        if let Some((idx, distance)) = icon_finding {
            return Self::Impersonation {
                registered: index.names[idx].clone(),
                actual: own_name.map(str::to_string),
                evidence: Evidence::Icon { distance },
            };
        }

        // Nothing points elsewhere. One case is left, and leaving it silent was a defect: the
        // appearance matches the package's **own** registered entry, and the package's claim to
        // that entry was never proved. An unverified package name is a string the attacker picks
        // — this project's own registry banner says so — so `com.tencent.mm` + 微信 + no
        // certificate is indistinguishable from WeChat, and the first version called that
        // `Consistent`, which meant forging the package name downgraded a Critical block to a Low
        // log line. No logic distinguishes a perfect forgery without an authority; what it can do
        // is refuse to call it consistent.
        if let OwnIdentity::Claimed(name) = own {
            if own_idx.is_some() && (own_label_matched || own_icon_matched) {
                return Self::Unprovable {
                    registered: name.to_string(),
                };
            }
        }
        Self::Consistent
    }

    /// An operator-facing sentence. Never quotes the observed label back verbatim: a label
    /// is attacker-chosen text, and a finding message is read by a human.
    pub fn explain(&self, package: &str) -> String {
        match self {
            Self::Consistent => "app appearance is consistent with its identity".into(),
            Self::Unprovable { registered } => format!(
                "'{package}' presents '{registered}'s display identity and has not proved it is \
                 '{registered}': no signing certificate was attested, and a package name is a \
                 string an app picks. This is not evidence of impersonation — it is the absence \
                 of the evidence that would settle it. Set `require_attestation: true` once \
                 every adapter in the deployment attests."
            ),
            Self::Impersonation {
                registered,
                actual,
                evidence,
            } => {
                let what = match actual {
                    Some(name) => format!("'{package}' is the registered app '{name}'"),
                    None => format!("'{package}' is not in the app registry"),
                };
                format!(
                    "{what}, but {} — it is dressed as '{registered}'. \
                     A cloned icon and name is AgentScan §3.6, which succeeded on every \
                     agent the paper tested: an agent decides which app it is in by looking \
                     at the screen, and the screen is chosen by whoever wrote the app.",
                    evidence.describe()
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face<'a>(name: &'a str, folded: &'a [String], icons: &'a [IconHash]) -> RegisteredFace<'a> {
        RegisteredFace {
            name,
            folded,
            icons,
        }
    }

    #[test]
    fn folding_collapses_the_impersonation_tricks() {
        for label in [
            "WeChat",
            "wechat",
            "We Chat",
            "We-Chat",
            "  WeChat  ",
            "WeChat!",
            "Wе\u{200b}Сhаt",  // Cyrillic е and С and а, plus a zero-width space
            "ＷｅＣｈａｔ",    // full-width
            "W3Chat",          // digit leet
            "WeChat\u{ad}",    // soft hyphen
            "We\u{200d}Chat",  // ZWJ wedged in
            "Wé\u{301}Chat",   // combining acute
            "WeChat\u{202e}",  // bidi override
            "WeChat\u{e0041}", // tag block
        ] {
            assert_eq!(fold_label(label), "wechat", "{label:?}");
        }
    }

    /// The fold must not turn unrelated text into a registered name.
    #[test]
    fn folding_keeps_distinct_names_distinct() {
        assert_eq!(fold_label("WeChat Work"), "wechatwork");
        assert_eq!(fold_label("企业微信"), "企业微信");
        assert_eq!(fold_label("微信"), "微信");
        assert_eq!(
            fold_label("Δtime"),
            "δtime",
            "a lone Greek capital is not folded"
        );
        assert_eq!(fold_label("250 μsec"), "250μsec", "μ is not in the table");
        assert_ne!(fold_label("Stripe Terminal"), fold_label("Stripe"));
    }

    /// The cap is one over the limit so `label_match` can see it was exceeded.
    #[test]
    fn folding_is_bounded() {
        let huge = "a".repeat(1_000_000);
        let folded = fold_label(&huge);
        assert_eq!(folded.chars().count(), MAX_FOLDED_LEN + 1);
        assert_eq!(label_match(&folded, "aaaaa"), None);
    }

    #[test]
    fn label_match_classes() {
        assert_eq!(label_match("wechat", "wechat"), Some(LabelMatch::Exact));
        // The only two shapes: an adjacent transposition and a doubled letter.
        for near in ["wechta", "ewchat", "wechatt", "wwechat", "wecchat"] {
            assert_eq!(
                label_match(near, "wechat"),
                Some(LabelMatch::Typo),
                "{near}"
            );
        }
        // Substitution, arbitrary insertion and deletion are **not** matches. A general
        // one-edit rule made `Stride`, `Strive`, `Stripes`, `Stripo`, `Strip`, `WebChat` and
        // `Elemi` into Critical blocks against the shipped registry — measured, not feared.
        for far in ["wechet", "wecha", "webchat", "wechats"] {
            assert_eq!(label_match(far, "wechat"), None, "{far}");
        }
        for (label, registered) in [
            ("stride", "stripe"),
            ("strive", "stripe"),
            ("stripes", "stripe"),
            ("stripo", "stripe"),
            ("strip", "stripe"),
            ("webchat", "wechat"),
            ("elemi", "eleme"),
        ] {
            assert_eq!(
                label_match(label, registered),
                None,
                "{label} / {registered}"
            );
        }
        assert_eq!(label_match("wachot", "wechat"), None, "two substitutions");
        assert_eq!(
            label_match("wchat", "wechatt"),
            None,
            "length differs by two"
        );
    }

    /// Containment is not a match — the WeChat Work counterexample from the module docs.
    #[test]
    fn containment_is_not_a_match() {
        for other in [
            "wechatwork",
            "wechatpay",
            "mywechat",
            "wechatforbusiness",
            "instagramdownloader",
        ] {
            assert_eq!(label_match(other, "wechat"), None, "{other}");
        }
    }

    /// Four-letter Latin names carry too little information to compare **at all** — not even
    /// exactly. `AMap` is the registry's own casualty: French community-agriculture apps are
    /// named `AMAP`, and the Serbian name `Амар` folds onto it through the Cyrillic table.
    #[test]
    fn four_letter_latin_names_are_below_the_floor() {
        for short in ["line", "uber", "amap", "grab", "map", "x"] {
            assert_eq!(
                label_match(short, short),
                None,
                "{short} must not be comparable"
            );
        }
        // Five is enough.
        assert_eq!(label_match("eleme", "eleme"), Some(LabelMatch::Exact));
        // And two CJK characters are enough, because they are not drawn from 36 symbols.
        assert_eq!(label_match("微信", "微信"), Some(LabelMatch::Exact));
        assert_eq!(label_weight("微信"), 6);
        assert_eq!(label_weight("amap"), 4);
    }

    /// Two-character CJK names are the common case in this project's market, and they must
    /// match **exactly** or not at all. 微博 (Weibo) is one character from 微信 (WeChat).
    #[test]
    fn cjk_labels_match_exactly_and_never_by_one_edit() {
        assert_eq!(label_match("微信", "微信"), Some(LabelMatch::Exact));
        assert_eq!(label_match("美团", "美团"), Some(LabelMatch::Exact));
        assert_eq!(
            label_match("微博", "微信"),
            None,
            "Weibo is not a typo for WeChat"
        );
        assert_eq!(
            label_match("支付宝", "支付通"),
            None,
            "three characters, one different"
        );
        assert_eq!(
            label_match("高德地图", "高德地囹"),
            None,
            "still under the near-miss floor"
        );
        // Mixed scripts clear the weight floor on their Latin part alone.
        assert_eq!(label_match("微信pay", "微信pay"), Some(LabelMatch::Exact));
    }

    /// **A false-positive corpus, not a spot check — and read from the shipped registry.**
    ///
    /// Iteration 18 shipped a 0.0 % false-positive figure measured on a corpus that contained no
    /// emoji at all, in a module whose worst false positives were emoji. The first version of
    /// *this* test repeated the mistake in a subtler way: it hardcoded a copy of the registry's
    /// names and contained not one near-neighbour of any of them, so the whole near-miss rule was
    /// covered by nothing. Every label below marked `[FP]` was a **Critical block** against the
    /// shipped registry when this test was written.
    #[test]
    fn no_ordinary_app_label_collides_with_the_shipped_registry() {
        let yaml = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../policies/known-apps.yaml"),
        )
        .expect("shipped registry must be readable");
        let policy = crate::policy::KnownAppsPolicy::from_yaml_str(&yaml).expect("must load");
        let registered: Vec<String> = policy.apps.iter().flat_map(|a| a.folded_labels()).collect();
        assert!(
            registered.len() >= 5,
            "the registry has {} protectable labels; this corpus would be vacuous",
            registered.len()
        );

        let ordinary = [
            // Tencent's own separate products, and containment cases.
            "WeChat Work",
            "企业微信",
            "WeChat Pay",
            "微信读书",
            "微信输入法",
            "QQ",
            "QQ音乐",
            "腾讯视频",
            "腾讯会议",
            // [FP] one-edit neighbours of the registry's Latin names.
            "Stride",
            "Strive",
            "Stripes",
            "Stripo",
            "Strip",
            "Stripped",
            "Striper",
            // ("Meituann" is *not* here on purpose: a doubled trailing letter is one of the two
            // shapes `LabelMatch::Typo` keeps, and it is asserted as caught in the recall test.)
            "WebChat",
            "WeChats",
            "Wechet",
            "Elemi",
            "Elem",
            "Meitu",
            "Meituan Waimai",
            // [FP] four-letter names that fold onto `AMap`.
            "AMAP",
            "A Map",
            "Амар",
            "amap",
            "A-MAP",
            // [FP] version and model numbers that digit-leet turned into letters.
            "Note 5",
            "Word 7",
            "Photo 3",
            "Line 7",
            "Office 365",
            "Office 2021",
            "Nokia 3310 Tools",
            "3D Scanner",
            "1Password",
            "7-Zip",
            "Sub0 Wallet",
            // Competitors one character away.
            "微博",
            "微店",
            "微医",
            "美图秀秀",
            "美柚",
            "美篇",
            "团团",
            "高德打车",
            "百度地图",
            "腾讯地图",
            "凯立德导航",
            "饿了么商家版",
            "美团外卖",
            "美团买菜",
            "口碑",
            // Payment and finance, where a false block costs the most.
            "支付宝",
            "云闪付",
            "招商银行",
            "中国银行",
            "PayPal",
            "Stripe Terminal",
            "Stripe Dashboard",
            "Square",
            "Revolut",
            "Wise",
            "Alipay HK",
            // Global apps with awkward names.
            "WhatsApp",
            "Line",
            "LINE",
            "Signal",
            "Telegram",
            "Threads",
            "X",
            "Instagram",
            "Instagram Lite",
            "Downloader for Instagram",
            "Google Maps",
            "Maps",
            "Uber",
            "Uber Eats",
            "Lyft",
            "Grab",
            "Gojek",
            "Booking.com",
            "Trip.com",
            "Airbnb",
            "Agoda",
            "Expedia",
            // Names built from the characters the fold touches.
            "Δ Notes",
            "250 μsec Meter",
            "Word",
            "Excel",
            "Café Finder",
            "Naïve Notes",
            "Zoë Fitness",
            "Ångström Lab",
            "Škoda Connect",
            // System and vendor apps.
            "Settings",
            "设置",
            "Phone",
            "电话",
            "Camera",
            "相机",
            "Files",
            "文件管理",
            "Play Store",
            "应用商店",
            "Galaxy Store",
            "华为应用市场",
            "Material Files",
            "F-Droid",
            "Termux",
            "Tasker",
            "Automate",
        ];

        let mut collisions: Vec<(String, String, LabelMatch)> = Vec::new();
        for label in ordinary {
            let folded = fold_label(label);
            for reg in &registered {
                if let Some(m) = label_match(&folded, reg) {
                    collisions.push((label.to_string(), reg.clone(), m));
                }
            }
        }
        assert!(
            collisions.is_empty(),
            "these ordinary app labels would be reported as lookalikes: {collisions:?}"
        );
        assert!(ordinary.len() >= 100, "corpus shrank to {}", ordinary.len());
    }

    /// And the other half of the same figure: every impersonation shape the docs claim to
    /// catch, actually caught. A precision corpus with no recall corpus beside it is how a
    /// rule that fires on nothing scores 0.0 % false positives.
    #[test]
    fn every_claimed_impersonation_shape_is_caught() {
        let wechat = fold_label("WeChat");
        let weixin = fold_label("微信");
        // A doubled trailing letter on a *registry* name is a typosquat, and it is caught. Kept
        // beside the WeChat cases because the false-positive corpus deliberately excludes it.
        assert_eq!(
            label_match(&fold_label("Meituann"), &fold_label("Meituan")),
            Some(LabelMatch::Typo)
        );
        let caught = |label: &str| -> bool {
            let f = fold_label(label);
            label_match(&f, &wechat).is_some() || label_match(&f, &weixin).is_some()
        };
        for label in [
            "WeChat",
            "wechat",
            "WECHAT",
            "We Chat",
            "We-Chat",
            "We_Chat",
            "We.Chat",
            "  WeChat",
            "WeChat ",
            "WeChat!",
            "[WeChat]",
            "Wеchat",         // Cyrillic е
            "WeСhat",         // Cyrillic С
            "Wechаt",         // Cyrillic а
            "ＷｅＣｈａｔ",   // full-width
            "We\u{200b}Chat", // zero-width space
            "We\u{200d}Chat", // ZWJ
            "WeChat\u{ad}",   // soft hyphen
            "WeChat\u{202e}", // bidi override
            "Wéchat",
            "Wechät",
            "Wečhat", // precomposed Latin
            "W3Chat", // 3→e is mapped, so this folds to `wechat` exactly
            "WeChatt",
            "Wechta", // the two typo shapes
            "微信",
            "微\u{200b}信",
            "微信 ",
        ] {
            assert!(
                caught(label),
                "not caught: {label:?} folds to {:?}",
                fold_label(label)
            );
        }
        // And the shapes that are **not** caught, stated so the gap is visible rather than
        // discovered. Each is a real evasion of the label rule.
        for missed in [
            "WeCh4t",     // `4`→`a` is not in the map, and a substitution is not a typo shape
            "Wechet",     // a one-letter substitution
            "WebChat",    // an insertion
            "WeChat Pay", // containment
            "Wеchаt Lite",
        ] {
            assert!(
                !caught(missed),
                "unexpectedly caught {missed:?} — update the docs"
            );
        }
    }

    /// `typo_variants` must generate **exactly** the strings `label_match` calls a `Typo`.
    ///
    /// Exhaustive over a small alphabet in both directions. The comment on `typo_variants` claimed
    /// a test of this name existed for a whole iteration while it did not, and the consequence was
    /// live: only the lengthening direction was generated, so a registered `Google` had no key for
    /// an observed `Gogle` and the shipped path silently failed to match what the rule accepts.
    #[test]
    fn typo_variants_mirror_label_match() {
        let alphabet = ['a', 'b', 'c', 'd', 'e'];
        for base_len in 5..=7usize {
            // A handful of bases with and without repeated characters.
            for seed in 0..40usize {
                let base: String = (0..base_len)
                    .map(|i| alphabet[(seed / (i + 1) + i) % alphabet.len()])
                    .collect();
                let generated: std::collections::HashSet<String> =
                    typo_variants(&base).into_iter().collect();
                // Direction 1: everything generated must match.
                for v in &generated {
                    assert_eq!(
                        label_match(v, &base),
                        Some(LabelMatch::Typo),
                        "generated {v:?} does not match {base:?}"
                    );
                }
                // Direction 2: everything that matches must be generated. Enumerate every string
                // within one insertion, deletion or substitution over the alphabet.
                let cs: Vec<char> = base.chars().collect();
                let mut candidates: Vec<String> = Vec::new();
                for i in 0..=cs.len() {
                    for a in alphabet {
                        let mut v = cs.clone();
                        v.insert(i, a);
                        candidates.push(v.into_iter().collect());
                    }
                }
                for i in 0..cs.len() {
                    let mut v = cs.clone();
                    v.remove(i);
                    candidates.push(v.into_iter().collect());
                    for a in alphabet {
                        let mut v = cs.clone();
                        v[i] = a;
                        candidates.push(v.into_iter().collect());
                    }
                }
                for i in 0..cs.len().saturating_sub(1) {
                    let mut v = cs.clone();
                    v.swap(i, i + 1);
                    candidates.push(v.into_iter().collect());
                }
                for c in candidates {
                    if c == base {
                        continue;
                    }
                    if label_match(&c, &base) == Some(LabelMatch::Typo) {
                        assert!(
                            generated.contains(&c),
                            "{c:?} matches {base:?} but is not generated"
                        );
                    }
                }
            }
        }
    }

    /// The **indexed** path must agree with a brute-force scan of the rule, on generated
    /// registries. This is the test that would have caught the missing doubling direction, and it
    /// is the only test that exercises what actually ships: the recall corpus tests `label_match`,
    /// which is not the code path `resolve_appearance` takes.
    #[test]
    fn face_index_agrees_with_a_brute_force_scan() {
        let alphabet = ['a', 'b', 'c', 'd'];
        let mut checked = 0usize;
        let mut disagreements: Vec<String> = Vec::new();
        for seed in 0..300usize {
            // A two-app registry with generated labels, and a generated observed label.
            let mk = |n: usize, len: usize| -> String {
                (0..len)
                    .map(|i| alphabet[(n / (i + 1) + i * 3) % alphabet.len()])
                    .collect()
            };
            let a = mk(seed, 5 + seed % 3);
            let b = mk(seed * 7 + 1, 5 + (seed / 3) % 3);
            if a == b {
                continue;
            }
            let fa = vec![a.clone()];
            let fb = vec![b.clone()];
            let no_icons: Vec<IconHash> = vec![];
            let faces = vec![
                RegisteredFace {
                    name: "A",
                    folded: &fa,
                    icons: &no_icons,
                },
                RegisteredFace {
                    name: "B",
                    folded: &fb,
                    icons: &no_icons,
                },
            ];
            let index = FaceIndex::build(faces.clone());
            for probe_seed in 0..12usize {
                let observed = mk(seed * 13 + probe_seed, 4 + probe_seed % 4);
                // Brute force: the rule, applied directly.
                let mut expect: Option<(&str, LabelMatch)> = None;
                for f in &faces {
                    for reg in f.folded {
                        if let Some(m) = label_match(&observed, reg) {
                            if expect.is_none_or(|(_, prev)| m > prev) {
                                expect = Some((f.name, m));
                            }
                        }
                    }
                }
                let got = Appearance::resolve_indexed(
                    Some(&observed),
                    None,
                    OwnIdentity::Unregistered,
                    &index,
                );
                checked += 1;
                let got_pair = match &got {
                    Appearance::Impersonation {
                        registered,
                        evidence: Evidence::Label(m),
                        ..
                    } => Some((registered.as_str(), *m)),
                    _ => None,
                };
                let expect_pair = expect;
                // The names differ only when two apps tie; compare the *class*, and the name only
                // when the scan found a unique best.
                let same = match (expect_pair, got_pair) {
                    (None, None) => true,
                    (Some((_, em)), Some((_, gm))) => em == gm,
                    _ => false,
                };
                if !same {
                    disagreements.push(format!(
                        "observed {observed:?} vs A={a:?} B={b:?}: scan {expect_pair:?}, index {got_pair:?}"
                    ));
                }
            }
        }
        assert!(
            checked > 2_000,
            "only {checked} probes — the generator went degenerate"
        );
        assert!(
            disagreements.is_empty(),
            "{} disagreements between the indexed path and the rule, e.g. {:?}",
            disagreements.len(),
            &disagreements[..disagreements.len().min(5)]
        );
    }

    /// A label that is a variant of **two** apps must not be silenced by one of them being the
    /// observed app's own entry, and the verdict must not depend on registry order.
    #[test]
    fn an_ambiguous_variant_is_not_silenced_by_the_own_entry() {
        let fa = vec!["aabcde".to_string()];
        let fb = vec!["abbcde".to_string()];
        let no_icons: Vec<IconHash> = vec![];
        for order in [0, 1] {
            let faces = if order == 0 {
                vec![
                    RegisteredFace {
                        name: "Aabcde",
                        folded: &fa,
                        icons: &no_icons,
                    },
                    RegisteredFace {
                        name: "Abbcde",
                        folded: &fb,
                        icons: &no_icons,
                    },
                ]
            } else {
                vec![
                    RegisteredFace {
                        name: "Abbcde",
                        folded: &fb,
                        icons: &no_icons,
                    },
                    RegisteredFace {
                        name: "Aabcde",
                        folded: &fa,
                        icons: &no_icons,
                    },
                ]
            };
            // `aabbcde` doubles from both labels.
            assert_eq!(label_match("aabbcde", "aabcde"), Some(LabelMatch::Typo));
            assert_eq!(label_match("aabbcde", "abbcde"), Some(LabelMatch::Typo));
            let got = Appearance::resolve(
                Some("aabbcde"),
                None,
                OwnIdentity::Verified("Aabcde"),
                faces,
            );
            assert!(
                matches!(got, Appearance::Impersonation { ref registered, .. } if registered == "Abbcde"),
                "order {order}: {got:?}"
            );
        }
    }

    #[test]
    fn icon_hash_round_trips_and_rejects_junk() {
        let h = IconHash::parse("0f1e2d3c4b5a6978").unwrap();
        assert_eq!(h.to_string(), "0f1e2d3c4b5a6978");
        assert_eq!(IconHash::parse("0f1e2d3c4b5a697"), None, "15 chars");
        assert_eq!(IconHash::parse("0f1e2d3c4b5a69789"), None, "17 chars");
        assert_eq!(IconHash::parse("0f1e2d3c4b5a697g"), None, "non-hex");
        assert_eq!(IconHash::parse(""), None);
    }

    #[test]
    fn icon_distance_and_threshold() {
        let a = IconHash::parse("0f1e2d3c4b5a6978").unwrap();
        assert_eq!(a.distance(&a), 0);
        assert!(a.matches(&a));
        // Flip exactly ICON_MATCH_MAX_DISTANCE bits: still a match.
        let near = IconHash(a.bits() ^ 0b1111);
        assert_eq!(a.distance(&near), ICON_MATCH_MAX_DISTANCE);
        assert!(a.matches(&near));
        // One more bit: not a match.
        let far = IconHash(a.bits() ^ 0b1_1111);
        assert_eq!(a.distance(&far), ICON_MATCH_MAX_DISTANCE + 1);
        assert!(!a.matches(&far));
    }

    /// Two flat icons hash identically. That must not be a match — it is the one case
    /// where this hash is worthless rather than merely imperfect.
    #[test]
    fn degenerate_hashes_never_match() {
        let flat = IconHash::parse("0000000000000000").unwrap();
        let solid = IconHash::parse("ffffffffffffffff").unwrap();
        assert!(flat.is_degenerate() && solid.is_degenerate());
        assert!(!flat.matches(&flat), "a flat icon matches every flat icon");
        assert!(!solid.matches(&solid));
        // A gradient with only a few structural bits is degenerate too.
        let sparse = IconHash::parse("0000000000000007").unwrap();
        assert!(sparse.is_degenerate());
        // A structured hash is not.
        assert!(!IconHash::parse("0f1e2d3c4b5a6978").unwrap().is_degenerate());
    }

    /// **The measurement `ICON_MATCH_MAX_DISTANCE` and `Evidence::is_advisory` rest on.**
    ///
    /// The docs quote a false-match rate for the icon channel, and until this test existed those
    /// figures came from a scratch program that was not part of the artifact — for a fix whose whole
    /// point was to stop shipping unverified numbers, that was the wrong shape. The corpus is
    /// generated here, deterministically, so anyone can re-derive them by running the suite.
    ///
    /// It also *asserts* the conclusion rather than only printing it: unrelated simple glyphs
    /// collide often enough that icon-only evidence must not be able to intervene.
    /// The Rust half of the cross-language dHash contract.
    ///
    /// `AppFace.kt` reimplements this hash in Kotlin because the companion cannot load the
    /// Rust engine, and its own header calls the algorithm **normative**. Nothing checked
    /// that claim: the two could have disagreed on bit order, on the brightness comparison,
    /// or on which row is most significant, and the only symptom would have been an icon
    /// channel that never matched anything — indistinguishable from a clean device.
    ///
    /// Both sides now assert against `eval/fixtures/icon_dhash_vectors.json`. This test is
    /// half of that; `AppFaceDhashTest` in the companion is the other half.
    #[test]
    fn dhash_matches_the_shared_cross_language_vectors() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../eval/fixtures/icon_dhash_vectors.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse vectors");
        let vectors = doc["vectors"].as_array().expect("vectors array");
        assert!(
            vectors.len() >= 8,
            "a contract this load-bearing needs more than a couple of cases; got {}",
            vectors.len()
        );
        for v in vectors {
            let name = v["name"].as_str().unwrap_or("?");
            let grid: Vec<u8> = v["grid"]
                .as_array()
                .expect("grid")
                .iter()
                .map(|n| u8::try_from(n.as_u64().expect("grid sample")).expect("0..=255"))
                .collect();
            assert_eq!(grid.len(), 72, "{name}: a grid is 9 columns by 8 rows");
            let hash = IconHash::from_grid_9x8(&grid)
                .unwrap_or_else(|| panic!("{name}: from_grid_9x8 refused a 72-sample grid"));
            assert_eq!(
                hash.to_string(),
                v["hash"].as_str().expect("hash"),
                "{name}: the Rust hash disagrees with the shared vector"
            );
            // Every vector must be usable by both sides, so none may be degenerate: a
            // degenerate vector would exercise the refusal path and prove nothing about the
            // algorithm the two languages have to share.
            assert!(
                !hash.is_degenerate(),
                "{name}: vector is degenerate, so it cannot test cross-language agreement"
            );
        }
    }

    #[test]
    fn the_icon_channel_false_match_rate_is_measured_not_assumed() {
        const S: usize = 192;
        // Stroke vocabulary, drawn dark-on-white — the dominant real app-icon style.
        let stroke = |k: usize, x: f32, y: f32| -> bool {
            match k {
                0 => x > 0.22 && x < 0.34 && y > 0.2 && y < 0.8, // left vertical
                1 => x > 0.66 && x < 0.78 && y > 0.2 && y < 0.8, // right vertical
                2 => y > 0.68 && y < 0.8 && x > 0.22 && x < 0.78, // bottom bar
                3 => y > 0.44 && y < 0.56 && x > 0.22 && x < 0.78, // middle bar
                4 => (x - y).abs() < 0.08 && y > 0.2 && y < 0.8, // diagonal
                5 => y > 0.2 && y < 0.32 && x > 0.22 && x < 0.78, // top bar
                6 => x > 0.44 && x < 0.56 && y > 0.2 && y < 0.8, // centre vertical
                _ => (x + y - 1.0).abs() < 0.08 && y > 0.2 && y < 0.8, // anti-diagonal
            }
        };
        // Distinct stroke sets: crude letterforms plus geometric marks. No two are identical.
        let glyphs: Vec<Vec<usize>> = vec![
            vec![0, 1, 3, 5],
            vec![0, 1, 5, 3, 2],
            vec![0, 2, 5],
            vec![0, 1, 2, 5],
            vec![0, 2, 3, 5],
            vec![0, 3, 5],
            vec![0, 2, 4, 5],
            vec![0, 1, 3],
            vec![1, 2],
            vec![0, 3, 4],
            vec![0, 2],
            vec![0, 1, 4, 6],
            vec![0, 1, 4],
            vec![0, 1, 3, 5, 2],
            vec![0, 1, 2, 4, 5],
            vec![0, 1, 3, 4, 5],
            vec![2, 3, 5, 1],
            vec![5, 6],
            vec![0, 1, 2],
            vec![0, 4],
            vec![0, 1, 2, 4],
            vec![4, 7],
            vec![4, 6],
            vec![2, 5, 7],
            vec![3, 6],
            vec![1, 3, 5],
            vec![0, 6],
            vec![2, 4],
            vec![1, 5, 7],
            vec![0, 5, 7],
        ];
        let mut hashes: Vec<IconHash> = Vec::new();
        let mut degenerate = 0usize;
        for set in &glyphs {
            let mut px = vec![255u8; S * S * 4];
            for y in 0..S {
                for x in 0..S {
                    let (fx, fy) = (x as f32 / S as f32, y as f32 / S as f32);
                    if set.iter().any(|k| stroke(*k, fx, fy)) {
                        let i = (y * S + x) * 4;
                        px[i] = 20;
                        px[i + 1] = 20;
                        px[i + 2] = 20;
                    }
                }
            }
            match IconHash::from_rgba(&px, S, S, false) {
                Some(h) if !h.is_degenerate() => hashes.push(h),
                _ => degenerate += 1,
            }
        }
        assert!(
            hashes.len() >= 20,
            "only {} comparable glyphs of {} — the generator went degenerate",
            hashes.len(),
            glyphs.len()
        );
        let mut pairs = 0usize;
        let mut within_threshold = 0usize;
        let mut identical = 0usize;
        let mut max_distance = 0u32;
        for i in 0..hashes.len() {
            for j in i + 1..hashes.len() {
                let d = hashes[i].distance(&hashes[j]);
                pairs += 1;
                max_distance = max_distance.max(d);
                if d <= ICON_MATCH_MAX_DISTANCE {
                    within_threshold += 1;
                }
                if d == 0 {
                    identical += 1;
                }
            }
        }
        let rate = within_threshold as f64 / pairs as f64;
        eprintln!(
            "icon channel: {} comparable glyphs ({degenerate} refused as degenerate), {pairs} \
             unrelated pairs, max distance {max_distance}, {within_threshold} within \
             {ICON_MATCH_MAX_DISTANCE} bits ({:.1}%), {identical} identical",
            hashes.len(),
            100.0 * rate
        );

        // The claim that forced `Evidence::is_advisory`: unrelated simple glyphs DO collide at the
        // shipped threshold. If this ever stops being true, the icon channel could be promoted —
        // and this assertion is what would tell you, rather than a doc going quietly stale.
        assert!(
            rate > 0.01,
            "unrelated simple icons no longer collide at threshold {ICON_MATCH_MAX_DISTANCE} \
             (rate {:.3}%). The measurement behind `Evidence::is_advisory` and the numbers in \
             docs/app-lookalike.md no longer hold — re-derive them before promoting icon evidence.",
            100.0 * rate
        );
        // And the other half of the false claim this replaced: unrelated icons are NOT ~32 bits
        // apart. If the maximum over a whole corpus is well under 32, "wide margin" reasoning about
        // a 64-bit hash is unavailable.
        assert!(
            max_distance < 32,
            "max unrelated distance {max_distance} — the 'unrelated icons sit near 32 bits apart' \
             claim this test was written to refute may hold after all"
        );
        // Icon-only evidence must not be able to intervene, given the above.
        assert!(!Evidence::Icon { distance: 0 }.is_conclusive());
        assert!(Evidence::Icon { distance: 0 }.is_advisory());
    }

    #[test]
    fn rgba_hashing_composites_alpha_onto_white() {
        // A fully transparent image is white everywhere → flat → all zeros.
        let transparent = vec![0u8; 16 * 16 * 4];
        assert_eq!(
            IconHash::from_rgba(&transparent, 16, 16, false)
                .unwrap()
                .bits(),
            0
        );
        // A left-to-right dark→light ramp, opaque: no bit set (left never brighter).
        let mut ramp = vec![0u8; 18 * 16 * 4];
        for y in 0..16 {
            for x in 0..18 {
                let i = (y * 18 + x) * 4;
                let v = (x * 14) as u8;
                ramp[i] = v;
                ramp[i + 1] = v;
                ramp[i + 2] = v;
                ramp[i + 3] = 255;
            }
        }
        assert_eq!(IconHash::from_rgba(&ramp, 18, 16, false).unwrap().bits(), 0);
        // Reversed: every left sample brighter → all ones.
        let mut rev = ramp.clone();
        for y in 0..16 {
            for x in 0..18 {
                let i = (y * 18 + x) * 4;
                let v = ((17 - x) * 14) as u8;
                rev[i] = v;
                rev[i + 1] = v;
                rev[i + 2] = v;
            }
        }
        assert_eq!(
            IconHash::from_rgba(&rev, 18, 16, false).unwrap().bits(),
            u64::MAX
        );
        // Channel order is honoured: a pure-red image read as BGRA is pure blue, and the
        // two have different luma, so a red/blue checkerboard hashes differently.
        let mut checker = vec![255u8; 18 * 16 * 4];
        for y in 0..16 {
            for x in 0..18 {
                let i = (y * 18 + x) * 4;
                let red = (x / 2 + y / 2) % 2 == 0;
                checker[i] = if red { 255 } else { 0 };
                checker[i + 1] = 0;
                checker[i + 2] = if red { 0 } else { 255 };
            }
        }
        let as_rgba = IconHash::from_rgba(&checker, 18, 16, false).unwrap();
        let as_bgra = IconHash::from_rgba(&checker, 18, 16, true).unwrap();
        assert_ne!(as_rgba, as_bgra, "channel order must change the hash");
        // Too small, or a short buffer, is None rather than a partial hash.
        assert_eq!(IconHash::from_rgba(&checker, 8, 8, false), None);
        assert_eq!(IconHash::from_rgba(&checker[..100], 18, 16, false), None);
    }

    #[test]
    fn grid_hashing_matches_the_pinned_algorithm() {
        // Left brighter than right in every pair of every row → all ones.
        let descending: Vec<u8> = (0..8)
            .flat_map(|_| (0..9).map(|c| 90 - c * 10).collect::<Vec<_>>())
            .map(|v| v as u8)
            .collect();
        assert_eq!(
            IconHash::from_grid_9x8(&descending).unwrap().to_string(),
            "ffffffffffffffff"
        );
        // Ascending → no bit set anywhere.
        let ascending: Vec<u8> = (0..8).flat_map(|_| (0..9u8).map(|c| c * 10)).collect();
        assert_eq!(
            IconHash::from_grid_9x8(&ascending).unwrap().to_string(),
            "0000000000000000"
        );
        // Row 0's leftmost comparison is the most significant bit.
        let mut grid = vec![0u8; 72];
        grid[0] = 255;
        assert_eq!(
            IconHash::from_grid_9x8(&grid).unwrap().bits(),
            1u64 << 63,
            "row 0, column 0 must be the MSB"
        );
        // Equal samples do not set a bit — strictly brighter, not brighter-or-equal.
        assert_eq!(IconHash::from_grid_9x8(&[128u8; 72]).unwrap().bits(), 0);
        assert_eq!(IconHash::from_grid_9x8(&[0u8; 71]), None);
    }

    // ── Appearance::resolve ──────────────────────────────────────────────────────

    fn wechat_folded() -> Vec<String> {
        vec!["wechat".to_string(), "微信".to_string()]
    }

    #[test]
    fn a_clone_under_its_own_package_is_impersonation() {
        let icons = vec![];
        let folded = wechat_folded();
        let got = Appearance::resolve(
            Some("WeChat"),
            None,
            OwnIdentity::Unregistered,
            [face("WeChat", &folded, &icons)],
        );
        match got {
            Appearance::Impersonation {
                registered,
                actual,
                evidence,
            } => {
                assert_eq!(registered, "WeChat");
                assert_eq!(actual, None);
                assert_eq!(evidence, Evidence::Label(LabelMatch::Exact));
                assert!(evidence.is_conclusive() && !evidence.is_advisory());
            }
            other => panic!("{other:?}"),
        }
    }

    /// The pure §3.6 attack: an app with its own honest signature and package, wearing
    /// another app's face. Nothing about its *identity* is forged, which is why
    /// `AppIdentity` alone cannot see it.
    #[test]
    fn a_verified_app_wearing_another_verified_face_is_impersonation() {
        let icons = vec![IconHash::parse("0f1e2d3c4b5a6978").unwrap()];
        let folded = wechat_folded();
        let got = Appearance::resolve(
            Some("微信"),
            Some(&IconHash::parse("0f1e2d3c4b5a6978").unwrap()),
            OwnIdentity::Verified("LegacyPOS"),
            [face("WeChat", &folded, &icons)],
        );
        assert!(
            matches!(
                got,
                Appearance::Impersonation {
                    ref registered,
                    actual: Some(ref actual),
                    evidence: Evidence::Both { label: LabelMatch::Exact, distance: 0 },
                } if registered == "WeChat" && actual == "LegacyPOS"
            ),
            "{got:?}"
        );
    }

    /// The normal path, and the one that would have made this check unshippable.
    #[test]
    fn a_verified_app_matching_its_own_entry_is_consistent() {
        let icons = vec![IconHash::parse("0f1e2d3c4b5a6978").unwrap()];
        let folded = wechat_folded();
        for label in ["WeChat", "微信", "WeChat "] {
            assert_eq!(
                Appearance::resolve(
                    Some(label),
                    Some(&IconHash::parse("0f1e2d3c4b5a6978").unwrap()),
                    OwnIdentity::Verified("WeChat"),
                    [face("WeChat", &folded, &icons)],
                ),
                Appearance::Consistent,
                "{label}"
            );
        }
    }

    /// **The hole that made forging one more field a downgrade.** A package that merely claims
    /// WeChat's entry, wearing WeChat's face, is `Unprovable` — not `Consistent`.
    #[test]
    fn a_claimed_own_entry_is_unprovable_not_consistent() {
        let icons = vec![IconHash::parse("0f1e2d3c4b5a6978").unwrap()];
        let folded = wechat_folded();
        assert_eq!(
            Appearance::resolve(
                Some("微信"),
                Some(&IconHash::parse("0f1e2d3c4b5a6978").unwrap()),
                OwnIdentity::Claimed("WeChat"),
                [face("WeChat", &folded, &icons)],
            ),
            Appearance::Unprovable {
                registered: "WeChat".into()
            }
        );
        // A claimed entry whose face matches *nothing* is simply consistent: there is no
        // appearance to be unable to prove.
        assert_eq!(
            Appearance::resolve(
                Some("Something Else"),
                None,
                OwnIdentity::Claimed("WeChat"),
                [face("WeChat", &folded, &icons)],
            ),
            Appearance::Consistent
        );
    }

    /// Each channel is excused only by its **own** channel matching the app's own entry.
    #[test]
    fn one_own_channel_does_not_excuse_the_other() {
        let wechat_icon = IconHash::parse("0f1e2d3c4b5a6978").unwrap();
        let pos_icon = IconHash::parse("123456789abcdef0").unwrap();
        let wechat_icons = vec![wechat_icon];
        let pos_icons = vec![pos_icon];
        let wechat = wechat_folded();
        let pos = vec!["legacypos".to_string()];
        let faces = || {
            vec![
                face("WeChat", &wechat, &wechat_icons),
                face("LegacyPOS", &pos, &pos_icons),
            ]
        };
        // Own icon kept, label cloned → conclusive impersonation.
        let got = Appearance::resolve(
            Some("微信"),
            Some(&pos_icon),
            OwnIdentity::Verified("LegacyPOS"),
            faces(),
        );
        assert!(
            matches!(
                got,
                Appearance::Impersonation { ref registered, evidence: Evidence::Label(LabelMatch::Exact), .. }
                if registered == "WeChat"
            ),
            "own icon must not excuse a cloned label: {got:?}"
        );
        // Own label kept, icon cloned → advisory impersonation.
        let got = Appearance::resolve(
            Some("LegacyPOS"),
            Some(&wechat_icon),
            OwnIdentity::Verified("LegacyPOS"),
            faces(),
        );
        assert!(
            matches!(
                got,
                Appearance::Impersonation { ref registered, evidence: Evidence::Icon { distance: 0 }, .. }
                if registered == "WeChat"
            ),
            "own label must not excuse a cloned icon: {got:?}"
        );
        match got {
            Appearance::Impersonation { evidence, .. } => {
                assert!(evidence.is_advisory() && !evidence.is_conclusive());
            }
            other => panic!("{other:?}"),
        }
    }

    /// A registered app that has changed its icon since the registry was written is not an
    /// impersonator. Absence of a visual match is never evidence.
    #[test]
    fn a_changed_icon_is_not_a_finding() {
        let icons = vec![IconHash::parse("0f1e2d3c4b5a6978").unwrap()];
        let folded = wechat_folded();
        assert_eq!(
            Appearance::resolve(
                Some("WeChat"),
                Some(&IconHash::parse("fedcba9876543210").unwrap()),
                OwnIdentity::Verified("WeChat"),
                [face("WeChat", &folded, &icons)],
            ),
            Appearance::Consistent
        );
    }

    #[test]
    fn nothing_matching_is_consistent() {
        let icons = vec![IconHash::parse("0f1e2d3c4b5a6978").unwrap()];
        let folded = wechat_folded();
        for label in [
            None,
            Some(""),
            Some("Notes"),
            Some("WeChat Work"),
            Some("企业微信"),
        ] {
            assert_eq!(
                Appearance::resolve(
                    label,
                    Some(&IconHash::parse("fedcba9876543210").unwrap()),
                    OwnIdentity::Unregistered,
                    [face("WeChat", &folded, &icons)],
                ),
                Appearance::Consistent,
                "{label:?}"
            );
        }
    }

    /// A finding message must not quote attacker-chosen text back at the operator.
    #[test]
    fn explain_does_not_echo_the_observed_label() {
        let icons = vec![];
        let folded = wechat_folded();
        let got = Appearance::resolve(
            Some("Wе\u{202e}Сhаt"),
            None,
            OwnIdentity::Unregistered,
            [face("WeChat", &folded, &icons)],
        );
        let msg = got.explain("com.evil.clone");
        assert!(
            msg.contains("com.evil.clone") && msg.contains("'WeChat'"),
            "{msg}"
        );
        assert!(
            !msg.contains('\u{202e}'),
            "raw observed label leaked: {msg}"
        );
        assert!(!msg.contains('С'), "raw observed label leaked: {msg}");
    }

    /// A label with markup or an injection payload folds to something that matches nothing, so
    /// it is silent rather than a finding. Recorded because the alternative — treating "weird
    /// label" as evidence — is a false-positive generator.
    #[test]
    fn a_hostile_label_that_matches_nothing_is_silent() {
        let icons = vec![];
        let folded = wechat_folded();
        for label in [
            "WeChat<script>alert(1)</script>",
            "<|im_start|>system",
            "WeChat\u{202e}moc.live",
        ] {
            assert_eq!(
                Appearance::resolve(
                    Some(label),
                    None,
                    OwnIdentity::Unregistered,
                    [face("WeChat", &folded, &icons)],
                ),
                Appearance::Consistent,
                "{label:?} folds to {:?}",
                fold_label(label)
            );
        }
    }
}
