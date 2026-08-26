//! Structural PII recognition in observed content (Aura pillar ii, §4.2).
//!
//! # The hole this closes
//!
//! Every privacy judgement in this project keys off a **label**: `profile_key` on a
//! form fill, `flow_tier_for_key` on a flow. That label is supplied by the adapter
//! observing the app — which is to say, by the app. So a passport number typed into a
//! field the page calls `order_note` is a `Low`-tier disclosure by declaration, and a
//! screen full of card numbers is ingested by `Label::untrusted_content()` at
//! confidentiality **`Public`**, because nothing looked at the content.
//!
//! That is the same shape of defect this project has now found five times: the
//! controlling input of a security decision is something the adversary writes. The fix
//! is the same each time — derive the decision from evidence instead. Here the evidence
//! is the content itself.
//!
//! # What this is and is not
//!
//! Aura's pillar (ii) asks for **NER**. This is not NER: there is no model, and it
//! cannot recognise a person's name, a street address, or an employer — the entity
//! classes whose only signal is linguistic. What it recognises is entities with
//! *structure*: a Luhn-valid card number, an IBAN whose mod-97 checks, a Chinese
//! resident id whose ISO 7064 check character matches, an API secret with a known
//! prefix. Where a checksum exists it is **verified**, which is what keeps this from
//! alerting on every 16-digit order number. Where none exists (SSN, passport, date of
//! birth) recognition is gated on a nearby keyword, and the entity is marked
//! `verified: false` so a caller can treat it as weaker evidence — because it is.
//!
//! `docs/semantic-firewall.md` states the classes it cannot see, rather than letting
//! "PII detection" imply all of them.
//!
//! # No regex
//!
//! Hand-written linear scanners, deliberately. This runs on the accessibility hot path
//! over text an attacker controls, and a backtracking regex there is a denial-of-service
//! surface: the guard would be the thing that hangs the device. Every scanner below is
//! single-pass over the character vector with a bounded lookahead.
//!
//! # Findings must not leak what they found
//!
//! An [`Entity`] never carries the matched text. It carries a redaction — `•••• 4242`,
//! `a…@example.com` — because the consumer of a finding is an audit record, and an audit
//! record is hashed, signed, exported and shipped to an auditor. A privacy control whose
//! own alert copies the card number into a signed log has moved the leak, not stopped it.

use serde::{Deserialize, Serialize};

use crate::taint::Confidentiality;

/// A class of entity this module can recognise structurally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// Luhn-valid primary account number.
    PaymentCard,
    /// IBAN whose mod-97 checksum holds.
    Iban,
    /// PRC resident identity number, ISO 7064:1983 MOD 11-2 verified.
    NationalIdCn,
    /// US social security number, separator-formatted. No checksum exists.
    Ssn,
    /// RFC-shaped address.
    Email,
    /// E.164, or a digit run next to a telephone keyword.
    PhoneNumber,
    /// Alphanumeric token next to a passport keyword. No checksum exists.
    PassportNumber,
    /// Credential with a known issuer prefix, or a PEM private key header.
    ApiSecret,
    /// Date next to a birth keyword. No checksum exists.
    DateOfBirth,
}

impl EntityKind {
    /// Confidentiality this entity's presence implies for the content holding it.
    ///
    /// Everything here is `High`. That is not laziness: the tiers in
    /// `GuardContract::high_keys` already class `email` and `phone_number` as High, and
    /// an entity recogniser that graded some of its own findings `Low` would be
    /// second-guessing the policy from a weaker position — it sees a fragment of a
    /// screen, the policy sees the deployment.
    pub fn confidentiality(self) -> Confidentiality {
        Confidentiality::High
    }

    /// Whether this class is confirmed by arithmetic rather than by shape alone.
    pub fn has_checksum(self) -> bool {
        matches!(
            self,
            Self::PaymentCard | Self::Iban | Self::NationalIdCn | Self::ApiSecret
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PaymentCard => "payment_card",
            Self::Iban => "iban",
            Self::NationalIdCn => "national_id_cn",
            Self::Ssn => "ssn",
            Self::Email => "email",
            Self::PhoneNumber => "phone_number",
            Self::PassportNumber => "passport_number",
            Self::ApiSecret => "api_secret",
            Self::DateOfBirth => "date_of_birth",
        }
    }
}

/// One recognised entity. Never carries the matched text — see the module doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    pub kind: EntityKind,
    /// Enough to recognise the finding again without reproducing the value.
    pub redacted: String,
    /// True when a checksum confirmed it; false when only shape and context did.
    pub verified: bool,
}

impl Entity {
    fn new(kind: EntityKind, redacted: String, verified: bool) -> Self {
        Self {
            kind,
            redacted,
            verified,
        }
    }
}

/// Recognise every entity class in `text`.
///
/// Order is by class, then by position, and duplicates of the same `(kind, redaction)`
/// collapse — a screen repeating one card number is one finding, not forty.
/// 扫描前的归一化,以及回到原文的索引映射。
///
/// # 为什么必须有这一层
///
/// 识别器以前直接在原文的 `Vec<char>` 上跑,而且只认 `is_ascii_digit` 和两种分隔符
/// (`' '`/`'-'`)。于是下面这些**自然文本**里的卡号一个都识别不出来:
///
/// ```text
/// found    "Saved card 4242424242424242"     -> ["payment_card"]
/// MISSED   "Saved card 4242424242424242."    -> []      句尾句号
/// MISSED   "Card ending 4242424242424242. Thank you." -> []
/// MISSED   "4242.4242.4242.4242"             -> []      点分隔
/// MISSED   NBSP / 零宽 / 软连字符 分隔        -> []
/// MISSED   全角身份证号                       -> []
/// found    "Saved card 4242424242424242,"    -> ["payment_card"]   逗号可以,句号不行
/// ```
///
/// 而漏掉的后果是完整的两条:`ContentScan` 的 `verified_fields` 为空 →
/// `redact_event_for_audit` 返回 `None` → **完整的 PAN 原样写进 `AuditRecord::event_json`**
/// (在哈希链内、签名内、可导出);同时 `confidentiality()` 为 `None` → 标签停在 Public →
/// 后续 `data_flow` 到公网 sink 判 `Allow` 而不是 `FLOW-CONF/Block`。
///
/// 复核实测的九个变体里有八个被放行到公网 sink。而其中软连字符、点分隔、全角数字、句尾
/// 句号**连一条补偿性的文本异常告警都没有**。
///
/// 返回归一化后的字符,以及每个归一化字符对应的**原文字符下标** —— 后者让遮蔽器能把
/// 识别到的区间映射回原文,这是两个实现能就"一段值是什么"达成一致的基础。
fn normalise_for_scan(text: &str) -> (Vec<char>, Vec<usize>) {
    let mut out = Vec::with_capacity(text.chars().count());
    let mut map = Vec::with_capacity(text.chars().count());
    for (idx, c) in text.chars().enumerate() {
        // 不可见的格式字符不能把一段值切成两半 —— 它们在屏幕上不占位置,所以人看到的
        // 是一个连续的号码。剥掉它们,索引映射保证遮蔽仍然覆盖原文的那些位置。
        if is_invisible_separator(c) {
            continue;
        }
        // 非 ASCII 的空格折成普通空格,非 ASCII 的数字折成 ASCII 数字。
        let folded = if matches!(c, '\u{a0}' | '\u{202f}' | '\u{2007}' | '\u{2060}') {
            ' '
        } else {
            fold_digit(c)
        };
        out.push(folded);
        map.push(idx);
    }
    (out, map)
}

/// 零宽与软连字符类:剥掉,不作为分隔符。
fn is_invisible_separator(c: char) -> bool {
    matches!(c,
        '\u{00ad}'                     // soft hyphen
        | '\u{200b}'..='\u{200f}'      // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{2028}'..='\u{202e}'
        | '\u{2061}'..='\u{2064}'
        | '\u{feff}'
        | '\u{034f}'
        | '\u{061c}'
        | '\u{180b}'..='\u{180e}'
    )
}

/// 非 ASCII 的十进制数字折成 ASCII。
///
/// 与 [`crate::logsafe`] 的 `is_digit` 覆盖同一批区段 —— 那个函数早就认全角数字了,
/// 而识别器没有,于是全角身份证号在显示路径被遮、在**审计路径**却原样留下。
fn fold_digit(c: char) -> char {
    // 全角拉丁字母也要折。身份证号的校验位可以是全角 X(U+FF38),而
    // `scan_national_id_cn` 只认 ASCII X —— 于是一个全角身份证号在数字都折对之后仍然
    // 识别不出来,只因为最后一位没折。
    if ('\u{ff21}'..='\u{ff3a}').contains(&c) {
        return char::from_u32(c as u32 - 0xff21 + 'A' as u32).unwrap_or(c);
    }
    if ('\u{ff41}'..='\u{ff5a}').contains(&c) {
        return char::from_u32(c as u32 - 0xff41 + 'a' as u32).unwrap_or(c);
    }
    let base = match c {
        '\u{ff10}'..='\u{ff19}' => Some('\u{ff10}'), // full-width
        '\u{0660}'..='\u{0669}' => Some('\u{0660}'), // Arabic-indic
        '\u{06f0}'..='\u{06f9}' => Some('\u{06f0}'), // Extended Arabic-indic
        '\u{0966}'..='\u{096f}' => Some('\u{0966}'), // Devanagari
        _ => None,
    };
    match base {
        Some(b) => char::from_digit(c as u32 - b as u32, 10).unwrap_or(c),
        None => c,
    }
}

/// 数字分组分隔符。**一份**定义,识别器和遮蔽器共用。
///
/// 以前两边各写一遍,而且不一样:识别器认 `' '`/`'-'`,遮蔽器也认 `' '`/`'-'`,但
/// `scan_iban` 的分组路径认**任何**非字母数字字符。于是逗号/斜杠/换行/点分组的 IBAN 被判
/// `verified: true`(调用方据此认为该字段已送去遮蔽),而遮蔽器一个字符都不改:
///
/// ```text
/// THEATRE "IBAN GB82,WEST,1234,5698,7654,32"  verified=["iban"]  masked 完全未变
/// THEATRE "IBAN GB82/WEST/…"                  verified=["iban"]  masked 完全未变
/// THEATRE "IBAN GB82.WEST.…"                  verified=["iban"]  masked 完全未变
/// ```
///
/// 审计行报告"已脱敏",实际存的是完整 IBAN。这正是模块文档说上一轮已经修掉的失败模式,
/// 只是换了一种分隔符又复现了一次 —— 因为两个独立实现在猜同一件事。
pub(crate) const RUN_SEPARATORS: &[char] = &[' ', '-', '.', ',', '/', '\u{2013}', '\u{2014}'];

fn is_run_separator(c: char) -> bool {
    RUN_SEPARATORS.contains(&c)
}

pub fn recognise(text: &str) -> Vec<Entity> {
    if text.is_empty() {
        return Vec::new();
    }
    let (chars, _map) = normalise_for_scan(text);
    let text: String = chars.iter().collect();
    let text = text.as_str();
    // Lowercased **once**, as a char vector, and passed down by reference.
    //
    // `keyword_before` used to build this per call, i.e. once per candidate token: the
    // scanners were linear but the keyword gate made the whole pass quadratic, and 300 KB
    // of identifier-shaped text took 7.2 s inside `Engine::process` — in a release build,
    // on the accessibility hot path, in a module whose own doc says a backtracking regex
    // is unacceptable *because* it could hang the device. Replacing a regex DoS with a
    // hand-rolled one is not an improvement.
    //
    // A single lowercased vector is not always index-aligned with `chars` (a few code
    // points change length when lowercased), so the keyword window is deliberately
    // approximate — see `keyword_before`.
    let lower_chars: Vec<char> = text.to_lowercase().chars().collect();
    let mut out = Vec::new();

    scan_api_secrets(text, &mut out);
    scan_digit_runs(&chars, &lower_chars, &mut out);
    scan_iban(&chars, &mut out);
    scan_national_id_cn(&chars, &mut out);
    scan_emails(&chars, &mut out);
    scan_ssn(&chars, &mut out);
    scan_keyword_gated(&chars, &lower_chars, &mut out);

    out.sort_by(|a, b| {
        a.kind
            .as_str()
            .cmp(b.kind.as_str())
            .then_with(|| a.redacted.cmp(&b.redacted))
    });
    out.dedup();
    out
}

/// The highest confidentiality any recognised entity implies, if any.
///
/// The convenience the engine actually uses: content is at least as sensitive as the
/// most sensitive thing recognised in it.
pub fn recognised_confidentiality(text: &str) -> Option<Confidentiality> {
    recognise(text)
        .iter()
        .map(|e| e.kind.confidentiality())
        .max()
}

/// Whether any entity in `text` is confirmed by a checksum.
///
/// Callers that want to act rather than log should prefer this: shape-and-keyword
/// evidence is worth recording and not worth blocking traffic over.
pub fn has_verified_entity(text: &str) -> bool {
    recognise(text).iter().any(|e| e.verified)
}

/// Mask anything in `text` that could be an account number or a credential.
///
/// A *separate, deliberately blunter* pass from [`recognise`], and it exists for one
/// reason: the finding is not the only copy. `AuditRecord::event_json` stores the whole
/// event verbatim, so the same `Engine::process` call that reported a redacted
/// `payment_card` also wrote the PAN into a hashed, signed, exportable audit row. The
/// module doc's argument — "a privacy control whose own alert copies the card number into
/// a signed log has moved the leak, not stopped it" — applied to the guard's own audit
/// path, and the first cut did not notice.
///
/// Blunter on purpose, and in the safe direction: it masks every ≥13-digit run, every
/// IBAN-shaped token and every token with a credential prefix, without asking whether a
/// checksum passes. Over-masking an audit row costs forensic detail; under-masking it
/// costs the user their card number. The caller applies this only to fields where
/// [`recognise`] already found a **checksum-verified** entity, so an audit log is not
/// quietly degraded on the strength of a keyword match.
///
/// The last four characters survive, so a row can still be correlated with a receipt.
pub fn mask_sensitive_runs(text: &str) -> String {
    mask_runs_and_tokens(text, true)
}

/// The token half of [`mask_sensitive_runs`] only: IBAN-shaped tokens, credential prefixes
/// and PEM blocks, leaving digit runs alone.
///
/// [`crate::logsafe::log_safe`] needs this because it applies its own digit-run rule with
/// exemptions (a `timestamp_ms`, an `evidence_ref`, a currency amount), and composing the
/// two meant the audit masker got there first and masked the very fields the display rule
/// exists to keep readable.
pub fn mask_tokens_only(text: &str) -> String {
    mask_runs_and_tokens(text, false)
}

fn mask_runs_and_tokens(text: &str, mask_digit_runs: bool) -> String {
    // 和识别器走**同一份**归一化和**同一套**分隔符。
    //
    // 两个独立实现猜同一件事,是"已核验但没被遮蔽"那一类缺陷的结构性来源:识别器报出一个
    // checksum 已验证的 IBAN,调用方据此认为该字段已送去遮蔽,而遮蔽器因为分隔符集合不同
    // 而一个字符都不改。现在它们共用 `normalise_for_scan` 和 `RUN_SEPARATORS`,并且
    // `chars_are_verified_together` 那条测试把"识别到的一定被遮到"钉成一条性质。
    let (chars, map) = normalise_for_scan(text);
    let orig: Vec<char> = text.chars().collect();
    // 归一化下标 -> 是否要被遮蔽。按区间标记,最后按原文回写。
    let mut masked_as: Vec<Option<String>> = vec![None; chars.len()];
    let mut covered = vec![false; chars.len()];
    let mut i = 0usize;
    while i < chars.len() {
        // Digit runs, separators tolerated, as in `scan_digit_runs`.
        if chars[i].is_ascii_digit() && (i == 0 || !chars[i - 1].is_alphanumeric()) {
            let start = i;
            let mut digits = 0usize;
            let mut j = i;
            while j < chars.len() {
                if chars[j].is_ascii_digit() {
                    digits += 1;
                    j += 1;
                } else if is_run_separator(chars[j])
                    && j + 1 < chars.len()
                    && chars[j + 1].is_ascii_digit()
                {
                    j += 1;
                } else {
                    break;
                }
            }
            if mask_digit_runs && digits >= 13 {
                let run: String = chars[start..j].iter().collect();
                masked_as[start] = Some(redact_tail(&run, 4));
                for c in covered[start..j].iter_mut() {
                    *c = true;
                }
                i = j;
                continue;
            }
        }
        // Alphanumeric tokens: IBAN-shaped, or a credential prefix.
        //
        // token 扫描也容忍分隔符,和 `scan_iban` 的分组路径一致 —— 那条路径把连续的 alnum
        // token 拼起来、完全不看中间是什么,而这里以前只认连续 token。分隔符分组的 IBAN
        // 因此被判 verified 却没被遮。
        if chars[i].is_ascii_alphanumeric() && (i == 0 || !is_token_char(chars[i - 1])) {
            let start = i;
            let mut j = i;
            let mut compact = String::new();
            while j < chars.len() {
                if is_token_char(chars[j]) {
                    compact.push(chars[j]);
                    j += 1;
                } else if is_run_separator(chars[j])
                    && j + 1 < chars.len()
                    && chars[j + 1].is_ascii_alphanumeric()
                    && is_iban_shaped_prefix(&compact)
                {
                    j += 1;
                } else {
                    break;
                }
            }
            // 先看紧凑形(原有行为),再看拼接形(分组的 IBAN)。
            let contiguous: String = chars[start..j]
                .iter()
                .take_while(|c| is_token_char(**c))
                .collect();
            let hit = if is_iban_shaped(&contiguous) || has_credential_prefix(&contiguous) {
                Some(contiguous.len())
            } else if is_iban_shaped(&compact) {
                Some(j - start)
            } else {
                None
            };
            if let Some(_len) = hit {
                let whole: String = chars[start..j].iter().collect();
                masked_as[start] = Some(redact_tail(&whole, 4));
                for c in covered[start..j].iter_mut() {
                    *c = true;
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    // 按原文回写。被覆盖区间对应的原文字符(含被剥掉的不可见字符)一并替换掉 ——
    // 否则零宽分隔的号码会留下可见数字。
    let mut out = String::with_capacity(text.len());
    let mut oi = 0usize;
    let mut ni = 0usize;
    while oi < orig.len() {
        if ni < map.len() && map[ni] == oi {
            if let Some(rep) = &masked_as[ni] {
                out.push_str(rep);
            }
            let this_covered = covered[ni];
            if !this_covered {
                out.push(orig[oi]);
            }
            ni += 1;
            oi += 1;
            continue;
        }
        // 这个原文字符在归一化里被剥掉了(不可见)。它属于最近一个归一化位置所在的区间。
        let inside = ni > 0 && covered[ni - 1];
        if !inside {
            out.push(orig[oi]);
        }
        oi += 1;
    }
    // A PEM block is not partially interesting.
    if out.contains("-----BEGIN") && out.contains("PRIVATE KEY-----") {
        return "[redacted: pem_private_key]".into();
    }
    out
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// 一个正在拼接的 token 还有可能长成 IBAN 吗。
///
/// 只用来决定"要不要跨过一个分隔符继续拼",所以判据是前缀形状而不是完整形状:
/// 两个字母 + 两个数字开头,且到目前为止全是字母数字。
fn is_iban_shaped_prefix(partial: &str) -> bool {
    let b = partial.as_bytes();
    if b.len() < 4 || b.len() > 34 {
        return false;
    }
    b[0].is_ascii_alphabetic()
        && b[1].is_ascii_alphabetic()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b.iter().all(|c| c.is_ascii_alphanumeric())
}

fn is_iban_shaped(token: &str) -> bool {
    let b = token.as_bytes();
    (15..=34).contains(&token.len())
        && b[0].is_ascii_alphabetic()
        && b[1].is_ascii_alphabetic()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b.iter().all(|c| c.is_ascii_alphanumeric())
}

fn has_credential_prefix(token: &str) -> bool {
    const P: &[&str] = &[
        "sk-",
        "sk_live_",
        "rk_live_",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "ASIA",
        "AIza",
    ];
    P.iter().any(|p| token.starts_with(p)) && token.len() >= 16
}

// ---------------------------------------------------------------------------
// Scanners
// ---------------------------------------------------------------------------

/// Digit runs, tolerating single spaces and hyphens *inside* the run.
///
/// A run is split into **groups** at its separators, and candidate account numbers are
/// contiguous whole-group windows. The first cut tested the run as a single blob, which
/// meant one neighbouring number hid the card completely:
///
/// ```text
/// "Visa 4242 4242 4242 4242 12/29"          -> 21 digits, not 13..=19  -> nothing
/// "4242 4242 4242 4242 123"                 -> 19 digits, wrong Luhn   -> nothing
/// ```
///
/// and this repo's *own* macOS AX flatten joins sibling nodes with a space, so a
/// four-box card form arrives as `"4242 4242 4242 4242 12 29 123"` — the exact shape the
/// blob test cannot see. That is not an evasion an attacker has to find; it is the normal
/// rendering of a card form.
///
/// Windows are constrained rather than exhaustive, because a Luhn check passes on one in
/// ten random 16-digit strings: every group in a window must be 3–6 digits, and all
/// groups must be the same size except possibly the last. That admits 4-4-4-4,
/// 4-4-4-4-3, 4-6-5 and a single unseparated group, and rejects digit soup (`1-1-1-1…`)
/// outright. It also bounds the work: a window is at most 19 digits, so at most 7 groups
/// start at any group, and the pass stays linear.
fn scan_digit_runs(chars: &[char], lower_chars: &[char], out: &mut Vec<Entity>) {
    let mut i = 0usize;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // A run may not start mid-token: a digit preceded by an alphanumeric belongs to
        // something else (an order id, a hex blob), and treating it as a card prefix is
        // how a recogniser earns its reputation for noise.
        // `.` 不再算"延续一个更大的 token"。它是一个分隔符,不是标识符字符 ——
        // 把它当后者正是 `4242424242424242.` 和 `4242.4242.4242.4242` 全部漏掉的原因。
        if i > 0 && chars[i - 1].is_alphanumeric() {
            i += 1;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }
        let start = i;
        // Groups of digits, and the whole run's digits, in one pass.
        let mut groups: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut all_digits = String::new();
        let mut j = i;
        while j < chars.len() {
            if chars[j].is_ascii_digit() {
                current.push(chars[j]);
                all_digits.push(chars[j]);
                j += 1;
            } else if is_run_separator(chars[j])
                && j + 1 < chars.len()
                && chars[j + 1].is_ascii_digit()
            {
                groups.push(std::mem::take(&mut current));
                j += 1;
            } else {
                break;
            }
        }
        if !current.is_empty() {
            groups.push(current);
        }
        // Trailing alphanumeric means the run was part of a larger token.
        //
        // 句尾的 `.` **不是**一个更大 token 的一部分 —— 它是标点。以前它在这里,于是
        // `"Saved card 4242 4242 4242 4242."` 一个 entity 都不产出,而同一句话去掉句号
        // 就正确识别。逗号一直是可以的,句号不行 —— 这个差别没有任何理由。
        let clean_end = j >= chars.len() || !chars[j].is_alphanumeric();
        if clean_end {
            if let Some(pan) = card_window(&groups) {
                // 什么时候才算"无歧义地是一个卡号"。
                //
                // 三种情形之一即可:
                //   1. 整段未分隔(`4242424242424242`) —— 一个 13..19 位的连续数字串,
                //      通过 Luhn 和 IIN,没有别的解读;
                //   2. 分组数不超过 5 —— 真实卡号最多是 4-4-4-4 或 4-6-5 这类,五组是上限。
                //      再多就是一张数字表格,而表格里"某个起点恰好拼出合法 PAN"是必然事件
                //      (每窗口约 2.36%,20 组一行有 17 个窗口 → 32%);
                //   3. 附近有卡类关键字 —— 表格里出现 `card`/`卡号`/`visa` 时,那确实是卡号。
                //
                // 光数候选个数不够:20 组的一行里往往**恰好只有一个**窗口通过,于是
                // "候选 ≤ 1"仍然把它判成 verified(实测 24%)。分组数才是"这是不是一张表"
                // 的直接证据。
                //
                // 降级只影响 `verified`:finding 仍然产出、仍然进审计,只是不再触发审计改写
                // 和 `FLOW-CONF` 阻断 —— 也就是误报不再变成拦截。
                const CARD_WORDS: &[&str] = &[
                    "card",
                    "credit",
                    "debit",
                    "visa",
                    "mastercard",
                    "amex",
                    "pan",
                    "卡号",
                    "卡",
                    "银行卡",
                    "信用卡",
                    "カード",
                ];
                let unambiguous = groups.len() == 1
                    || groups.len() <= 5
                    || keyword_before(lower_chars, start, CARD_WORDS);
                out.push(Entity::new(
                    EntityKind::PaymentCard,
                    redact_tail(&pan, 4),
                    unambiguous,
                ));
            } else if is_phone_run(&all_digits, chars, start, lower_chars) {
                out.push(Entity::new(
                    EntityKind::PhoneNumber,
                    redact_tail(&all_digits, 3),
                    false,
                ));
            }
        }
        i = j.max(start + 1);
    }
}

/// The first card-shaped, Luhn-valid, IIN-plausible window of whole groups.
fn card_window(groups: &[String]) -> Option<String> {
    // An unseparated group *is* a candidate on its own — including one sitting next to
    // other numbers, which is the `"Row 3 4242424242424242"` case.
    for g in groups {
        if (13..=19).contains(&g.len()) && is_luhn(g) && plausible_pan(g) {
            return Some(g.clone());
        }
    }
    for a in 0..groups.len() {
        let mut window = String::new();
        let mut sizes: Vec<usize> = Vec::new();
        for g in groups[a..].iter() {
            if !(3..=6).contains(&g.len()) {
                break;
            }
            window.push_str(g);
            sizes.push(g.len());
            if window.len() > 19 {
                break;
            }
            if window.len() >= 13
                && card_group_shape(&sizes)
                && is_luhn(&window)
                && plausible_pan(&window)
            {
                return Some(window);
            }
        }
    }
    None
}

/// Whether a window's group sizes look like a printed card number.
///
/// Uniform groups with an optionally shorter last one covers 4-4-4-4 and 4-4-4-4-3
/// (19-digit UnionPay), and `[4, 6, 5]` is Amex, which prints in three unequal groups and
/// is the one real pattern the uniform rule cannot express.
///
/// The point of the constraint is arithmetic, not aesthetics: Luhn passes on one in ten
/// random 16-digit strings, so admitting arbitrary group combinations would turn a long
/// digit table into a stream of "verified" card numbers.
fn card_group_shape(sizes: &[usize]) -> bool {
    if sizes.is_empty() {
        return false;
    }
    if sizes == [4, 6, 5] {
        return true;
    }
    let first = sizes[0];
    let last = sizes.len() - 1;
    sizes
        .iter()
        .enumerate()
        .all(|(i, s)| *s == first || (i == last && *s < first))
}

/// A digit run is a telephone number when it is E.164-shaped (`+` then 8–15 digits) or
/// sits within the keyword window of a word that names a telephone.
///
/// Two routes to the same conclusion, deliberately: the `+` is self-describing and needs
/// no context, while a bare run needs the label — `Room 4021 for 3 nights` is not a phone
/// number and no amount of shape analysis will say so.
fn is_phone_run(digits: &str, chars: &[char], start: usize, lower_chars: &[char]) -> bool {
    let e164 = (8..=15).contains(&digits.len()) && start > 0 && chars[start - 1] == '+';
    // A *bare* run is capped at 13 digits, below E.164's 15. An Android "About phone"
    // screen shows a 15-digit IMEI within the keyword window of the word "phone", and a
    // serial number next to a telephone label is more likely a serial than a number
    // someone can dial.
    let labelled =
        (7..=13).contains(&digits.len()) && keyword_before(lower_chars, start, PHONE_KEYWORDS);
    e164 || labelled
}

/// Words that name a telephone. Matched at **word boundaries** — see `keyword_before`.
///
/// Without boundaries this list was a false-positive machine, and on exactly the corpus
/// this project cares about: `tel` matched inside **Hotel**, so
/// `"Grand Hotel Shanghai — confirmation number 4938201755"` was a phone number, and the
/// flagship task profile is `book_hotel`. `cell` matched inside `cancellation`, `dob`
/// inside `Adobe`. `联系` is dropped entirely: it is the generic Chinese "contact", it has
/// no word boundary to anchor to, and it appears in every page footer.
/// Bare `mobile` is absent deliberately: it is a word boundary away from **T-Mobile**,
/// so it matched a carrier's name on a plan screen. The label forms an app actually
/// prints are kept instead.
const PHONE_KEYWORDS: &[&str] = &[
    // Bare `phone` stays: `Phone:` is the commonest label on a screen, and at a word
    // boundary it cannot match inside `headphone` or `smartphone`. What made it dangerous
    // was the *length* it admitted, not the word — see the 13-digit cap above.
    "phone",
    "phone no",
    "telephone",
    "tel",
    "mobile number",
    "mobile no",
    "mobile phone",
    "cellphone",
    "whatsapp",
    "手机",
    "电话",
];
const PASSPORT_KEYWORDS: &[&str] = &["passport", "护照", "passport no", "passport number"];
const DOB_KEYWORDS: &[&str] = &[
    "dob",
    "date of birth",
    "birthday",
    "birth date",
    "出生",
    "生日",
];

/// Luhn (ISO/IEC 7812-1) check.
fn is_luhn(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for c in digits.chars().rev() {
        let mut d = c.to_digit(10).unwrap_or(0);
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Reject digit strings that pass Luhn but are not account numbers.
///
/// Luhn is a transcription check, not an identity: one in ten random 16-digit strings
/// passes it, and several *other* identifier families use it deliberately. The worst of
/// those is the **IMEI** — 15 digits, Luhn-valid, and an Android "About phone" screen
/// shows one next to the model name, so `"IMEI 356938035643809"` followed by any network
/// flow was a hard `FLOW-CONF` block. The first cut tested only "first digit in 3..6",
/// which admits every IMEI ever issued.
///
/// So the length and the issuer prefix are checked together, from the real IIN ranges.
/// That excludes IMEIs (15 digits starting `35`, where a 15-digit card must be Amex `34`
/// or `37`) and admits Mastercard's **2-series** (2221–2720), live since 2017 and rejected
/// outright by the previous rule — a coverage gap the doc had presented as a precision
/// feature.
fn plausible_pan(digits: &str) -> bool {
    let b = digits.as_bytes();
    let first = b[0];
    // A repeated single digit is a placeholder, a fixture or a table rule. `0000…` is
    // Luhn-valid.
    if b.iter().all(|x| *x == first) {
        return false;
    }
    let two: u32 = digits[..2].parse().unwrap_or(0);
    let four: u32 = digits[..4].parse().unwrap_or(0);
    match digits.len() {
        13 => first == b'4',
        // Diners Club: 300–305, 3095, 36, 38, 39.
        14 => {
            (300..=305).contains(&(digits[..3].parse::<u32>().unwrap_or(0)))
                || four == 3095
                || matches!(two, 36 | 38 | 39)
        }
        // Amex only. This is the line that excludes IMEIs.
        15 => matches!(two, 34 | 37),
        16 => {
            first == b'4'
                || (51..=55).contains(&two)
                || (2221..=2720).contains(&four)
                || four == 6011
                || matches!(two, 62 | 64 | 65)
                || (3528..=3589).contains(&four)
        }
        // No scheme issues 17- or 18-digit PANs.
        17 | 18 => false,
        19 => first == b'4' || matches!(two, 62 | 65),
        _ => false,
    }
}

/// IBAN: two letters, two check digits, then up to 30 alphanumerics; mod-97 == 1.
///
/// Candidates are *tokens*, found by walking word boundaries — the first cut glued
/// space-separated tokens into one run and then advanced past the whole run, so only the
/// first token of each run was ever tested. Since real screens put a word in front of the
/// number, the class almost never fired:
///
/// ```text
/// "GB82WEST12345698765432"            -> iban          (the unit test's input)
/// "IBAN GB82WEST12345698765432"       -> nothing        ← the realistic one
/// "Beneficiary IBAN DE89370400440532013000 confirmed" -> nothing
/// ```
///
/// It was not precise, it was unreachable. Now each alphanumeric token is tested on its
/// own, and separately the *grouped* form (`DE89 3704 0044 0532 0130 00`) is reassembled
/// from consecutive short tokens — printed IBANs come in fours, and joining only 2–4-char
/// groups keeps that from becoming "glue everything again".
fn scan_iban(chars: &[char], out: &mut Vec<Entity>) {
    let n = chars.len();
    // Tokenise once: [(start, text)] for every alphanumeric token.
    let mut tokens: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < n {
        if !chars[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let mut t = String::new();
        while i < n && chars[i].is_ascii_alphanumeric() {
            t.push(chars[i].to_ascii_uppercase());
            i += 1;
        }
        tokens.push(t);
    }
    let push = |token: &str, out: &mut Vec<Entity>| {
        if (15..=34).contains(&token.len()) && iban_checks(token) {
            out.push(Entity::new(
                EntityKind::Iban,
                format!("{}••{}", &token[..2], redact_tail(token, 4)),
                true,
            ));
        }
    };
    for t in &tokens {
        push(t, out);
    }
    // The grouped print form: consecutive tokens of 2–4 characters, joined.
    for a in 0..tokens.len() {
        if tokens[a].len() > 4 {
            continue;
        }
        let mut joined = String::new();
        for t in tokens[a..].iter() {
            if !(2..=4).contains(&t.len()) {
                break;
            }
            joined.push_str(t);
            if joined.len() > 34 {
                break;
            }
            if joined.len() >= 15 {
                push(&joined, out);
            }
        }
    }
}

fn iban_checks(token: &str) -> bool {
    let b = token.as_bytes();
    if !(b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic()) {
        return false;
    }
    if !(b[2].is_ascii_digit() && b[3].is_ascii_digit()) {
        return false;
    }
    // Move the country code and check digits to the end, expand letters to numbers,
    // then take mod 97 incrementally so no big integer is needed.
    let rearranged: String = token[4..].chars().chain(token[..4].chars()).collect();
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let v = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else if c.is_ascii_uppercase() {
            c as u32 - 'A' as u32 + 10
        } else {
            return false;
        };
        rem = if v > 9 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

/// PRC resident id: 17 digits + check character, ISO 7064:1983 MOD 11-2.
fn scan_national_id_cn(chars: &[char], out: &mut Vec<Entity>) {
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
    let n = chars.len();
    if n < 18 {
        return;
    }
    for i in 0..=(n - 18) {
        if i > 0 && chars[i - 1].is_alphanumeric() {
            continue;
        }
        if i + 18 < n && chars[i + 18].is_alphanumeric() {
            continue;
        }
        let body = &chars[i..i + 17];
        if !body.iter().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let tail = chars[i + 17].to_ascii_uppercase();
        if !(tail.is_ascii_digit() || tail == 'X') {
            continue;
        }
        let sum: u32 = body
            .iter()
            .enumerate()
            .map(|(k, c)| c.to_digit(10).unwrap_or(0) * W[k])
            .sum();
        if CHECK[(sum % 11) as usize] == tail {
            let id: String = chars[i..i + 18].iter().collect();
            out.push(Entity::new(
                EntityKind::NationalIdCn,
                // 不保留前 4 位。
                //
                // 那是省+市行政区划码 —— "在哪里登记的",一个准可识别属性;而末位是校验位,
                // 是其余 17 位的函数,保留它等于白送一个约束。原来的形状
                // `1101••…••2X` 同时泄漏了地区、性别位和一个校验约束。
                format!("••••••{}", &id[16..17]),
                true,
            ));
        }
    }
}

/// Email: `local@domain.tld`, with a plausible TLD length.
fn scan_emails(chars: &[char], out: &mut Vec<Entity>) {
    let n = chars.len();
    for i in 0..n {
        if chars[i] != '@' {
            continue;
        }
        // Local part, backwards.
        let mut ls = i;
        while ls > 0 && is_local_char(chars[ls - 1]) {
            ls -= 1;
        }
        if ls == i {
            continue;
        }
        // Domain, forwards, requiring at least one dot and a 2..24 letter TLD.
        let mut de = i + 1;
        while de < n && (chars[de].is_ascii_alphanumeric() || chars[de] == '-' || chars[de] == '.')
        {
            de += 1;
        }
        let domain: String = chars[i + 1..de].iter().collect();
        let domain = domain.trim_end_matches('.').to_string();
        let Some((_, tld)) = domain.rsplit_once('.') else {
            continue;
        };
        if tld.len() < 2 || tld.len() > 24 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let local: String = chars[ls..i].iter().collect();
        let head = local.chars().next().unwrap_or('•');
        out.push(Entity::new(
            EntityKind::Email,
            format!("{head}…@{domain}"),
            false,
        ));
    }
}

fn is_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

/// US SSN, `AAA-GG-SSSS` only.
///
/// No checksum exists, so the separators *are* the evidence: matching nine bare digits
/// would fire on every order number in every corpus.
fn scan_ssn(chars: &[char], out: &mut Vec<Entity>) {
    let n = chars.len();
    if n < 11 {
        return;
    }
    for i in 0..=(n - 11) {
        if i > 0 && chars[i - 1].is_alphanumeric() {
            continue;
        }
        if i + 11 < n && chars[i + 11].is_alphanumeric() {
            continue;
        }
        let w = &chars[i..i + 11];
        let shaped = w[..3].iter().all(|c| c.is_ascii_digit())
            && w[3] == '-'
            && w[4..6].iter().all(|c| c.is_ascii_digit())
            && w[6] == '-'
            && w[7..].iter().all(|c| c.is_ascii_digit());
        if !shaped {
            continue;
        }
        let area: String = w[..3].iter().collect();
        let group: String = w[4..6].iter().collect();
        let serial: String = w[7..].iter().collect();
        // Ranges the SSA never issues.
        if area == "000"
            || area == "666"
            || area.starts_with('9')
            || group == "00"
            || serial == "0000"
        {
            continue;
        }
        // **遮掉 serial,保留 area。**
        //
        // 以前反了:`•••-••-{serial}` 完整保留 4 位 serial,而遮掉的 area+group 恰恰是可
        // 枚举的那部分 —— SSA 曾发行的 area 约 800 个、group 89 个,合起来约 7.1 万候选,
        // 若知道出生州就只剩几百。也就是说遮蔽把**唯一不可枚举的四位**留在了日志里,遮掉的
        // 是攻击者本来就能穷举的部分。
        //
        // 现在保留 area(三位,用来判"这是一个 SSN"和大致来源),遮掉 serial。
        out.push(Entity::new(
            EntityKind::Ssn,
            format!("{area}-••-••••"),
            false,
        ));
    }
}

/// Credentials with a known issuer prefix, and PEM private key headers.
///
/// The prefix must start a **token**, and the tail must be alphanumeric or `_` — no
/// hyphens. Both constraints exist because plain substring search matched `sk-` and `AKIA`
/// *inside ordinary words*, and reported the result as `verified: true`, i.e. as
/// checksum-grade evidence:
///
/// ```text
/// risk-assessment-framework-v2-final          -> api_secret (verified)
/// desk-reservation-confirmation-page           -> api_secret (verified)
/// .../disk-usage-dashboard-widget.js           -> api_secret (verified)   ← `url` is scanned
/// hash 9AKIAB3F27DE1C4590AA71B8E6              -> api_secret (verified)
/// ```
///
/// Token anchoring kills the first three; the no-hyphen tail kills any that survive,
/// since real keys from these issuers are base62 with underscores and never kebab-case.
fn scan_api_secrets(text: &str, out: &mut Vec<Entity>) {
    const PREFIXES: &[(&str, usize)] = &[
        ("sk-", 20),
        ("sk_live_", 16),
        ("rk_live_", 16),
        ("ghp_", 36),
        ("gho_", 36),
        ("github_pat_", 22),
        ("xoxb-", 20),
        ("xoxp-", 20),
        ("AKIA", 16),
        ("ASIA", 16),
        ("AIza", 30),
    ];
    let bytes = text.as_bytes();
    for (prefix, min_tail) in PREFIXES {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(prefix) {
            let at = from + rel;
            // Token start: the character before must not continue an identifier.
            let anchored = at == 0
                || !(bytes[at - 1].is_ascii_alphanumeric()
                    || bytes[at - 1] == b'_'
                    || bytes[at - 1] == b'-');
            // `anchored` first, and count at most `min_tail + 1`.
            //
            // This used to compute `run` over the *entire* remaining tail before looking at
            // `anchored`. Every issuer prefix is made of characters that also satisfy the
            // run predicate (`[A-Za-z0-9_]`), so text built out of `AKIA`/`AIza`/`ASIA`
            // matched on every fourth byte and each match scanned to end of input: O(n²),
            // and all of it wasted, because `at > 0` makes `anchored` false and no entity is
            // produced. 400 KiB of `AKIA` took **31.6 seconds** inside `Engine::process`, on
            // the unconditional `ui_text` path with no rule match required — 2750× the
            // linear baseline. The module doc's claim that "every scanner is a single linear
            // pass, because a hand-rolled DoS is no better than a regex one" was false here.
            //
            // `run >= min_tail` needs no more than `min_tail + 1` characters to decide, so
            // the count is now bounded by a constant regardless of input length.
            let run = if anchored {
                text[at + prefix.len()..]
                    .chars()
                    .take(*min_tail + 1)
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .count()
            } else {
                0
            };
            if anchored && run >= *min_tail {
                out.push(Entity::new(
                    EntityKind::ApiSecret,
                    // No length: the length of a secret is information about the secret.
                    format!("{prefix}…"),
                    true,
                ));
            }
            from = at + prefix.len();
        }
    }
    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
        out.push(Entity::new(
            EntityKind::ApiSecret,
            "pem_private_key".into(),
            true,
        ));
    }
}

/// Classes with no checksum, recognised only next to a keyword that names them.
fn scan_keyword_gated(chars: &[char], lower_chars: &[char], out: &mut Vec<Entity>) {
    let n = chars.len();
    // Passport: 6–9 alphanumerics containing at least one digit, near a keyword.
    let mut i = 0usize;
    while i < n {
        let boundary = i == 0 || !chars[i - 1].is_alphanumeric();
        if !boundary || !chars[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < n && chars[j].is_ascii_alphanumeric() {
            j += 1;
        }
        let token: String = chars[i..j].iter().collect();
        if (6..=9).contains(&token.len())
            && token.chars().any(|c| c.is_ascii_digit())
            && token.chars().any(|c| c.is_ascii_alphabetic())
            && keyword_before(lower_chars, i, PASSPORT_KEYWORDS)
        {
            out.push(Entity::new(
                EntityKind::PassportNumber,
                redact_tail(&token, 2),
                false,
            ));
        }
        i = j.max(i + 1);
    }
    // Date of birth: a date shape near a birth keyword. The *date* is not the finding —
    // dates are everywhere in a booking flow — the pairing is.
    let mut i = 0usize;
    while i < n {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut j = i;
        let mut digits = 0;
        let mut seps = 0;
        while j < n {
            if chars[j].is_ascii_digit() {
                digits += 1;
                j += 1;
            } else if matches!(chars[j], '-' | '/' | '.' | '年' | '月')
                && j + 1 < n
                && chars[j + 1].is_ascii_digit()
            {
                seps += 1;
                j += 1;
            } else {
                break;
            }
        }
        if (6..=8).contains(&digits)
            && seps >= 2
            && keyword_before(lower_chars, start, DOB_KEYWORDS)
        {
            out.push(Entity::new(
                EntityKind::DateOfBirth,
                "date_near_birth_keyword".into(),
                false,
            ));
        }
        i = j.max(start + 1);
    }
}

/// Whether one of `keywords` occurs as a **word** within 40 characters before `at`.
///
/// Two properties, both learned the hard way.
///
/// *No allocation.* It takes the already-lowercased char slice. Building one per call
/// made the whole pass quadratic: 300 KB of identifier-shaped text spent 7.2 s in
/// `Engine::process`, in a module that refuses regex on the grounds that it must not hang
/// the device.
///
/// *Word boundaries.* An ASCII keyword must be flanked by non-alphanumerics, because
/// substring matching made this a false-positive generator on ordinary screens: `tel`
/// inside **Hotel**, `cell` inside **cancellation**, `dob` inside **Adobe**. Non-ASCII
/// keywords (`手机`, `电话`, `护照`) have no word boundary to anchor to and are matched as
/// substrings, which is correct for scripts that do not delimit words.
///
/// The 40-character window is short on purpose: a keyword two paragraphs away is
/// coincidence, not context. `a_distant_keyword_is_not_context` pins it.
fn keyword_before(lower_chars: &[char], at: usize, keywords: &[&str]) -> bool {
    const WINDOW: usize = 40;
    let end = at.min(lower_chars.len());
    let from = end.saturating_sub(WINDOW);
    let window = &lower_chars[from..end];
    keywords.iter().any(|k| contains_word(window, k))
}

/// Substring search over a char window, requiring word boundaries for ASCII needles.
fn contains_word(window: &[char], needle: &str) -> bool {
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() || n.len() > window.len() {
        return false;
    }
    let ascii = n.iter().all(|c| c.is_ascii());
    for i in 0..=(window.len() - n.len()) {
        if window[i..i + n.len()] != n[..] {
            continue;
        }
        if !ascii {
            return true;
        }
        let before_ok = i == 0 || !window[i - 1].is_alphanumeric();
        let after = i + n.len();
        let after_ok = after >= window.len() || !window[after].is_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Keep the last `keep` characters, mask the rest. Never returns the whole value.
/// 遮蔽,保留末 `keep` 个字符,前面用**固定数量**的圆点。
///
/// 圆点数量以前是"一个字符一个",于是遮蔽结果**精确暴露原值长度**。
/// `scan_api_secrets` 刻意避开了这一点(它的注释写着"一个 secret 的长度是关于这个 secret
/// 的信息"),而其他类没有跟上 —— 而长度对小空间的值是很强的约束:一个 15/16/19 位的
/// 数字串,长度本身就把发卡组织缩到几种。
///
/// 固定成四个,所以输出里不再有长度这一维信息。
fn redact_tail(value: &str, keep: usize) -> String {
    const DOTS: &str = "••••";
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= keep {
        return DOTS.to_string();
    }
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{DOTS}{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<&'static str> {
        recognise(text).iter().map(|e| e.kind.as_str()).collect()
    }

    #[test]
    fn a_luhn_valid_card_is_recognised_grouped_or_not() {
        for s in [
            "4242424242424242",
            "4242 4242 4242 4242",
            "4242-4242-4242-4242",
            "card: 5555555555554444 exp 12/29",
        ] {
            assert!(kinds(s).contains(&"payment_card"), "{s:?} → {:?}", kinds(s));
        }
    }

    /// The property that keeps this usable: a 16-digit number that is not a card does
    /// not become one. Without the Luhn check every order id on every receipt is a
    /// finding, and a recogniser that cries wolf gets switched off.
    #[test]
    fn a_digit_run_that_is_not_a_card_is_not_a_card() {
        for s in [
            "order 1234567890123456",
            "ref 4242424242424243", // one digit off Luhn
            "0000000000000000",     // Luhn-valid, not a PAN
            "4444444444444444444",  // repeated digit
            "id 9999999999999999",  // wrong leading digit
            "sku4242424242424242",  // mid-token
            "4242424242424242abc",  // mid-token the other way
        ] {
            assert!(
                !kinds(s).contains(&"payment_card"),
                "{s:?} → {:?}",
                kinds(s)
            );
        }
    }

    #[test]
    fn an_iban_is_verified_by_mod_97() {
        assert!(kinds("GB82 WEST 1234 5698 7654 32").contains(&"iban"));
        assert!(kinds("DE89370400440532013000").contains(&"iban"));
        // A single transposed character breaks the checksum.
        assert!(!kinds("GB82WEST12345698765433").contains(&"iban"));
    }

    #[test]
    fn a_prc_resident_id_is_verified_by_its_check_character() {
        // Constructed so the ISO 7064 check character is correct.
        let id = "11010519491231002X";
        assert!(kinds(id).contains(&"national_id_cn"), "{:?}", kinds(id));
        assert!(!kinds("110105194912310021").contains(&"national_id_cn"));
    }

    #[test]
    fn emails_and_secrets_are_recognised() {
        assert!(kinds("write to ming.lin@lbemobile.com today").contains(&"email"));
        assert!(!kinds("a@b").contains(&"email"), "no TLD");
        assert!(kinds("AKIAIOSFODNN7EXAMPLE").contains(&"api_secret"));
        assert!(kinds("-----BEGIN OPENSSH PRIVATE KEY-----").contains(&"api_secret"));
        assert!(!kinds("sk-short").contains(&"api_secret"));
    }

    #[test]
    fn ssn_needs_its_separators_and_a_valid_range() {
        assert!(kinds("SSN 078-05-1120").contains(&"ssn"));
        assert!(
            !kinds("078051120").contains(&"ssn"),
            "bare digits are order ids"
        );
        assert!(!kinds("000-05-1120").contains(&"ssn"));
        assert!(!kinds("666-05-1120").contains(&"ssn"));
    }

    /// Classes with no checksum are gated on a keyword naming them, so ordinary
    /// booking text does not produce findings.
    #[test]
    fn keyword_gated_classes_need_their_keyword() {
        assert!(kinds("Passport No: X1234567").contains(&"passport_number"));
        assert!(!kinds("Flight X1234567").contains(&"passport_number"));
        assert!(kinds("Date of birth 1990-05-02").contains(&"date_of_birth"));
        assert!(
            !kinds("Check-in 2026-05-02, check-out 2026-05-09").contains(&"date_of_birth"),
            "a booking date is not a birth date"
        );
        assert!(kinds("Phone: 555 0134 219").contains(&"phone_number"));
        assert!(kinds("+8613800138000").contains(&"phone_number"));
        assert!(
            !kinds("Room 4021 for 3 nights").contains(&"phone_number"),
            "{:?}",
            kinds("Room 4021 for 3 nights")
        );
    }

    /// The corpus's own benign screen text must stay clean, or the mechanism is a
    /// false-positive generator wearing a privacy control's clothes.
    #[test]
    fn ordinary_booking_and_shopping_text_is_clean() {
        for s in [
            "Booking summary",
            "Complete Purchase",
            "Order total ¥128.00, 2 items",
            "Check-in 2026-05-02  Check-out 2026-05-09  2 guests",
            "Seat 14A, gate B7, boarding 09:35",
            "确认支付 ¥128.00",
            "Reference 8842-1190-2201",
            "Tracking 1Z999AA10123456784",
        ] {
            assert!(recognise(s).is_empty(), "{s:?} → {:?}", recognise(s));
        }
    }

    #[test]
    fn a_finding_never_carries_the_value_it_found() {
        let pan = "4242424242424242";
        let found = recognise(&format!("card {pan}"));
        assert_eq!(found.len(), 1);
        assert!(!found[0].redacted.contains(pan));
        // 圆点数量**固定**,不再是"一个字符一个" —— 后者精确暴露原值长度,而长度对小空间
        // 的值是很强的约束。`scan_api_secrets` 一开始就避开了这一点("一个 secret 的长度是
        // 关于这个 secret 的信息"),其他类当时没有跟上。
        assert_eq!(found[0].redacted, "••••4242");
        let email = recognise("ming.lin@lbemobile.com");
        assert!(!email[0].redacted.contains("ming.lin"));
    }

    /// 遮蔽结果不能泄漏原值长度。
    ///
    /// 不同长度的同类值,遮蔽后的圆点数量必须一样 —— 否则一个 15 位和一个 19 位的卡号
    /// 在日志里可以直接区分,而卡号长度本身就把发卡组织缩到几种。
    #[test]
    fn 遮蔽不泄漏长度() {
        let a = recognise("card 4242424242424242"); // 16 位
        let b = recognise("card 378282246310005"); // 15 位 Amex
        let c = recognise("card 6011111111111117"); // 16 位 Discover
        for v in [&a, &b, &c] {
            assert_eq!(v.len(), 1, "夹具应当各识别出一个");
        }
        let dots = |e: &Entity| e.redacted.chars().filter(|c| *c == '•').count();
        assert_eq!(
            dots(&a[0]),
            dots(&b[0]),
            "16 位和 15 位的圆点数不同 —— 长度泄漏了"
        );
        assert_eq!(dots(&a[0]), dots(&c[0]));
    }

    /// SSN 的遮蔽要遮掉**不可枚举**的那一段。
    ///
    /// 以前是 `•••-••-{serial}`:完整保留 4 位 serial,遮掉的 area+group 恰恰是可枚举的
    /// 部分(约 7.1 万候选,知道出生州就只剩几百)。也就是遮蔽把唯一不可枚举的四位留在了
    /// 日志里。
    #[test]
    fn ssn_遮蔽掉不可枚举的那一段() {
        let e = recognise("SSN 078-05-1120");
        assert_eq!(e.len(), 1, "{e:?}");
        let r = &e[0].redacted;
        assert!(!r.contains("1120"), "serial 仍然完整留在遮蔽结果里:{r}");
        assert!(r.starts_with("078"), "area 应当保留以便判类:{r}");
    }

    /// 身份证的遮蔽不能保留行政区划码。
    #[test]
    fn 身份证遮蔽不保留地区码() {
        let e = recognise("身份证 11010519491231002X");
        assert_eq!(e.len(), 1, "{e:?}");
        let r = &e[0].redacted;
        assert!(!r.contains("1101"), "前 4 位行政区划码仍在:{r}");
        assert!(!r.contains("491231"), "出生日期仍在:{r}");
    }

    /// 一排 4 位数字不能变成一串"已核验"的卡号。
    ///
    /// `card_group_shape` 被文档描述成防住这件事,实测没有:随机 20×4 位表格里 32.2% 含
    /// 至少一个 verified payment_card,而 `verified: true` 会触发审计改写并把 taint 抬到
    /// High —— 于是误报变成 `FLOW-CONF` **阻断**,不只是噪声。
    #[test]
    fn 数字表格不产生已核验的卡号() {
        // 一个刻意构造的、Luhn 通过的 4 位分组表(20 组)。
        let mut rows = Vec::new();
        let mut st = 42u64;
        let mut flagged = 0usize;
        for _ in 0..400 {
            let mut groups = Vec::new();
            for _ in 0..20 {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                groups.push(format!("{:04}", (st >> 33) % 10000));
            }
            let line = format!("Row {}", groups.join(" "));
            if recognise(&line)
                .iter()
                .any(|e| matches!(e.kind, EntityKind::PaymentCard) && e.verified)
            {
                flagged += 1;
            }
            rows.push(line);
        }
        assert!(
            flagged * 100 / rows.len() < 5,
            "{}/{} 行数字表格产出了**已核验**的卡号({}%)",
            flagged,
            rows.len(),
            flagged * 100 / rows.len()
        );
    }

    /// 反面:一个真正的、未分隔的卡号仍然是 verified。
    #[test]
    fn 未分隔的真卡号仍然已核验() {
        for s in [
            "card 4242424242424242",
            "Saved card 4242 4242 4242 4242",
            "4000056655665556",
        ] {
            let e = recognise(s);
            assert!(
                e.iter()
                    .any(|x| matches!(x.kind, EntityKind::PaymentCard) && x.verified),
                "{s:?} 不再是 verified —— 降级降过头了:{e:?}"
            );
        }
    }

    #[test]
    fn repeats_collapse_to_one_finding() {
        let text = "4242 4242 4242 4242 / 4242424242424242 / 4242-4242-4242-4242";
        assert_eq!(recognise(text).len(), 1);
    }

    #[test]
    fn recognised_confidentiality_is_high_or_absent() {
        assert_eq!(
            recognised_confidentiality("card 4242424242424242"),
            Some(Confidentiality::High)
        );
        assert_eq!(recognised_confidentiality("Booking summary"), None);
        assert!(has_verified_entity("card 4242424242424242"));
        // Shape-and-keyword evidence is weaker, and says so.
        assert!(!has_verified_entity("Passport No: X1234567"));
    }

    /// Linear in the input, on text chosen to hit the keyword gate — which is where the
    /// quadratic behaviour actually was.
    ///
    /// The first version of this test used `"4".repeat(20_000)`, `"a@".repeat(10_000)` and
    /// `"1-".repeat(10_000)`, and passed while the real cost was 100–300× higher: every one
    /// of those inputs sidesteps `keyword_before` (a 20 000-digit run is not in `7..=15`;
    /// 1-char tokens are below the 6-char passport gate). It asserted a bound on inputs
    /// that could not reach the slow path — a test passing for a reason other than the
    /// property it claimed.
    ///
    /// These inputs *do* reach it: identifier-shaped tokens, digit runs next to telephone
    /// keywords, and passport-shaped tokens next to passport keywords. Before the fix
    /// (`keyword_before` allocating a `Vec<char>` of the whole text per call) 300 KB of the
    /// first case took 7.2 s in a release build inside `Engine::process`; it is ~30 ms now.
    /// The bound below is loose enough for a debug build and a shared CI box, and tight
    /// enough that quadratic behaviour cannot hide under it.
    #[test]
    fn adversarial_text_does_not_go_quadratic() {
        let cases = [
            "a1b2c3 ".repeat(20_000),         // identifier soup, every token a candidate
            "Contact 1234567 ".repeat(9_000), // digit runs beside a keyword
            "passport X1234567 ".repeat(8_000), // passport-shaped tokens beside a keyword
            "Tel 555 0134 ".repeat(10_000),
            "1-".repeat(60_000), // pathological group structure
            "GB82 WEST 1234 5698 7654 32 ".repeat(4_000), // the grouped IBAN path
            "4242 4242 4242 4242 12 29 ".repeat(4_000), // the grouped PAN path
        ];
        for text in &cases {
            let start = std::time::Instant::now();
            let _ = recognise(text);
            let elapsed = start.elapsed();
            assert!(
                elapsed.as_millis() < 3_000,
                "{} bytes took {elapsed:?}",
                text.len()
            );
        }
        // And the growth must be sub-quadratic: 4× the input must not be 16× the time.
        let small = "a1b2c3 ".repeat(10_000);
        let big = "a1b2c3 ".repeat(40_000);
        let t0 = std::time::Instant::now();
        let _ = recognise(&small);
        let small_ms = t0.elapsed().as_secs_f64();
        let t1 = std::time::Instant::now();
        let _ = recognise(&big);
        let big_ms = t1.elapsed().as_secs_f64();
        assert!(
            big_ms < small_ms * 10.0 + 0.05,
            "4x input took {big_ms:.3}s vs {small_ms:.3}s — superlinear"
        );
    }

    /// A keyword outside the window is not context. The window is the only thing
    /// standing between "a page that mentions telephones" and "every number on it is a
    /// telephone number".
    #[test]
    fn a_distant_keyword_is_not_context() {
        let near = "Phone: 5550134219";
        assert!(kinds(near).contains(&"phone_number"));
        let far = format!(
            "Phone support hours are listed below.{}5550134219",
            " ".repeat(60)
        );
        assert!(
            !kinds(&far).contains(&"phone_number"),
            "{:?}",
            recognise(&far)
        );
        let far_passport = format!("Passport office{}X1234567", "-".repeat(60));
        assert!(!kinds(&far_passport).contains(&"passport_number"));
    }

    /// Keywords match as words, not substrings. This is the difference between a control
    /// and a nuisance, and the corpus this project cares about is full of the counterexamples.
    #[test]
    fn keywords_match_words_not_substrings() {
        for (text, forbidden) in [
            (
                "Grand Hotel Shanghai — confirmation number 4938201755",
                "phone_number",
            ),
            ("Hotel Ibis Budget — reference 12345678", "phone_number"),
            ("Intel Core i7 processor, serial 1029384756", "phone_number"),
            (
                "Free cancellation until 2026-05-01. Order 87654321",
                "phone_number",
            ),
            ("T-Mobile plan — account 123456789", "phone_number"),
            (
                "Adobe Acrobat Reader — license expires 2026-05-02",
                "date_of_birth",
            ),
            (
                "About phone Model Pixel 8 Pro IMEI 356938035643809",
                "phone_number",
            ),
            (
                "About phone Model Pixel 8 Pro IMEI 356938035643809",
                "payment_card",
            ),
        ] {
            assert!(
                !kinds(text).contains(&forbidden),
                "{text:?} → {:?}",
                recognise(text)
            );
        }
    }

    /// An issuer prefix must start a token, and its tail must not be kebab-case.
    ///
    /// Plain substring search reported ordinary English compounds as **checksum-grade**
    /// secrets: `risk-assessment-framework-v2-final`, `desk-reservation-confirmation-page`,
    /// a `disk-usage-dashboard-widget.js` URL, `task-list-item-checkbox-wrapper`.
    #[test]
    fn an_issuer_prefix_must_start_a_token() {
        for clean in [
            "risk-assessment-framework-v2-final",
            "See the risk-management-guidelines-2026 page",
            "desk-reservation-confirmation-page",
            "https://cdn.example/assets/disk-usage-dashboard-widget.js",
            "class=\"task-list-item-checkbox-wrapper\"",
            "kiosk-mode-enabled-for-this-terminal",
            "hash 9AKIAB3F27DE1C4590AA71B8E6",
        ] {
            assert!(
                !kinds(clean).contains(&"api_secret"),
                "{clean:?} → {:?}",
                recognise(clean)
            );
        }
        // A real one still lands.
        assert!(kinds("token sk-abcdefghijklmnopqrstuvwxyz012345").contains(&"api_secret"));
        assert!(kinds("AKIAIOSFODNN7EXAMPLE").contains(&"api_secret"));
        // …and its length is not disclosed.
        let e = recognise("token sk-abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(e[0].redacted, "sk-…");
    }

    /// A PAN next to another number is still a PAN. This repo's own macOS AX flatten
    /// joins sibling nodes with a space, so a four-box card form arrives as one run:
    /// `"4242 4242 4242 4242 12 29 123"`. Testing the run as a single blob saw nothing.
    #[test]
    fn a_pan_is_found_beside_its_expiry_and_cvc() {
        for s in [
            "Visa 4242 4242 4242 4242 12/29",
            "4242 4242 4242 4242 123",
            "4242 4242 4242 4242 12 29 123",
            "Row 3 4242424242424242",
            "Saved card 4242 4242 4242 4242 128",
            "3782 822463 10005 exp 12/29",
        ] {
            assert!(
                kinds(s).contains(&"payment_card"),
                "{s:?} → {:?}",
                recognise(s)
            );
        }
    }

    /// An IBAN with a word in front of it is the realistic case, and it used to be the
    /// unrecognised one: candidates were glued into runs and only the first token of each
    /// run was tested.
    #[test]
    fn an_iban_is_found_when_something_precedes_it() {
        for s in [
            "IBAN GB82WEST12345698765432",
            "Beneficiary IBAN GB82WEST12345698765432",
            "Send to GB82WEST12345698765432",
            "IBAN DE89 3704 0044 0532 0130 00",
            "Payment to DE89370400440532013000 confirmed",
        ] {
            assert!(kinds(s).contains(&"iban"), "{s:?} → {:?}", recognise(s));
        }
    }

    /// Luhn is a transcription check, not an identity: other identifier families use it
    /// on purpose, and the IIN table is what separates them.
    #[test]
    fn luhn_valid_non_cards_are_rejected_and_live_ranges_accepted() {
        // IMEIs are Luhn-valid and start with 3.
        for imei in ["356938035643809", "490154203237518"] {
            assert!(
                !kinds(imei).contains(&"payment_card"),
                "{imei} → {:?}",
                recognise(imei)
            );
        }
        // Mastercard's 2-series has been live since 2017 and was rejected outright.
        for pan in ["2221000000000009", "2720000000000005"] {
            assert!(kinds(pan).contains(&"payment_card"), "{pan}");
        }
        // No scheme issues a 17- or 18-digit PAN.
        assert!(!kinds("42424242424242424").contains(&"payment_card"));
    }

    /// The audit log's copy must be masked too, or the finding's redaction is theatre.
    #[test]
    fn sensitive_runs_are_masked_for_the_audit_log() {
        let text = "Saved payment method: Visa 4242 4242 4242 4242, exp 12/29";
        let masked = mask_sensitive_runs(text);
        assert!(!masked.contains("4242 4242 4242"), "{masked}");
        assert!(
            masked.ends_with("4242, exp 12/29") || masked.contains("4242,"),
            "{masked}"
        );
        // Context survives, so the row is still worth keeping.
        assert!(masked.contains("Saved payment method: Visa"));
        // IBANs, credentials and PEM blocks.
        assert!(!mask_sensitive_runs("IBAN GB82WEST12345698765432").contains("WEST1234"));
        assert!(
            !mask_sensitive_runs("key sk-abcdefghijklmnopqrstuvwxyz012345").contains("abcdefgh")
        );
        assert_eq!(
            mask_sensitive_runs("-----BEGIN OPENSSH PRIVATE KEY-----\nabc"),
            "[redacted: pem_private_key]"
        );
        // Short numbers, dates and ordinary text are untouched.
        for keep in [
            "Order 12345678 on 2026-05-02",
            "Total ¥128.00 for 2 guests",
            "Seat 14A gate B7",
        ] {
            assert_eq!(mask_sensitive_runs(keep), keep);
        }
    }

    /// Realistic screen text from the kinds of app this guard watches. Every entry here
    /// is something a reviewer found the first version firing on, or an identifier family
    /// that shares a shape with one.
    #[test]
    fn realistic_app_text_produces_no_findings() {
        for s in [
            "Tracking 1Z999AA10123456784",
            "MAC 00:1B:44:11:3A:B7",
            "commit 9f2a4c1e8b7d6a5f4e3c2b1a0987654321fedcba",
            "ISBN 978-3-16-148410-0",
            "uuid 550e8400-e29b-41d4-a716-446655440000",
            "Order 1234567890123456",
            "ref 078051120",
            "Flight AA1234 gate B7 seat 14A",
            "总价 ¥1,280.00  订单 20260502-0001",
            "联系我们  订单号 20260502001",
            "Excellent 4.8/5 from 1029384 reviews",
            "Telegram desktop build 5123456",
            "promo code SAVE20NOW2026 valid until May",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ] {
            assert!(recognise(s).is_empty(), "{s:?} → {:?}", recognise(s));
        }
    }
}

#[cfg(test)]
mod b5_识别与遮蔽复核 {
    use super::*;

    /// 自然文本里的卡号必须被识别 —— 句尾句号、点/逗号/NBSP/零宽/软连字符分组、全角数字。
    ///
    /// 一次独立复核实测:下面这些里有八个是 `recognise` 返回 `[]`,后果是完整 PAN
    /// (a) 原样写进签名审计的 `event_json`,(b) 标签停在 Public,于是 `data_flow` 到
    /// 公网 sink 判 `Allow` 而不是 `FLOW-CONF/Block`。
    ///
    /// 最刺眼的一格:逗号结尾**可以**,句号结尾不行 —— 那个差别没有任何理由。
    #[test]
    fn 自然文本里的卡号必须被识别() {
        let kinds = |t: &str| -> Vec<String> {
            recognise(t)
                .iter()
                .map(|e| format!("{:?}", e.kind))
                .collect()
        };
        for t in [
            "Saved card 4242424242424242",
            "Saved card 4242424242424242.",
            "Saved card 4242 4242 4242 4242.",
            "Saved card 4242-4242-4242-4242.",
            "Card ending 4242424242424242. Thank you.",
            "Saved card 4242424242424242,",
            "card 4242.4242.4242.4242",
            "card 4242,4242,4242,4242",
            "card 4242\u{a0}4242\u{a0}4242\u{a0}4242",
            "card 4242\u{200b}4242\u{200b}4242\u{200b}4242",
            "card 4242\u{ad}4242\u{ad}4242\u{ad}4242",
        ] {
            assert!(
                kinds(t).iter().any(|k| k == "PaymentCard"),
                "{t:?} 没有识别出 payment_card —— 得到 {:?}",
                kinds(t)
            );
        }
        // 全角身份证号(显示路径一直能遮,审计路径以前原样留下)
        assert!(
            !recognise("身份证 １１０１０５１９４９１２３１００２Ｘ").is_empty(),
            "全角身份证号没有被识别"
        );
    }

    /// **识别到的一定要被遮到。**
    ///
    /// 这条是上面那一类缺陷的结构性防线。以前识别器和遮蔽器是两个独立实现,各自对
    /// "一段值从哪到哪"有一套猜法,于是出现"已核验但没被遮蔽":
    ///
    /// ```text
    /// THEATRE "IBAN GB82,WEST,1234,5698,7654,32"  verified=["iban"]  masked 完全未变
    /// THEATRE "IBAN GB82\u{a0}WEST\u{a0}…"        verified=["iban"]  masked 完全未变
    /// ```
    ///
    /// 审计行报告"已脱敏",实际存的是完整 IBAN。断言的是性质而不是某几个例子:任何被
    /// `has_verified_entity` 判为真的输入,`mask_sensitive_runs` 都必须真的改变它。
    #[test]
    fn 已核验的实体一定被遮蔽() {
        let cases = [
            "IBAN GB82 WEST 1234 5698 7654 32",
            "IBAN GB82,WEST,1234,5698,7654,32",
            "IBAN GB82/WEST/1234/5698/7654/32",
            "IBAN GB82.WEST.1234.5698.7654.32",
            "IBAN GB82\u{a0}WEST\u{a0}1234\u{a0}5698\u{a0}7654\u{a0}32",
            "IBAN GB82WEST12345698765432",
            "card 4242424242424242",
            "card 4242424242424242.",
            "card 4242.4242.4242.4242",
            "card 4242\u{200b}4242\u{200b}4242\u{200b}4242",
            "id 11010519491231002X",
            "DE89 3704 0044 0532 0130 00",
        ];
        for t in cases {
            if !has_verified_entity(t) {
                continue;
            }
            let masked = mask_sensitive_runs(t);
            assert_ne!(
                masked, t,
                "{t:?} 被判为含已核验实体,但审计遮蔽器一个字符都没改 —— 审计行会报告\"已脱敏\"而存下原值"
            );
        }
    }

    /// 遮蔽之后,原值的连续数字不能还在输出里 —— 零宽分隔的号码尤其。
    ///
    /// 零宽字符被剥掉之后,人和 grep 看到的是 `card 4242424242424242`;如果遮蔽只覆盖
    /// 可见字符之间的区间,就会留下一串可见数字。
    #[test]
    fn 遮蔽后不残留原始数字串() {
        for t in [
            "card 4242\u{200b}4242\u{200b}4242\u{200b}4242",
            "card 4242\u{ad}4242\u{ad}4242\u{ad}4242",
        ] {
            let masked = mask_sensitive_runs(t);
            let digits: String = masked.chars().filter(|c| c.is_ascii_digit()).collect();
            assert!(
                digits.len() <= 4,
                "{t:?} 遮蔽后仍残留 {} 位数字:{masked:?}",
                digits.len()
            );
        }
    }

    /// 反面:普通文本不能因为把 `.` 当分隔符而被误判。
    ///
    /// 版本号、IP、金额、时间戳都含 `.` 加数字。它们要么位数不够,要么过不了校验和 ——
    /// 但这必须被钉住,否则这次修复就是把误报换成了另一种误报。
    #[test]
    fn 把点当分隔符不产生误报() {
        for t in [
            "version 1.2.3.4",
            "192.168.1.100",
            "Total 4.99 USD",
            "ratio 0.3333333333333333",
            "timestamp 1786508766.171",
            "build 2026.08.26.1430",
            "coords 51.5074, -0.1278",
            "pi 3.14159265358979",
        ] {
            let e = recognise(t);
            assert!(
                e.iter().all(|x| !x.verified),
                "{t:?} 产生了已核验实体 {:?} —— 误报会让人把守卫关掉",
                e.iter()
                    .map(|x| format!("{:?}", x.kind))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// 归一化不能让识别变慢成二次。
    #[test]
    fn 归一化后仍然是线性的() {
        for kb in [64usize, 256] {
            let s = "4242.".repeat(kb * 205);
            let t = std::time::Instant::now();
            let _ = recognise(&s);
            let dt = t.elapsed();
            assert!(
                dt < std::time::Duration::from_secs(2),
                "{kb} KiB 耗时 {dt:?}"
            );
        }
    }
}
