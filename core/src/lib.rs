//! cr-core — CleanReach engine.
//!
//! Contact list extraction, email verification (syntax, disposable/temp
//! detection, domain MX/SPF/DMARC health), deterministic lane
//! classification, phone validation, and a small file toolkit
//! (split / merge / extract). Pure `std` — no external crates, so the
//! same code builds unchanged for desktop, mobile, CLI and Docker.
//!
//! Honesty rules baked in:
//! - Syntax + MX + SPF is evidence, never "inbox proof".
//! - `unknown` is its own lane — unknown is never reported as invalid.
//! - Free mailbox providers (Gmail etc.) are "risky/unverifiable",
//!   never fake-"valid".
//! - Disposable/temp addresses are removed from clean output by default.
//! - No AI calls, ever: verdicts are deterministic and reproducible.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::io::Read;
use std::io::Write;
use std::net::UdpSocket;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Disposable domains (built-in starter list, user-extensible)
// ---------------------------------------------------------------------------

static BUILTIN_DISPOSABLE: &str = include_str!("disposable.txt");

#[derive(Debug, Clone, Default)]
pub struct DisposableSet {
    domains: HashSet<String>,
}

impl DisposableSet {
    pub fn builtin() -> Self {
        let mut s = Self::default();
        s.add_list(BUILTIN_DISPOSABLE);
        s
    }
    /// Add domains from list text (one per line, `#` comments allowed).
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            let d = line.trim().trim_start_matches("*.").to_ascii_lowercase();
            if !d.is_empty() && !d.starts_with('#') && d.contains('.') {
                self.domains.insert(d);
            }
        }
    }
    pub fn len(&self) -> usize {
        self.domains.len()
    }
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }
    pub fn contains(&self, domain: &str) -> bool {
        let d = domain.trim().to_ascii_lowercase();
        if self.domains.contains(&d) {
            return true;
        }
        // Parent-domain match: sub.mailinator.com is still disposable.
        let mut rest = d.as_str();
        while let Some(idx) = rest.find('.') {
            rest = &rest[idx + 1..];
            if self.domains.contains(rest) {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Email syntax + classification
// ---------------------------------------------------------------------------

/// Well-known free mailbox providers: real inboxes, but list owners
/// cannot verify ownership and signups are throwaway-friendly, so the
/// honest verdict is "risky", not "valid".
pub const FREE_PROVIDERS: &[&str] = &[
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com", "msn.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com",
    "yandex.ru", "zoho.com", "tutanota.com", "fastmail.com", "qq.com",
    "163.com", "126.com", "rediffmail.com", "wp.pl", "o2.pl", "free.fr",
    "orange.fr", "sfr.fr", "web.de", "t-online.de", "libero.it",
];

/// Local parts that mean a function mailbox, not a person.
pub const ROLE_LOCALS: &[&str] = &[
    "admin", "administrator", "support", "help", "helpdesk", "info",
    "contact", "sales", "marketing", "billing", "accounts", "accounting",
    "hr", "jobs", "careers", "recruitment", "noreply", "no-reply",
    "donotreply", "postmaster", "webmaster", "hostmaster", "abuse",
    "security", "privacy", "legal", "office", "team", "hello", "mail",
    "enquiries", "inquiries", "orders", "booking", "bookings",
    "reservations", "service", "services", "customerservice",
    "customer.service", "newsletter", "news", "press", "media", "it",
    "tech", "techsupport", "feedback", "complaints", "unsubscribe",
    "root", "system", "daemon", "mailer-daemon", "bounce", "bounces",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lane {
    CleanPersonal,
    CleanCorporate,
    Role,
    FreeProviderRisky,
    Disposable,
    Invalid,
    Unknown,
}

impl Lane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Lane::CleanPersonal => "clean-personal",
            Lane::CleanCorporate => "clean-corporate",
            Lane::Role => "role",
            Lane::FreeProviderRisky => "free-provider-risky",
            Lane::Disposable => "disposable",
            Lane::Invalid => "invalid",
            Lane::Unknown => "unknown",
        }
    }
    /// Lanes that belong in the default clean export. Disposable and
    /// invalid never do; unknown never does (it is not proven clean).
    pub fn in_clean_export(&self) -> bool {
        matches!(
            self,
            Lane::CleanPersonal | Lane::CleanCorporate | Lane::FreeProviderRisky
        )
    }
}

/// Strict-enough RFC 5322 subset: one `@`, sane local part, dotted
/// domain with a real TLD, no spaces, no consecutive dots.
pub fn email_syntax_ok(email: &str) -> bool {
    let e = email.trim();
    if e.is_empty() || e.len() > 254 || e.contains(char::is_whitespace) {
        return false;
    }
    let parts: Vec<&str> = e.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (local, domain) = (parts[0], parts[1]);
    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '!'))
    {
        return false;
    }
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    if domain.starts_with('.') || domain.starts_with('-') || domain.contains("..") {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    let tld = domain.rsplit('.').next().unwrap_or("");
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

pub fn email_domain(email: &str) -> Option<String> {
    let e = email.trim().to_ascii_lowercase();
    let (_, d) = e.split_once('@')?;
    if d.is_empty() {
        None
    } else {
        Some(d.to_string())
    }
}

pub fn is_role_local(email: &str) -> bool {
    let local = email
        .trim()
        .to_ascii_lowercase()
        .split('@')
        .next()
        .unwrap_or("")
        .to_string();
    // Exact match, or role word before a separator: support-uk, sales.team
    let head: String = local
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    ROLE_LOCALS.contains(&local.as_str()) || ROLE_LOCALS.contains(&head.as_str())
}

pub fn is_free_provider(domain: &str) -> bool {
    FREE_PROVIDERS.contains(&domain.trim().to_ascii_lowercase().as_str())
}

/// Optional domain-health facts that influence classification. `None`
/// fields mean "not checked" — never treated as failure.
#[derive(Debug, Clone, Default)]
pub struct DomainFacts {
    pub mx_checked: bool,
    pub has_mx: bool,
}

#[derive(Debug, Clone)]
pub struct EmailVerdict {
    pub email: String,
    pub syntax_ok: bool,
    pub disposable: bool,
    pub role: bool,
    pub free_provider: bool,
    pub lane: Lane,
    pub reason: String,
}

/// Classify one email address. Pure and deterministic.
pub fn classify_email(email: &str, disp: &DisposableSet, facts: &DomainFacts) -> EmailVerdict {
    let e = email.trim().to_ascii_lowercase();
    let syntax_ok = email_syntax_ok(&e);
    if !syntax_ok {
        return EmailVerdict {
            email: e,
            syntax_ok: false,
            disposable: false,
            role: false,
            free_provider: false,
            lane: Lane::Invalid,
            reason: "syntax: not a well-formed email address".to_string(),
        };
    }
    let domain = email_domain(&e).unwrap_or_default();
    let disposable = disp.contains(&domain);
    let role = is_role_local(&e);
    let free_provider = is_free_provider(&domain);
    let (lane, reason) = if disposable {
        (
            Lane::Disposable,
            "disposable/temp domain — removed from clean output by default".to_string(),
        )
    } else if facts.mx_checked && !facts.has_mx {
        (
            Lane::Unknown,
            "domain has no MX record — cannot confirm it receives mail (unknown, not invalid)"
                .to_string(),
        )
    } else if role {
        (
            Lane::Role,
            "role/function mailbox (support@, info@, …) — exported separately".to_string(),
        )
    } else if free_provider {
        (
            Lane::FreeProviderRisky,
            "free mailbox provider — real inbox possible, ownership unverifiable; risky, not fake-valid"
                .to_string(),
        )
    } else if facts.mx_checked && facts.has_mx {
        // A non-free domain with MX: corporate if it also carries SPF is
        // decided by the caller; here MX alone still separates from
        // personal webmail. Personal-vs-corporate is refined below.
        (Lane::CleanCorporate, "syntax ok, domain has MX".to_string())
    } else {
        (
            Lane::CleanPersonal,
            "syntax ok, not disposable/role/free-provider (MX not checked)".to_string(),
        )
    };
    EmailVerdict {
        email: e,
        syntax_ok,
        disposable,
        role,
        free_provider,
        lane,
        reason,
    }
}

// ---------------------------------------------------------------------------
// Phone validation — honest basics (parse/format/region, not carrier truth)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneStatus {
    Valid,
    Invalid,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PhoneVerdict {
    pub input: String,
    pub e164: Option<String>,
    pub country: Option<String>, // "GB" | "US" | "CA"
    pub national: Option<String>,
    pub status: PhoneStatus,
    pub line_type: String, // always "unknown" without a carrier lookup
    pub reason: String,
}

/// Validate + normalize a phone number for GB / US / CA.
/// Default region applies when the number has no country code.
pub fn validate_phone(input: &str, default_region: &str) -> PhoneVerdict {
    let raw = input.trim();
    let mut digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    let has_plus = raw.starts_with('+') || raw.starts_with("00");
    if raw.starts_with("00") {
        digits = digits[2.min(digits.len())..].to_string();
    }
    let mk = |e164: Option<String>, country: Option<String>, national: Option<String>,
              status: PhoneStatus, reason: &str| PhoneVerdict {
        input: raw.to_string(),
        e164,
        country,
        national,
        status,
        line_type: "unknown".to_string(),
        reason: reason.to_string(),
    };
    if digits.len() < 7 {
        return mk(None, None, None, PhoneStatus::Invalid, "too short to be a phone number");
    }
    // International forms first.
    if has_plus || digits.starts_with('1') && digits.len() == 11 || digits.starts_with("44") && digits.len() >= 12 {
        if let Some(v) = parse_nanp(&digits, raw) {
            return v;
        }
        if let Some(v) = parse_gb_intl(&digits, raw) {
            return v;
        }
        if has_plus {
            return mk(None, None, None, PhoneStatus::Unknown,
                      "international number outside GB/US/CA support — format not verified");
        }
    }
    // National forms by default region.
    match default_region.to_ascii_uppercase().as_str() {
        "GB" | "UK" => {
            if digits.starts_with('0') && digits.len() == 11 {
                let nat = &digits[1..];
                // GB mobile 07xxx, geographic 01/02, non-geo 03, freephone 0800/0808, premium 09 excluded
                if nat.starts_with('7') || nat.starts_with('1') || nat.starts_with('2') || nat.starts_with('3') || nat.starts_with("800") || nat.starts_with("808") {
                    return mk(Some(format!("+44{nat}")), Some("GB".into()),
                              Some(format!("0{nat}")), PhoneStatus::Valid,
                              "GB national format ok (line type unknown without carrier lookup)");
                }
                return mk(None, Some("GB".into()), None, PhoneStatus::Invalid,
                          "GB number with unallocated range prefix");
            }
            mk(None, Some("GB".into()), None, PhoneStatus::Invalid, "not a valid GB national number (expect 11 digits starting 0)")
        }
        "US" | "CA" => {
            if digits.len() == 10 {
                if let Some(v) = parse_nanp(&format!("1{digits}"), raw) {
                    return v;
                }
            }
            if digits.len() == 11 && digits.starts_with('1') {
                if let Some(v) = parse_nanp(&digits, raw) {
                    return v;
                }
            }
            mk(None, None, None, PhoneStatus::Invalid, "not a valid US/CA number (expect 10 digits + area code)")
        }
        _ => mk(None, None, None, PhoneStatus::Unknown,
                "unsupported default region — use GB, US or CA, or give the number in + international form"),
    }
}

fn parse_nanp(digits: &str, raw: &str) -> Option<PhoneVerdict> {
    if digits.len() != 11 || !digits.starts_with('1') {
        return None;
    }
    let area = &digits[1..4];
    let exchange = &digits[4..7];
    let area_n = area.parse::<u32>().ok()?;
    // NANP: area code and exchange cannot start with 0 or 1.
    if area.starts_with('0') || area.starts_with('1') || exchange.starts_with('0') || exchange.starts_with('1') {
        return Some(PhoneVerdict {
            input: raw.to_string(),
            e164: None,
            country: None,
            national: None,
            status: PhoneStatus::Invalid,
            line_type: "unknown".to_string(),
            reason: "NANP area/exchange code cannot start with 0 or 1".to_string(),
        });
    }
    if area_n < 200 {
        return None;
    }
    // A few unmistakably Canadian area codes; the rest default to US.
    const CA_AREAS: &[&str] = &["204", "226", "236", "249", "250", "263", "289", "306", "343",
        "354", "365", "367", "368", "382", "403", "416", "418", "421", "428", "431", "437",
        "438", "450", "468", "474", "506", "514", "519", "548", "579", "581", "584", "587",
        "600", "604", "613", "639", "647", "672", "683", "705", "709", "742", "753", "778",
        "780", "782", "807", "819", "825", "867", "873", "902", "905"];
    let country = if CA_AREAS.contains(&area) { "CA" } else { "US" };
    Some(PhoneVerdict {
        input: raw.to_string(),
        e164: Some(format!("+{digits}")),
        country: Some(country.to_string()),
        national: Some(format!("({}) {}-{}", area, exchange, &digits[7..])),
        status: PhoneStatus::Valid,
        line_type: "unknown".to_string(),
        reason: format!("NANP format ok ({country}) — line type unknown without carrier lookup"),
    })
}

fn parse_gb_intl(digits: &str, raw: &str) -> Option<PhoneVerdict> {
    if !digits.starts_with("44") || digits.len() != 12 {
        return None;
    }
    let nat = &digits[2..];
    if nat.starts_with('7') || nat.starts_with('1') || nat.starts_with('2') || nat.starts_with('3') {
        return Some(PhoneVerdict {
            input: raw.to_string(),
            e164: Some(format!("+44{nat}")),
            country: Some("GB".to_string()),
            national: Some(format!("0{nat}")),
            status: PhoneStatus::Valid,
            line_type: "unknown".to_string(),
            reason: "GB international format ok (line type unknown without carrier lookup)".to_string(),
        });
    }
    Some(PhoneVerdict {
        input: raw.to_string(),
        e164: None,
        country: Some("GB".to_string()),
        national: None,
        status: PhoneStatus::Invalid,
        line_type: "unknown".to_string(),
        reason: "GB number with unallocated range prefix".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Extraction from messy text + CSV-ish row parsing
// ---------------------------------------------------------------------------

/// Find email-shaped tokens anywhere in free text.
pub fn extract_emails(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cur = String::new();
    let is_tok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@');
    for c in text.chars().chain(std::iter::once(' ')) {
        if is_tok(c) {
            cur.push(c);
        } else {
            let t = cur.trim_matches(|x| matches!(x, '.' | '-' | '_'));
            if t.contains('@') && email_syntax_ok(t) {
                let low = t.to_ascii_lowercase();
                if seen.insert(low.clone()) {
                    out.push(low);
                }
            }
            cur.clear();
        }
    }
    out
}

/// Find phone-shaped candidates: runs of digits/spaces/()+/- with
/// 7–15 digits. Returns the raw candidates (validation is separate).
pub fn extract_phones(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for chunk in text.split(|c: char| !(c.is_ascii_digit() || matches!(c, '+' | '(' | ')' | '-' | ' ' | '.'))) {
        let t = chunk.trim();
        let ndig = t.chars().filter(|c| c.is_ascii_digit()).count();
        if (7..=15).contains(&ndig) && t.len() >= 7 {
            let key: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
            if seen.insert(key) {
                out.push(t.to_string());
            }
        }
    }
    out
}

/// One input contact row.
#[derive(Debug, Clone, Default)]
pub struct ContactRow {
    pub email: Option<String>,
    pub phone: Option<String>,
    pub consent: bool,
    pub source_line: usize,
}

/// Split one CSV line on commas/semicolons/tabs, honouring simple
/// double-quote wrapping.
pub fn split_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in line.chars() {
        match c {
            '"' => in_q = !in_q,
            ',' | ';' | '\t' if !in_q => {
                out.push(cur.trim().trim_matches('"').to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    out.push(cur.trim().trim_matches('"').to_string());
    out
}

/// Parse list text (CSV or free text) into contact rows. Columns are
/// detected by content: any field that parses as an email, a phone-like
/// field, and a consent column (`true/yes/1/opted-in`) — position-free,
/// header-aware when a header row names email/phone/consent columns.
pub fn parse_contacts(text: &str) -> Vec<ContactRow> {
    parse_contacts_counted(text).0
}

/// Like `parse_contacts`, but also returns how many duplicate rows were
/// dropped (by email, else by phone digits).
pub fn parse_contacts_counted(text: &str) -> (Vec<ContactRow>, usize) {
    let mut dropped_dupes = 0usize;
    let mut rows: Vec<ContactRow> = Vec::new();
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut seen_phones: HashSet<String> = HashSet::new();
    let mut header: Option<(Option<usize>, Option<usize>, Option<usize>)> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let fields = split_fields(t);
        let lower: Vec<String> = fields.iter().map(|f| f.to_ascii_lowercase()).collect();
        if i < 3 && lower.iter().any(|f| f == "email" || f == "e-mail" || f == "mail") {
            let find = |names: &[&str]| lower.iter().position(|f| names.contains(&f.as_str()));
            header = Some((
                find(&["email", "e-mail", "mail"]),
                find(&["phone", "mobile", "tel", "telephone", "number"]),
                find(&["consent", "opted_in", "opted-in", "optin", "opt_in", "subscribed"]),
            ));
            continue;
        }
        let mut row = ContactRow { source_line: i + 1, ..Default::default() };
        if let Some((ec, pc, cc)) = header {
            if let Some(idx) = ec {
                if let Some(v) = fields.get(idx) {
                    let v = v.trim();
                    if !v.is_empty() {
                        // Kept even when syntax is broken: the classifier
                        // must see it so it lands in the invalid lane
                        // instead of silently vanishing.
                        row.email = Some(v.to_ascii_lowercase());
                    }
                }
            }
            if let Some(idx) = pc {
                if let Some(v) = fields.get(idx) {
                    if !v.trim().is_empty() {
                        row.phone = Some(v.trim().to_string());
                    }
                }
            }
            if let Some(idx) = cc {
                if let Some(v) = fields.get(idx) {
                    row.consent = consent_value(v);
                }
            }
        }
        // Content-based detection fills anything the header missed.
        for f in &fields {
            let fv = f.trim();
            if row.email.is_none() && fv.contains('@') && !fv.contains(char::is_whitespace) {
                row.email = Some(fv.to_ascii_lowercase());
            } else if row.phone.is_none() {
                let ndig = fv.chars().filter(|c| c.is_ascii_digit()).count();
                if (7..=15).contains(&ndig) && fv.chars().all(|c| c.is_ascii_digit() || matches!(c, '+' | '(' | ')' | '-' | ' ' | '.')) {
                    row.phone = Some(fv.to_string());
                }
            }
            if !row.consent && consent_value(fv) && fields.len() > 1 {
                // bare true/yes only counts outside the email/phone fields
                if Some(fv.to_ascii_lowercase()) != row.email && Some(fv.to_string()) != row.phone {
                    row.consent = true;
                }
            }
        }
        if row.email.is_none() && row.phone.is_none() {
            // Free-text line: try extraction.
            let em = extract_emails(t);
            if let Some(e) = em.into_iter().next() {
                row.email = Some(e);
            } else if t.contains('@') {
                // Email-shaped but broken: keep the token so it is
                // reported in the invalid lane, not silently dropped.
                if let Some(tok) = t
                    .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '<' | '>' | '"' | '\''))
                    .find(|s| s.contains('@'))
                {
                    row.email = Some(tok.trim_matches(|c| matches!(c, '.' | ',' | ';')).to_ascii_lowercase());
                }
            }
            if row.phone.is_none() {
                if let Some(p) = extract_phones(t).into_iter().next() {
                    row.phone = Some(p);
                }
            }
        }
        if row.email.is_none() && row.phone.is_none() {
            continue;
        }
        // Dedupe: by email if present, else by phone digits.
        let dup = match &row.email {
            Some(e) => !seen_emails.insert(e.clone()),
            None => {
                let key: String = row.phone.clone().unwrap_or_default().chars().filter(|c| c.is_ascii_digit()).collect();
                !seen_phones.insert(key)
            }
        };
        if !dup {
            if let Some(p) = &row.phone {
                let key: String = p.chars().filter(|c| c.is_ascii_digit()).collect();
                seen_phones.insert(key);
            }
            rows.push(row);
        } else {
            dropped_dupes += 1;
        }
    }
    (rows, dropped_dupes)
}

pub fn consent_value(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "1" | "opted-in" | "opted_in" | "optin" | "subscribed" | "consent" | "y"
    )
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct CleanOptions {
    /// Check MX per domain (network). Off keeps everything offline-fast.
    pub check_mx: bool,
    pub default_region: String, // "GB" | "US" | "CA"
    pub resolver: String,       // DNS resolver host:port
}

impl CleanOptions {
    pub fn new() -> Self {
        CleanOptions {
            check_mx: false,
            default_region: "GB".to_string(),
            resolver: "8.8.8.8:53".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CleanedContact {
    pub email: Option<EmailVerdict>,
    pub phone: Option<PhoneVerdict>,
    pub consent: bool,
    pub source_line: usize,
}

#[derive(Debug, Default)]
pub struct CleanReport {
    pub contacts: Vec<CleanedContact>,
    pub total_rows: usize,
    pub duplicates_removed: usize,
    pub mx_checked_domains: usize,
}

pub fn clean_list(text: &str, disp: &DisposableSet, opts: &CleanOptions) -> CleanReport {
    let (rows, dupes) = parse_contacts_counted(text);
    let mut facts_cache: BTreeMap<String, DomainFacts> = BTreeMap::new();
    let mut mx_checked = 0usize;
    let mut out: Vec<CleanedContact> = Vec::new();
    for row in &rows {
        let email = row.email.as_ref().map(|e| {
            let domain = email_domain(e).unwrap_or_default();
            let facts = facts_cache.entry(domain.clone()).or_insert_with(|| {
                if opts.check_mx && !domain.is_empty() {
                    mx_checked += 1;
                    let h = domain_health(&domain, &opts.resolver, Duration::from_secs(5));
                    DomainFacts { mx_checked: true, has_mx: h.has_mx() }
                } else {
                    DomainFacts::default()
                }
            });
            classify_email(e, disp, facts)
        });
        let phone = row
            .phone
            .as_ref()
            .map(|p| validate_phone(p, &opts.default_region));
        out.push(CleanedContact {
            email,
            phone,
            consent: row.consent,
            source_line: row.source_line,
        });
    }
    CleanReport {
        duplicates_removed: dupes,
        total_rows: rows.len(),
        contacts: out,
        mx_checked_domains: mx_checked,
    }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn jstr(o: &Option<String>) -> String {
    match o {
        Some(s) => format!("\"{}\"", escape_json(s)),
        None => "null".to_string(),
    }
}

fn csv_cell(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

impl CleanReport {
    pub fn lane_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut m: BTreeMap<&'static str, usize> = BTreeMap::new();
        for c in &self.contacts {
            if let Some(e) = &c.email {
                *m.entry(e.lane.as_str()).or_insert(0) += 1;
            }
        }
        m
    }

    pub fn to_json(&self) -> String {
        let mut items = Vec::new();
        for c in &self.contacts {
            let email = match &c.email {
                Some(v) => format!(
                    "{{\"address\":\"{}\",\"lane\":\"{}\",\"syntax_ok\":{},\"disposable\":{},\"role\":{},\"free_provider\":{},\"reason\":\"{}\"}}",
                    escape_json(&v.email), v.lane.as_str(), v.syntax_ok, v.disposable, v.role,
                    v.free_provider, escape_json(&v.reason)
                ),
                None => "null".to_string(),
            };
            let phone = match &c.phone {
                Some(v) => format!(
                    "{{\"input\":\"{}\",\"e164\":{},\"country\":{},\"status\":\"{}\",\"line_type\":\"{}\",\"reason\":\"{}\"}}",
                    escape_json(&v.input), jstr(&v.e164), jstr(&v.country),
                    match v.status { PhoneStatus::Valid => "valid", PhoneStatus::Invalid => "invalid", PhoneStatus::Unknown => "unknown" },
                    escape_json(&v.line_type), escape_json(&v.reason)
                ),
                None => "null".to_string(),
            };
            items.push(format!(
                "{{\"line\":{},\"email\":{},\"phone\":{},\"consent\":{}}}",
                c.source_line, email, phone, c.consent
            ));
        }
        format!(
            "{{\"total_rows\":{},\"duplicates_removed\":{},\"mx_checked_domains\":{},\"lane_counts\":{},\"contacts\":[{}]}}",
            self.total_rows,
            self.duplicates_removed,
            self.mx_checked_domains,
            {
                let counts: Vec<String> = self.lane_counts().iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
                format!("{{{}}}", counts.join(","))
            },
            items.join(",")
        )
    }

    fn emails_in_lanes(&self, lanes: &[Lane]) -> Vec<String> {
        self.contacts
            .iter()
            .filter_map(|c| c.email.as_ref())
            .filter(|e| lanes.contains(&e.lane))
            .map(|e| e.email.clone())
            .collect()
    }

    /// clean.csv — the headline export. Disposable and invalid are
    /// NEVER in here (owner rule); unknown is not proven clean either.
    pub fn clean_csv(&self) -> String {
        let mut s = String::from("email,phone_e164,consent,lane\n");
        for c in &self.contacts {
            if let Some(e) = &c.email {
                if e.lane.in_clean_export() {
                    let ph = c.phone.as_ref().and_then(|p| p.e164.clone()).unwrap_or_default();
                    s.push_str(&format!(
                        "{},{},{},{}\n",
                        csv_cell(&e.email), csv_cell(&ph), c.consent, e.lane.as_str()
                    ));
                }
            }
        }
        s
    }

    pub fn lane_csv(&self, lane: Lane) -> String {
        let mut s = String::from("email,reason\n");
        for e in self.contacts.iter().filter_map(|c| c.email.as_ref()).filter(|e| e.lane == lane) {
            s.push_str(&format!("{},{}\n", csv_cell(&e.email), csv_cell(&e.reason)));
        }
        s
    }

    pub fn disposable_csv(&self) -> String {
        self.lane_csv(Lane::Disposable)
    }
    pub fn role_csv(&self) -> String {
        self.lane_csv(Lane::Role)
    }
    pub fn invalid_csv(&self) -> String {
        self.lane_csv(Lane::Invalid)
    }
    /// risky.csv = free-provider-risky + unknown (handle with care lanes).
    pub fn risky_csv(&self) -> String {
        let mut s = String::from("email,lane,reason\n");
        for e in self.contacts.iter().filter_map(|c| c.email.as_ref())
            .filter(|e| matches!(e.lane, Lane::FreeProviderRisky | Lane::Unknown)) {
            s.push_str(&format!("{},{},{}\n", csv_cell(&e.email), e.lane.as_str(), csv_cell(&e.reason)));
        }
        s
    }

    /// The ONLY export that feeds Opt-in Messaging: rows whose consent
    /// flag is explicitly true AND whose phone validated. Nothing else
    /// crosses that bridge — ever.
    pub fn consented_phones_csv(&self) -> String {
        let mut s = String::from("phone_e164,country,email\n");
        for c in &self.contacts {
            if c.consent {
                if let Some(p) = &c.phone {
                    if p.status == PhoneStatus::Valid {
                        if let Some(e164) = &p.e164 {
                            let email = c.email.as_ref().map(|e| e.email.clone()).unwrap_or_default();
                            s.push_str(&format!(
                                "{},{},{}\n",
                                csv_cell(e164),
                                csv_cell(p.country.as_deref().unwrap_or("")),
                                csv_cell(&email)
                            ));
                        }
                    }
                }
            }
        }
        s
    }

    pub fn summary_md(&self) -> String {
        let counts = self.lane_counts();
        let mut s = String::from("# CleanReach — cleaning summary\n\n");
        s.push_str(&format!("- Rows processed: **{}**\n", self.total_rows));
        s.push_str(&format!("- Duplicates removed: **{}**\n", self.duplicates_removed));
        s.push_str(&format!("- Domains MX-checked: **{}**\n\n", self.mx_checked_domains));
        s.push_str("## Email lanes\n\n");
        for (k, v) in &counts {
            s.push_str(&format!("- `{k}`: {v}\n"));
        }
        let consented = self.consented_phones_csv().lines().count().saturating_sub(1);
        s.push_str(&format!("\n## Phones\n\n- Consented, valid phones exported for Opt-in Messaging: **{consented}**\n"));
        s.push_str("\n> Honesty note: syntax/MX/SPF checks are evidence, not inbox proof. `unknown` means unverified — never treat it as invalid or as clean.\n");
        s
    }

    /// All exports as (filename, content) pairs.
    pub fn all_exports(&self) -> Vec<(&'static str, String)> {
        vec![
            ("results.json", self.to_json()),
            ("clean.csv", self.clean_csv()),
            ("disposable.csv", self.disposable_csv()),
            ("role.csv", self.role_csv()),
            ("invalid.csv", self.invalid_csv()),
            ("risky.csv", self.risky_csv()),
            ("consented_phones.csv", self.consented_phones_csv()),
            ("summary.md", self.summary_md()),
        ]
    }
}

// ---------------------------------------------------------------------------
// File toolkit — split / merge / extract on plain lists
// ---------------------------------------------------------------------------

/// Split lines into chunks of `size` (last chunk smaller). Deterministic.
pub fn split_lines(lines: &[String], size: usize) -> Vec<Vec<String>> {
    if size == 0 {
        return Vec::new();
    }
    lines.chunks(size).map(|c| c.to_vec()).collect()
}

/// Merge several list texts into one de-duplicated list (case-insensitive
/// for emails, first occurrence wins, original order preserved).
pub fn merge_lists(texts: &[&str]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for t in texts {
        for line in t.lines() {
            let v = line.trim();
            if v.is_empty() || v.starts_with('#') {
                continue;
            }
            let key = v.to_ascii_lowercase();
            if seen.insert(key) {
                out.push(v.to_string());
            }
        }
    }
    out
}

/// Extract every email from several texts, de-duplicated.
pub fn extract_from_texts(texts: &[&str]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for t in texts {
        for e in extract_emails(t) {
            if seen.insert(e.clone()) {
                out.push(e);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Domain health — raw DNS wire queries (A / MX / TXT), SPF + DMARC.
// Same wire approach as Network Diagnostics' nd-core: dependency-free,
// verifiable with canned packets where UDP is unavailable.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct DomainHealth {
    pub domain: String,
    pub a_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub spf: Option<String>,
    pub dmarc: Option<String>,
    pub resolver: String,
    pub error: Option<String>,
}

impl DomainHealth {
    pub fn has_mx(&self) -> bool {
        !self.mx_records.is_empty()
    }
    pub fn verdict(&self) -> String {
        let mut parts = Vec::new();
        parts.push(if self.a_records.is_empty() {
            "no A record"
        } else {
            "A ok"
        });
        parts.push(if self.has_mx() {
            "MX ok (can receive mail)"
        } else {
            "no MX (cannot receive mail)"
        });
        parts.push(if self.spf.is_some() { "SPF ok" } else { "SPF missing" });
        parts.push(if self.dmarc.is_some() { "DMARC ok" } else { "DMARC missing" });
        parts.join(" · ")
    }
    pub fn to_json(&self) -> String {
        let arr = |v: &[String]| -> String {
            let items: Vec<String> =
                v.iter().map(|s| format!("\"{}\"", escape_json(s))).collect();
            format!("[{}]", items.join(","))
        };
        format!(
            "{{\"domain\":\"{}\",\"a_records\":{},\"mx_records\":{},\"spf\":{},\"dmarc\":{},\"resolver\":\"{}\",\"error\":{}}}",
            escape_json(&self.domain),
            arr(&self.a_records),
            arr(&self.mx_records),
            jstr(&self.spf),
            jstr(&self.dmarc),
            escape_json(&self.resolver),
            jstr(&self.error),
        )
    }
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn decode_name(packet: &[u8], mut offset: usize) -> (String, usize) {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut next = offset;
    let mut guard = 0;
    loop {
        guard += 1;
        if offset >= packet.len() || guard > 64 {
            break;
        }
        let len = packet[offset];
        if len == 0 {
            if !jumped {
                next = offset + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                break;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | packet[offset + 1] as usize;
            if !jumped {
                next = offset + 2;
            }
            jumped = true;
            offset = ptr;
            continue;
        }
        let start = offset + 1;
        let end = start + len as usize;
        if end > packet.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&packet[start..end]).to_string());
        offset = end;
        if !jumped {
            next = offset;
        }
    }
    (labels.join("."), next)
}

pub enum RData {
    A(String),
    Mx(u16, String),
    Txt(String),
    Other,
}

fn dns_query(resolver: &str, name: &str, qtype: u16, timeout: Duration) -> Result<Vec<RData>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    socket.connect(resolver).map_err(|e| format!("dns connect: {e}"))?;
    let id: u16 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x1234))
        ^ (name.len() as u16).wrapping_mul(257);
    let mut packet: Vec<u8> = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&encode_name(name));
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    socket.send(&packet).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let n = socket.recv(&mut buf).map_err(|e| format!("dns recv: {e}"))?;
    parse_answers(&buf[..n])
}

pub fn parse_answers(buf: &[u8]) -> Result<Vec<RData>, String> {
    if buf.len() < 12 {
        return Err("dns: short response".to_string());
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qd {
        let (_, next) = decode_name(buf, offset);
        offset = next + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        if offset >= buf.len() {
            break;
        }
        let (_, next) = decode_name(buf, offset);
        offset = next;
        if offset + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        let rdata_start = offset + 10;
        if rdata_start + rdlen > buf.len() {
            break;
        }
        let rdata = &buf[rdata_start..rdata_start + rdlen];
        out.push(match rtype {
            1 if rdlen == 4 => RData::A(format!(
                "{}.{}.{}.{}",
                rdata[0], rdata[1], rdata[2], rdata[3]
            )),
            15 if rdlen > 2 => {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                let (exchange, _) = decode_name(buf, rdata_start + 2);
                RData::Mx(pref, exchange)
            }
            16 => {
                let mut s = String::new();
                let mut i = 0;
                while i < rdata.len() {
                    let l = rdata[i] as usize;
                    i += 1;
                    if i + l > rdata.len() {
                        break;
                    }
                    s.push_str(&String::from_utf8_lossy(&rdata[i..i + l]));
                    i += l;
                }
                RData::Txt(s)
            }
            _ => RData::Other,
        });
        offset = rdata_start + rdlen;
    }
    Ok(out)
}

pub fn domain_health(domain: &str, resolver: &str, timeout: Duration) -> DomainHealth {
    let domain = domain.trim().trim_start_matches('@').to_ascii_lowercase();
    let mut health = DomainHealth {
        domain: domain.clone(),
        resolver: resolver.to_string(),
        ..Default::default()
    };
    match dns_query(resolver, &domain, 1, timeout) {
        Ok(records) => {
            for r in records {
                if let RData::A(ip) = r {
                    health.a_records.push(ip);
                }
            }
        }
        Err(e) => health.error = Some(e),
    }
    if let Ok(records) = dns_query(resolver, &domain, 15, timeout) {
        let mut mx: Vec<(u16, String)> = records
            .into_iter()
            .filter_map(|r| match r {
                RData::Mx(p, host) => Some((p, host)),
                _ => None,
            })
            .collect();
        mx.sort();
        health.mx_records = mx.into_iter().map(|(_, h)| h).collect();
    }
    if let Ok(records) = dns_query(resolver, &domain, 16, timeout) {
        for r in records {
            if let RData::Txt(t) = r {
                if t.to_ascii_lowercase().starts_with("v=spf1") {
                    health.spf = Some(t);
                }
            }
        }
    }
    let dmarc_name = format!("_dmarc.{domain}");
    if let Ok(records) = dns_query(resolver, &dmarc_name, 16, timeout) {
        for r in records {
            if let RData::Txt(t) = r {
                if t.to_ascii_lowercase().starts_with("v=dmarc1") {
                    health.dmarc = Some(t);
                }
            }
        }
    }
    health
}

/// Optional conservative SMTP probe — OFF by default everywhere.
/// Opens one TCP connection, reads the banner, sends EHLO and a single
/// RCPT TO inside a MAIL FROM envelope, then QUITs politely. This is
/// intrusive by nature; callers must opt in explicitly and use it only
/// on lists they own or are authorized to verify.
pub fn smtp_probe(email: &str, timeout: Duration) -> (bool, String) {
    use std::net::TcpStream;
    let domain = match email_domain(email) {
        Some(d) => d,
        None => return (false, "no domain".to_string()),
    };
    let health = domain_health(&domain, "8.8.8.8:53", timeout);
    let mx = match health.mx_records.first() {
        Some(m) => m.clone(),
        None => return (false, "no MX host to probe".to_string()),
    };
    let addr = format!("{mx}:25");
    let mut stream = match TcpStream::connect_timeout(
        &match addr.parse() {
            Ok(a) => a,
            Err(_) => match std::net::ToSocketAddrs::to_socket_addrs(&addr) {
                Ok(mut it) => match it.next() {
                    Some(a) => a,
                    None => return (false, "MX host does not resolve".to_string()),
                },
                Err(e) => return (false, format!("resolve: {e}")),
            },
        },
        timeout,
    ) {
        Ok(s) => s,
        Err(e) => return (false, format!("connect: {e}")),
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut buf = [0u8; 512];
    let mut read_line = |s: &mut TcpStream| -> String {
        match s.read(&mut buf) {
            Ok(n) => String::from_utf8_lossy(&buf[..n]).to_string(),
            Err(_) => String::new(),
        }
    };
    let banner = read_line(&mut stream);
    if !banner.starts_with("220") {
        return (false, format!("unexpected banner: {}", banner.trim()));
    }
    let _ = stream.write_all(b"EHLO cleanreach.local\r\n");
    let _ = read_line(&mut stream);
    let _ = stream.write_all(b"MAIL FROM:<verify@cleanreach.local>\r\n");
    let _ = read_line(&mut stream);
    let rcpt = format!("RCPT TO:<{}>\r\n", email.trim());
    let _ = stream.write_all(rcpt.as_bytes());
    let resp = read_line(&mut stream);
    let _ = stream.write_all(b"QUIT\r\n");
    if resp.starts_with("250") {
        (true, "SMTP accepted RCPT TO (250) — strong evidence, still not a guarantee".to_string())
    } else if resp.starts_with("550") || resp.starts_with("551") || resp.starts_with("553") {
        (false, format!("SMTP rejected RCPT TO: {}", resp.trim()))
    } else {
        (false, format!("SMTP inconclusive (greylisting/blocking common): {}", resp.trim()))
    }
}

// Re-export marker so `use cr_core::*` in the binary gets Read/Write too.
#[doc(hidden)]
pub fn _force_link() {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn disp() -> DisposableSet {
        DisposableSet::builtin()
    }

    #[test]
    fn syntax_accepts_normal_addresses() {
        for e in [
            "jane.doe@example.com",
            "jane+news@sub.example.co.uk",
            "a_b-c%d@mail-server.example.org",
            "x@y.io",
        ] {
            assert!(email_syntax_ok(e), "should accept {e}");
        }
    }

    #[test]
    fn syntax_rejects_broken_addresses() {
        for e in [
            "", "not-an-email", "a@b", "a@@b.com", "@b.com", "a@.com",
            "a b@c.com", "a..b@c.com", ".a@c.com", "a@c..com", "a@-bad.com",
            "a@bad-.com", "a@b.c", "a@b.123",
        ] {
            assert!(!email_syntax_ok(e), "should reject {e}");
        }
    }

    #[test]
    fn disposable_domains_are_classified_disposable() {
        let d = disp();
        assert!(d.len() >= 200, "builtin list should be a few hundred, got {}", d.len());
        for domain in ["mailinator.com", "guerrillamail.com", "yopmail.com", "10minutemail.com"] {
            assert!(d.contains(domain), "missing {domain}");
        }
        assert!(d.contains("sub.mailinator.com"), "parent match failed");
        let v = classify_email("temp@mailinator.com", &d, &DomainFacts::default());
        assert_eq!(v.lane, Lane::Disposable);
        let v2 = classify_email("x@guerrillamail.com", &d, &DomainFacts::default());
        assert_eq!(v2.lane, Lane::Disposable);
    }

    #[test]
    fn lanes_separate_role_free_and_clean() {
        let d = disp();
        let role = classify_email("support@acme-widgets.com", &d, &DomainFacts::default());
        assert_eq!(role.lane, Lane::Role);
        let info = classify_email("info@acme-widgets.com", &d, &DomainFacts::default());
        assert_eq!(info.lane, Lane::Role);
        let free = classify_email("jane@gmail.com", &d, &DomainFacts::default());
        assert_eq!(free.lane, Lane::FreeProviderRisky);
        assert!(free.free_provider);
        let personal = classify_email("jane@jane-doe.co.uk", &d, &DomainFacts::default());
        assert_eq!(personal.lane, Lane::CleanPersonal);
        let corp_facts = DomainFacts { mx_checked: true, has_mx: true };
        let corp = classify_email("jane@acme-widgets.com", &d, &corp_facts);
        assert_eq!(corp.lane, Lane::CleanCorporate);
    }

    #[test]
    fn no_mx_is_unknown_never_invalid() {
        let d = disp();
        let facts = DomainFacts { mx_checked: true, has_mx: false };
        let v = classify_email("jane@acme-widgets.com", &d, &facts);
        assert_eq!(v.lane, Lane::Unknown);
        assert!(v.syntax_ok);
    }

    #[test]
    fn invalid_syntax_goes_invalid() {
        let d = disp();
        let v = classify_email("not-an-email", &d, &DomainFacts::default());
        assert_eq!(v.lane, Lane::Invalid);
    }

    #[test]
    fn phones_gb_formats() {
        let m = validate_phone("07700 900123", "GB");
        assert_eq!(m.status, PhoneStatus::Valid);
        assert_eq!(m.e164.as_deref(), Some("+447700900123"));
        assert_eq!(m.country.as_deref(), Some("GB"));
        let intl = validate_phone("+44 20 7946 0958", "GB");
        assert_eq!(intl.status, PhoneStatus::Valid);
        assert_eq!(intl.e164.as_deref(), Some("+442079460958"));
        let bad = validate_phone("0123", "GB");
        assert_eq!(bad.status, PhoneStatus::Invalid);
        let bad_range = validate_phone("09900 900123", "GB");
        assert_eq!(bad_range.status, PhoneStatus::Invalid);
    }

    #[test]
    fn phones_nanp_formats() {
        let us = validate_phone("(212) 555-0147", "US");
        assert_eq!(us.status, PhoneStatus::Valid);
        assert_eq!(us.e164.as_deref(), Some("+12125550147"));
        assert_eq!(us.country.as_deref(), Some("US"));
        let ca = validate_phone("+1 416 555 0147", "US");
        assert_eq!(ca.country.as_deref(), Some("CA"));
        let bad_area = validate_phone("123-456-7890", "US");
        assert_eq!(bad_area.status, PhoneStatus::Invalid);
        // Line type is always honestly unknown without a carrier lookup.
        assert_eq!(us.line_type, "unknown");
    }

    #[test]
    fn extraction_from_messy_text() {
        let text = "Contact Jane <jane@acme.com>, or bob_smith@mail.org!! Also junk: a@b, @@, x@y";
        let found = extract_emails(text);
        assert_eq!(found, vec!["jane@acme.com".to_string(), "bob_smith@mail.org".to_string()]);
        let phones = extract_phones("Call 07700 900123 or +1 212 555 0147 today");
        assert_eq!(phones.len(), 2);
    }

    #[test]
    fn dedupe_in_parse_and_merge() {
        let text = "jane@acme.com\nJANE@acme.com\nbob@acme.com\njane@acme.com\n";
        let rows = parse_contacts(text);
        assert_eq!(rows.len(), 2);
        let merged = merge_lists(&["a@x.com\nb@x.com", "B@x.com\nc@x.com"]);
        assert_eq!(merged, vec!["a@x.com".to_string(), "b@x.com".to_string(), "c@x.com".to_string()]);
    }

    #[test]
    fn split_lines_chunks_correctly() {
        let lines: Vec<String> = (0..10).map(|i| i.to_string()).collect();
        let chunks = split_lines(&lines, 4);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 4);
        assert_eq!(chunks[2].len(), 2);
        assert!(split_lines(&lines, 0).is_empty());
    }

    #[test]
    fn csv_header_and_consent_parsing() {
        let text = "email,phone,consent\njane@acme.com,07700 900123,true\nbob@acme.com,07700 900456,false\n";
        let rows = parse_contacts(text);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].consent);
        assert!(!rows[1].consent);
        assert_eq!(rows[0].phone.as_deref(), Some("07700 900123"));
    }

    #[test]
    fn pipeline_fixture_lanes_and_consented_export() {
        let fixture = "email,phone,consent\n\
            jane.doe@acme-widgets.com,,false\n\
            support@acme-widgets.com,,false\n\
            person@gmail.com,,false\n\
            temp@mailinator.com,,false\n\
            x@guerrillamail.com,,false\n\
            not-an-email,,false\n\
            jane.doe@acme-widgets.com,,false\n\
            uk.person@acme-widgets.com,07700 900123,true\n\
            us.person@acme-widgets.com,+1 212 555 0147,false\n";
        let report = clean_list(fixture, &disp(), &CleanOptions::new());
        let counts = report.lane_counts();
        assert_eq!(counts.get("clean-personal"), Some(&3)); // jane + uk.person + us.person
        assert_eq!(counts.get("role"), Some(&1));
        assert_eq!(counts.get("free-provider-risky"), Some(&1));
        assert_eq!(counts.get("disposable"), Some(&2));
        assert_eq!(counts.get("invalid"), Some(&1));
        // clean.csv excludes disposable + invalid by rule
        let clean = report.clean_csv();
        assert!(!clean.contains("mailinator"));
        assert!(!clean.contains("guerrillamail"));
        assert!(!clean.contains("not-an-email"));
        // Consented export: exactly one row (the consent=true UK row)
        let consented = report.consented_phones_csv();
        let rows: Vec<&str> = consented.lines().skip(1).filter(|l| !l.is_empty()).collect();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].starts_with("+447700900123"));
    }

    // -- DNS canned-packet tests (UDP may be blocked in sandboxes) --

    fn build_response(qname: &str, qtype: u16, answers: &[Vec<u8>]) -> Vec<u8> {
        let mut pkt: Vec<u8> = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes());
        pkt.extend_from_slice(&0x8180u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&encode_name(qname));
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        for a in answers {
            pkt.extend_from_slice(a);
        }
        pkt
    }

    fn answer(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut a = vec![0xC0, 0x0C];
        a.extend_from_slice(&rtype.to_be_bytes());
        a.extend_from_slice(&1u16.to_be_bytes());
        a.extend_from_slice(&300u32.to_be_bytes());
        a.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        a.extend_from_slice(rdata);
        a
    }

    #[test]
    fn dns_parses_a_and_mx_packets() {
        let pkt = build_response("test.example", 1, &[answer(1, &[93, 184, 216, 34])]);
        let recs = parse_answers(&pkt).unwrap();
        assert!(matches!(&recs[0], RData::A(ip) if ip == "93.184.216.34"));
        let mut rdata = 10u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&encode_name("mail.test.example"));
        let pkt = build_response("test.example", 15, &[answer(15, &rdata)]);
        let recs = parse_answers(&pkt).unwrap();
        assert!(matches!(&recs[0], RData::Mx(10, host) if host == "mail.test.example"));
    }

    #[test]
    fn dns_parses_txt_spf_packet() {
        let spf = b"v=spf1 include:_spf.test.example ~all";
        let mut rdata = vec![spf.len() as u8];
        rdata.extend_from_slice(spf);
        let pkt = build_response("test.example", 16, &[answer(16, &rdata)]);
        let recs = parse_answers(&pkt).unwrap();
        assert!(matches!(&recs[0], RData::Txt(t) if t.starts_with("v=spf1")));
    }
}
