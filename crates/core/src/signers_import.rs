//! 既存の allowed signers のファイル（`gpg.ssh.allowedSignersFile`）を読む。書式は ssh-keygen(1) の
//! 「ALLOWED SIGNERS」。記録に取り込める行と、取り込めない行（理由付き）に分ける。ファイルは変えない。

use crate::error::Result;
use crate::signers::{check_email, normalize_key, rfc3339, ssh_fingerprint};

/// 取り込める行。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedEntry {
    /// 1 始まり。
    pub line: u32,
    /// 最初の principal（人のメールアドレス）。
    pub email: String,
    /// 2 つめからの principal（記録には入れない。見せるだけ）。
    pub other_principals: Vec<String>,
    /// 種類と本体（説明は捨てる）。
    pub key: String,
    /// `SHA256:...`（ssh-keygen が求めたもの）。
    pub fingerprint: String,
    /// `valid-after`・`valid-before`（UTC、RFC 3339）。
    pub valid_after: Option<String>,
    pub valid_before: Option<String>,
}

/// 取り込めない行と、その理由。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedLine {
    pub line: u32,
    pub reason: SkipReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// 最初の principal がパターン（`*@example.com`）で、1 人に決まらない。
    Pattern,
    /// 最初の principal がメールアドレスとして使えない。
    Principal,
    /// `cert-authority` の行（扱わない）。
    CertAuthority,
    /// `namespaces` に git がない（git の検証には使われない）。
    NotForGit,
    /// 鍵として読めない、または署名に使えない種類。
    Key,
    /// 時刻（`valid-after`・`valid-before`）が読めない。
    Time,
    /// 書式が読めない（引用符が閉じていない、欄が足りないなど）。
    Syntax,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedSigners {
    pub entries: Vec<ParsedEntry>,
    pub skipped: Vec<SkippedLine>,
}

/// allowed signers のファイルの中身を読む。空行と `#` の行は飛ばす。フィンガープリントは ssh-keygen で求める
/// （ssh-keygen を起動できなければ誤り）。
pub fn parse_allowed_signers(text: &str) -> Result<ParsedSigners> {
    let mut out = ParsedSigners::default();
    for (i, raw) in text.lines().enumerate() {
        let line = (i + 1) as u32;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_line(trimmed) {
            Ok(mut entry) => {
                // 鍵の形は確かめてあるので、ssh-keygen が読めないのは鍵が壊れているとき
                match ssh_fingerprint(&entry.key) {
                    Ok(f) => {
                        entry.line = line;
                        entry.fingerprint = f;
                        out.entries.push(entry);
                    }
                    Err(crate::Error::Spawn { program, source }) => {
                        return Err(crate::Error::Spawn { program, source });
                    }
                    Err(_) => out.skipped.push(SkippedLine {
                        line,
                        reason: SkipReason::Key,
                    }),
                }
            }
            Err(reason) => out.skipped.push(SkippedLine { line, reason }),
        }
    }
    Ok(out)
}

fn parse_line(line: &str) -> std::result::Result<ParsedEntry, SkipReason> {
    let words = split_quoted(line, |c| c.is_ascii_whitespace()).ok_or(SkipReason::Syntax)?;
    if words.len() < 3 {
        return Err(SkipReason::Syntax);
    }
    // 2 つめが鍵の種類なら、指定（options）はない
    // 鍵の種類らしい語（`ssh-`・`ecdsa-`・`sk-` で始まる）も、読めない種類の鍵として扱う
    let looks_like_key = |w: &str| ["ssh-", "ecdsa-", "sk-"].iter().any(|p| w.starts_with(p));
    let (options, key_at) = if normalize_key(&format!("{} {}", words[1], words[2])).is_ok()
        || looks_like_key(&words[1])
    {
        ("", 1)
    } else {
        (words[1].as_str(), 2)
    };
    let (Some(kind), Some(body)) = (words.get(key_at), words.get(key_at + 1)) else {
        return Err(SkipReason::Syntax);
    };
    let key = normalize_key(&format!("{kind} {body}")).map_err(|_| SkipReason::Key)?;

    let mut valid_after = None;
    let mut valid_before = None;
    for option in split_quoted(options, |c| c == ',').ok_or(SkipReason::Syntax)? {
        if option.is_empty() {
            continue;
        }
        let (name, value) = match option.split_once('=') {
            Some((n, v)) => (n.to_ascii_lowercase(), Some(unquote(v))),
            None => (option.to_ascii_lowercase(), None),
        };
        match (name.as_str(), value) {
            ("cert-authority", _) => return Err(SkipReason::CertAuthority),
            ("namespaces", Some(v)) => {
                if !v.split(',').any(|n| matches!(n.trim(), "git" | "*")) {
                    return Err(SkipReason::NotForGit);
                }
            }
            ("valid-after", Some(v)) => valid_after = Some(parse_time(&v).ok_or(SkipReason::Time)?),
            ("valid-before", Some(v)) => {
                valid_before = Some(parse_time(&v).ok_or(SkipReason::Time)?)
            }
            // ほかの指定は、git の検証に関わらないので読み捨てる
            _ => {}
        }
    }

    let principals: Vec<String> = unquote(&words[0])
        .split(',')
        .map(|p| unquote(p.trim()))
        .filter(|p| !p.is_empty())
        .collect();
    let Some(first) = principals.first() else {
        return Err(SkipReason::Principal);
    };
    if first.contains(['*', '?']) {
        return Err(SkipReason::Pattern);
    }
    let email = check_email(first)
        .map_err(|_| SkipReason::Principal)?
        .to_owned();
    Ok(ParsedEntry {
        line: 0,
        email,
        other_principals: principals[1..].to_vec(),
        key,
        fingerprint: String::new(),
        valid_after,
        valid_before,
    })
}

/// `sep` で区切る。二重引用符の中は区切らない。引用符が閉じていなければ `None`。引用符は残す。
fn split_quoted(text: &str, sep: impl Fn(char) -> bool) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut started = false;
    for c in text.chars() {
        if c == '"' {
            quoted = !quoted;
            word.push(c);
            started = true;
        } else if !quoted && sep(c) {
            if started {
                out.push(std::mem::take(&mut word));
                started = false;
            } else if !c.is_ascii_whitespace() {
                // `a,,b` の空の欄
                out.push(String::new());
            }
        } else {
            word.push(c);
            started = true;
        }
    }
    if quoted {
        return None;
    }
    if started {
        out.push(word);
    }
    Some(out)
}

fn unquote(text: &str) -> String {
    text.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(text)
        .to_owned()
}

/// allowed signers の時刻（`YYYYMMDD`・`YYYYMMDDHHMM`・`YYYYMMDDHHMMSS`。末尾の `Z` は UTC、なければこの
/// コンピュータの時刻帯）を、UTC の RFC 3339 にする。
fn parse_time(text: &str) -> Option<String> {
    let (digits, utc) = match text.strip_suffix(['Z', 'z']) {
        Some(d) => (d, true),
        None => (text, false),
    };
    if !matches!(digits.len(), 8 | 12 | 14) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |r: std::ops::Range<usize>| digits.get(r).map_or(0, |s| s.parse::<i64>().unwrap_or(0));
    let (y, m, d) = (n(0..4), n(4..6), n(6..8));
    let (h, mi, s) = (n(8..10), n(10..12), n(12..14));
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let secs = if utc {
        days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + s
    } else {
        local_to_epoch(y, m, d, h, mi, s)?
    };
    u64::try_from(secs).ok().map(rfc3339)
}

/// 年月日を 1970-01-01 からの日数にする（Howard Hinnant の days_from_civil）。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// この時刻帯での時刻を UNIX 時刻にする（夏時間も含めて、C ランタイムの mktime に任せる）。
#[cfg(any(unix, windows))]
#[allow(unsafe_code)]
fn local_to_epoch(y: i64, m: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    // Windows の libc クレートは mktime を出していないので、UCRT の _mktime64 を宣言する
    #[cfg(windows)]
    unsafe extern "C" {
        #[link_name = "_mktime64"]
        fn mktime(tm: *mut libc::tm) -> i64;
    }
    #[cfg(unix)]
    use libc::mktime;
    // SAFETY: ゼロ埋めの tm に値を入れて mktime に渡すだけ。mktime は渡した tm だけを書き換える。
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = i32::try_from(y - 1900).ok()?;
        tm.tm_mon = (m - 1) as i32;
        tm.tm_mday = d as i32;
        tm.tm_hour = h as i32;
        tm.tm_min = mi as i32;
        tm.tm_sec = s as i32;
        tm.tm_isdst = -1;
        let t = mktime(&mut tm);
        #[allow(clippy::unnecessary_cast)]
        (t != -1).then_some(t as i64)
    }
}

/// ほかの OS では、時刻帯を確かめる道を作っていない（`Z` の付いた時刻だけを読む）。
#[cfg(not(any(unix, windows)))]
fn local_to_epoch(_: i64, _: i64, _: i64, _: i64, _: i64, _: i64) -> Option<i64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9vaIjchjlw1Meq/+2WNnjXNbJMV6vLwmwhn4OE4LZZ";

    #[test]
    fn reads_lines() {
        let e = parse_line(&format!("alice@example.com {KEY} laptop")).unwrap();
        assert_eq!(
            (e.email.as_str(), e.key.as_str()),
            ("alice@example.com", KEY)
        );
        assert!(e.other_principals.is_empty());

        let e = parse_line(&format!(
            "alice@example.com,\"alice@work.example\" namespaces=\"git,file\",valid-after=\"20260101\",valid-before=\"20261121043000Z\" {KEY}"
        ))
        .unwrap();
        assert_eq!(e.other_principals, ["alice@work.example"]);
        assert_eq!(e.valid_before.as_deref(), Some("2026-11-21T04:30:00Z"));
        assert!(e.valid_after.is_some());

        let skip = |l: String| parse_line(&l).unwrap_err();
        assert_eq!(skip(format!("*@example.com {KEY}")), SkipReason::Pattern);
        assert_eq!(skip(format!("alice {KEY}")), SkipReason::Principal);
        assert_eq!(
            skip(format!("ca@example.com cert-authority {KEY}")),
            SkipReason::CertAuthority
        );
        assert_eq!(
            skip(format!("a@example.com namespaces=\"file\" {KEY}")),
            SkipReason::NotForGit
        );
        assert_eq!(
            skip(format!("a@example.com valid-before=\"2026\" {KEY}")),
            SkipReason::Time
        );
        assert_eq!(
            skip("a@example.com ssh-dss AAAAB3NzaC1kc3MAAACBAP".into()),
            SkipReason::Key
        );
        assert_eq!(
            skip(format!("a@example.com namespaces=\"git {KEY}")),
            SkipReason::Syntax
        );
        assert_eq!(skip("a@example.com".into()), SkipReason::Syntax);
    }

    #[test]
    fn reads_times() {
        assert_eq!(
            parse_time("20261121Z").as_deref(),
            Some("2026-11-21T00:00:00Z")
        );
        assert_eq!(
            parse_time("202611210430Z").as_deref(),
            Some("2026-11-21T04:30:00Z")
        );
        assert_eq!(
            parse_time("20000229235959Z").as_deref(),
            Some("2000-02-29T23:59:59Z")
        );
        for bad in [
            "2026112",
            "20261321Z",
            "20261121250000Z",
            "2026-11-21",
            "20261121x",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
        // 時刻帯のない時刻は、この時刻帯で読む（どの時刻帯でも 1 日以内にずれる）
        let local = parse_time("20261121").unwrap();
        assert!(local.starts_with("2026-11-2"), "{local}");
        // この時刻帯の 0 時と UTC の 0 時の差は、時刻帯のずれ（±14 時間以内、15 分の倍数）
        let utc = days_from_civil(2026, 11, 21) * 86_400;
        let offset = utc - local_to_epoch(2026, 11, 21, 0, 0, 0).unwrap();
        assert!(offset.abs() <= 14 * 3600 && offset % 900 == 0, "{offset}");
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 11, 21) * 86_400, 1_795_219_200);
    }
}
