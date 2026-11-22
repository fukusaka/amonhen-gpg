//! GitHub・GitLab から、利用者の SSH の署名用の鍵を取ってくる。HTTPS は curl に任せる（TLS をアプリの外に置く）。
//! 認証はせず、公開されている鍵だけを読む。

use std::process::Stdio;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::process::command;
use crate::signers::{SignerRecord, check_email, normalize_key, ssh_fingerprint};
use crate::staging::CodeHost;

/// 取ってきた鍵。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedKey {
    /// 種類と本体（説明は捨てる）。
    pub key: String,
    /// `SHA256:...`（ssh-keygen が求めたもの）。
    pub fingerprint: String,
    /// アカウントに登録したときの名前。
    pub title: Option<String>,
}

/// 取ってきた鍵と、記録との差。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerChanges {
    /// 記録にない鍵（退役させた鍵がまた出てきたときも）。
    pub new: Vec<FetchedKey>,
    /// このアカウントから取って受け入れた鍵のうち、もうアカウントにないもの（退役させていないもの）。
    pub gone: Vec<String>,
    /// アカウント以外（ファイル・手）から受け入れた鍵のうち、このアカウントにもあるもの（2 か所で一致した）。
    pub also: Vec<String>,
    /// アカウント以外（ファイル・手）から受け入れた鍵のうち、このアカウントにないもの（古い鍵か、別の場所の鍵）。
    pub absent: Vec<String>,
}

/// 応答の大きさの上限。鍵の一覧はずっと小さい。
const MAX_RESPONSE: &str = "1048576";

impl CodeHost {
    /// 利用者の SSH の鍵の一覧を返す API の URL。`api` は API の場所（テストではローカルのサーバー）。
    fn signing_keys_url(self, api: Option<&str>, user: &str) -> Result<String> {
        let user = self.check_user(user)?;
        let base = self.api(api);
        Ok(match self {
            CodeHost::GitHub => format!("{base}/users/{user}/ssh_signing_keys?per_page=100"),
            CodeHost::GitLab => format!("{base}/users/{user}/keys?per_page=100"),
        })
    }
}

/// `host` の利用者 `user` の SSH の署名用の鍵を取ってくる。GitHub は署名用の鍵だけを返す。GitLab は使い道
/// （`usage_type`）が署名を含む鍵だけを使う。OpenSSH が署名に使えない種類の鍵は飛ばす。利用者がいなければ
/// `Error::NotFound`。
pub fn fetch_signing_keys(host: CodeHost, user: &str) -> Result<Vec<FetchedKey>> {
    fetch(host, None, user)
}

/// テスト用。`api` に API の場所（`http://127.0.0.1:<port>` だけ）を指す。
#[doc(hidden)]
pub fn fetch_signing_keys_from(api: &str, host: CodeHost, user: &str) -> Result<Vec<FetchedKey>> {
    if !api.starts_with("http://127.0.0.1:") {
        return Err(Error::InvalidArgument {
            name: "api",
            message: "only a local test server".into(),
        });
    }
    fetch(host, Some(api), user)
}

fn fetch(host: CodeHost, api: Option<&str>, user: &str) -> Result<Vec<FetchedKey>> {
    let url = host.signing_keys_url(api, user)?;
    parse(host, &get(&url, api.is_some())?)
}

/// GET して本体を返す。404 は `Error::NotFound`、ほかの 200 でない応答は `Error::Tool`。
fn get(url: &str, local: bool) -> Result<Vec<u8>> {
    let (status, body) = curl(url, local)?;
    match status {
        200 => Ok(body),
        404 => Err(Error::NotFound),
        _ => Err(Error::Tool {
            program: "curl".into(),
            code: None,
            stderr: format!(
                "HTTP {status} from {url}: {}",
                String::from_utf8_lossy(&body)
                    .chars()
                    .take(300)
                    .collect::<String>()
            ),
        }),
    }
}

fn json<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| Error::Parse {
        line: e.line(),
        message: e.to_string(),
    })
}

/// 主体（allowed signers でその鍵の持ち主として書くメールアドレス）の候補の出どころ。GitHub・GitLab は、SSH の鍵が
/// どのメールアドレスのものかを示さないので、どれも推定。上ほど確か。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateSource {
    /// アカウントに登録した GPG 鍵のメールアドレスのうち、サービスが持ち主のものと確かめたもの（GitHub）。
    Verified,
    /// アカウントが公開している GPG 鍵の UID のメールアドレス（FE が一時保管の鍵から足す）。
    UserId,
    /// プロフィールで公開しているメールアドレス。
    Profile,
    /// サービスがアカウントごとに割り当てる、届かないアドレス。いつでも作れる。
    NoReply,
}

/// 主体の候補。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalCandidate {
    pub email: String,
    pub source: CandidateSource,
}

/// アカウントについて公開されていること。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountProfile {
    /// サービスでの表記（大文字・小文字は入力と違うことがある）。
    pub user: String,
    /// 主体の候補。確かなものから、同じアドレスは 1 度だけ。
    pub candidates: Vec<PrincipalCandidate>,
}

impl CodeHost {
    fn api(self, api: Option<&str>) -> &str {
        api.unwrap_or(match self {
            CodeHost::GitHub => "https://api.github.com",
            CodeHost::GitLab => "https://gitlab.com/api/v4",
        })
    }
}

/// `host` の利用者 `user` のプロフィールと、主体の候補を取ってくる（GitHub は 2 回、GitLab は 1 回 GET する）。
/// 利用者がいなければ `Error::NotFound`。
pub fn fetch_account_profile(host: CodeHost, user: &str) -> Result<AccountProfile> {
    fetch_profile(host, None, user)
}

/// テスト用。`api` に API の場所（`http://127.0.0.1:<port>` だけ）を指す。
#[doc(hidden)]
pub fn fetch_account_profile_from(api: &str, host: CodeHost, user: &str) -> Result<AccountProfile> {
    if !api.starts_with("http://127.0.0.1:") {
        return Err(Error::InvalidArgument {
            name: "api",
            message: "only a local test server".into(),
        });
    }
    fetch_profile(host, Some(api), user)
}

fn fetch_profile(host: CodeHost, api: Option<&str>, user: &str) -> Result<AccountProfile> {
    let user = host.check_user(user)?;
    let local = api.is_some();
    let base = host.api(api);
    match host {
        CodeHost::GitHub => {
            let profile = get(&format!("{base}/users/{user}"), local)?;
            let gpg_keys = get(&format!("{base}/users/{user}/gpg_keys?per_page=100"), local)?;
            github_profile(&profile, &gpg_keys)
        }
        CodeHost::GitLab => gitlab_profile(&get(&format!("{base}/users?username={user}"), local)?),
    }
}

#[derive(Deserialize)]
struct GitHubUser {
    login: String,
    id: u64,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GitHubGpgKey {
    #[serde(default)]
    emails: Vec<GitHubGpgEmail>,
}

#[derive(Deserialize)]
struct GitHubGpgEmail {
    email: String,
    #[serde(default)]
    verified: bool,
}

#[derive(Deserialize)]
struct GitLabUser {
    id: u64,
    username: String,
    public_email: Option<String>,
}

fn github_profile(profile: &[u8], gpg_keys: &[u8]) -> Result<AccountProfile> {
    let user: GitHubUser = json(profile)?;
    let keys: Vec<GitHubGpgKey> = json(gpg_keys)?;
    let mut found = Vec::new();
    for e in keys.iter().flat_map(|k| &k.emails).filter(|e| e.verified) {
        found.push((e.email.clone(), CandidateSource::Verified));
    }
    if let Some(email) = user.email {
        found.push((email, CandidateSource::Profile));
    }
    found.push((
        format!("{}+{}@users.noreply.github.com", user.id, user.login),
        CandidateSource::NoReply,
    ));
    Ok(AccountProfile {
        candidates: candidates(found),
        user: user.login,
    })
}

fn gitlab_profile(users: &[u8]) -> Result<AccountProfile> {
    let users: Vec<GitLabUser> = json(users)?;
    let user = users.into_iter().next().ok_or(Error::NotFound)?;
    let mut found = Vec::new();
    if let Some(email) = user.public_email {
        found.push((email, CandidateSource::Profile));
    }
    found.push((
        format!("{}-{}@users.noreply.gitlab.com", user.id, user.username),
        CandidateSource::NoReply,
    ));
    Ok(AccountProfile {
        candidates: candidates(found),
        user: user.username,
    })
}

/// 主体にできないもの（空・空白など）を除き、同じアドレス（大文字・小文字は区別しない）は先のものだけを残す。
fn candidates(found: Vec<(String, CandidateSource)>) -> Vec<PrincipalCandidate> {
    let mut out: Vec<PrincipalCandidate> = Vec::new();
    for (email, source) in found {
        let email = email.trim();
        if check_email(email).is_err() || out.iter().any(|c| c.email.eq_ignore_ascii_case(email)) {
            continue;
        }
        out.push(PrincipalCandidate {
            email: email.to_owned(),
            source,
        });
    }
    out
}

/// 鍵の一覧の 1 つ。GitHub と GitLab で共通の欄だけ。
#[derive(Deserialize)]
struct ApiKey {
    key: String,
    title: Option<String>,
    /// GitLab だけ（15.7 から）。それより前の GitLab の鍵は、認証にも署名にも使える。
    usage_type: Option<String>,
}

fn parse(host: CodeHost, body: &[u8]) -> Result<Vec<FetchedKey>> {
    let keys: Vec<ApiKey> = json(body)?;
    let mut out: Vec<FetchedKey> = Vec::new();
    for k in keys {
        let signing = match host {
            CodeHost::GitHub => true,
            CodeHost::GitLab => matches!(
                k.usage_type.as_deref(),
                None | Some("signing" | "auth_and_signing")
            ),
        };
        let Ok(key) = normalize_key(&k.key) else {
            continue;
        };
        if !signing {
            continue;
        }
        let fingerprint = ssh_fingerprint(&key)?;
        if out.iter().all(|o| o.fingerprint != fingerprint) {
            out.push(FetchedKey {
                key,
                fingerprint,
                title: k.title.filter(|t| !t.is_empty()),
            });
        }
    }
    Ok(out)
}

/// curl で GET し、HTTP の状態と本体を返す。リダイレクトはたどらず、`local` でなければ HTTPS だけ。
fn curl(url: &str, local: bool) -> Result<(u16, Vec<u8>)> {
    let program = format!("curl{}", std::env::consts::EXE_SUFFIX);
    let spawn_error = |source| Error::Spawn {
        program: program.clone(),
        source,
    };
    let out = command(&program)
        .args([
            "--silent",
            "--show-error",
            "--proto",
            if local { "=http" } else { "=https" },
            "--max-time",
            "30",
            "--max-filesize",
            MAX_RESPONSE,
            "--header",
            "Accept: application/json",
            "--user-agent",
            "amonhen-gpg",
            "--write-out",
            "\n%{http_code}",
            "--",
            url,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(spawn_error)?;
    let tool_error = || Error::Tool {
        program: program.clone(),
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    if !out.status.success() {
        return Err(tool_error());
    }
    let split = out
        .stdout
        .iter()
        .rposition(|&b| b == b'\n')
        .ok_or_else(tool_error)?;
    let status = std::str::from_utf8(&out.stdout[split + 1..])
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(tool_error)?;
    Ok((status, out.stdout[..split].to_vec()))
}

impl SignerRecord {
    /// `email` の人について、アカウント（`host`・`user`）から取ってきた鍵と記録との差。
    pub fn changes(
        &self,
        email: &str,
        host: CodeHost,
        user: &str,
        fetched: &[FetchedKey],
    ) -> Result<SignerChanges> {
        let person = self
            .people
            .iter()
            .find(|p| p.email == email)
            .ok_or(Error::NotFound)?;
        let new = fetched
            .iter()
            .filter(|f| {
                !person
                    .keys
                    .iter()
                    .any(|k| k.fingerprint == f.fingerprint && k.valid_before.is_none())
            })
            .cloned()
            .collect();
        let gone = person
            .keys
            .iter()
            .filter(|k| k.valid_before.is_none())
            .filter(|k| {
                k.source
                    .as_ref()
                    .is_some_and(|s| s.host == host && s.user == user)
            })
            .filter(|k| fetched.iter().all(|f| f.fingerprint != k.fingerprint))
            .map(|k| k.fingerprint.clone())
            .collect();
        // アカウントから取っていない鍵（入手元のないもの）を、このアカウントと比べる
        let elsewhere = || {
            person
                .keys
                .iter()
                .filter(|k| k.valid_before.is_none() && k.source.is_none())
        };
        let on_account =
            |k: &&crate::signers::SignerKey| fetched.iter().any(|f| f.fingerprint == k.fingerprint);
        let also = elsewhere()
            .filter(on_account)
            .map(|k| k.fingerprint.clone())
            .collect();
        let absent = elsewhere()
            .filter(|k| !on_account(k))
            .map(|k| k.fingerprint.clone())
            .collect();
        Ok(SignerChanges {
            new,
            gone,
            also,
            absent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_urls() {
        assert_eq!(
            CodeHost::GitHub.signing_keys_url(None, "alice").unwrap(),
            "https://api.github.com/users/alice/ssh_signing_keys?per_page=100"
        );
        assert_eq!(
            CodeHost::GitLab
                .signing_keys_url(None, "first.last")
                .unwrap(),
            "https://gitlab.com/api/v4/users/first.last/keys?per_page=100"
        );
        assert!(CodeHost::GitHub.signing_keys_url(None, "a/b").is_err());
        assert!(fetch_signing_keys_from("https://example.com", CodeHost::GitHub, "a").is_err());
    }

    #[test]
    fn rejects_broken_responses() {
        assert!(matches!(
            parse(CodeHost::GitHub, b"{\"message\":\"x\"}"),
            Err(Error::Parse { .. })
        ));
        assert_eq!(parse(CodeHost::GitHub, b"[]").unwrap(), []);
        // 読めない鍵は飛ばす（ssh-keygen を呼ぶ前に）
        let body = br#"[{"key":"ssh-dss AAAAB3NzaC1kc3MAAACBAP","title":"old"},{"key":"junk"}]"#;
        assert_eq!(parse(CodeHost::GitHub, body).unwrap(), []);
    }

    fn emails(profile: &AccountProfile) -> Vec<(&str, CandidateSource)> {
        profile
            .candidates
            .iter()
            .map(|c| (c.email.as_str(), c.source))
            .collect()
    }

    #[test]
    fn github_candidates() {
        let profile = br#"{"login":"Alice","id":42,"email":"alice@example.com"}"#;
        let keys = br#"[
            {"emails":[{"email":"alice@work.example","verified":true},{"email":"old@example.com","verified":false}]},
            {"emails":[{"email":"ALICE@example.com","verified":true}]},
            {"emails":[]}
        ]"#;
        let p = github_profile(profile, keys).unwrap();
        assert_eq!(p.user, "Alice");
        assert_eq!(
            emails(&p),
            [
                ("alice@work.example", CandidateSource::Verified),
                ("ALICE@example.com", CandidateSource::Verified),
                (
                    "42+Alice@users.noreply.github.com",
                    CandidateSource::NoReply
                ),
            ]
        );
        // メールアドレスを公開せず GPG 鍵もなければ、noreply だけ
        let p = github_profile(br#"{"login":"bob","id":7,"email":null}"#, b"[]").unwrap();
        assert_eq!(
            emails(&p),
            [("7+bob@users.noreply.github.com", CandidateSource::NoReply)]
        );
        assert!(github_profile(b"{}", b"[]").is_err());
    }

    #[test]
    fn gitlab_candidates() {
        let p = gitlab_profile(
            br#"[{"id":444,"username":"carol","public_email":"carol@example.com","name":"C"}]"#,
        )
        .unwrap();
        assert_eq!(
            emails(&p),
            [
                ("carol@example.com", CandidateSource::Profile),
                (
                    "444-carol@users.noreply.gitlab.com",
                    CandidateSource::NoReply
                ),
            ]
        );
        // 公開していないメールアドレスは空で来る
        let p = gitlab_profile(br#"[{"id":1,"username":"dan","public_email":""}]"#).unwrap();
        assert_eq!(
            emails(&p),
            [("1-dan@users.noreply.gitlab.com", CandidateSource::NoReply)]
        );
        assert!(matches!(gitlab_profile(b"[]"), Err(Error::NotFound)));
    }
}
