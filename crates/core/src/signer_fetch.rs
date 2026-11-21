//! GitHub・GitLab から、利用者の SSH の署名用の鍵を取ってくる。HTTPS は curl に任せる（TLS をアプリの外に置く）。
//! 認証はせず、公開されている鍵だけを読む。

use std::process::Stdio;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::process::command;
use crate::signers::{SignerRecord, normalize_key, ssh_fingerprint};
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
}

/// 応答の大きさの上限。鍵の一覧はずっと小さい。
const MAX_RESPONSE: &str = "1048576";

impl CodeHost {
    /// 利用者の SSH の鍵の一覧を返す API の URL。`api` は API の場所（テストではローカルのサーバー）。
    fn signing_keys_url(self, api: Option<&str>, user: &str) -> Result<String> {
        let user = self.check_user(user)?;
        Ok(match self {
            CodeHost::GitHub => format!(
                "{}/users/{user}/ssh_signing_keys?per_page=100",
                api.unwrap_or("https://api.github.com")
            ),
            CodeHost::GitLab => format!(
                "{}/users/{user}/keys?per_page=100",
                api.unwrap_or("https://gitlab.com/api/v4")
            ),
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
    let (status, body) = curl(&url, api.is_some())?;
    match status {
        200 => {}
        404 => return Err(Error::NotFound),
        _ => {
            return Err(Error::Tool {
                program: "curl".into(),
                code: None,
                stderr: format!(
                    "HTTP {status} from {url}: {}",
                    String::from_utf8_lossy(&body)
                        .chars()
                        .take(300)
                        .collect::<String>()
                ),
            });
        }
    }
    parse(host, &body)
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
    let keys: Vec<ApiKey> = serde_json::from_slice(body).map_err(|e| Error::Parse {
        line: e.line(),
        message: e.to_string(),
    })?;
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
        Ok(SignerChanges { new, gone })
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
}
