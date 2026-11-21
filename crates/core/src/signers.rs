//! git の allowed signers（`gpg.ssh.allowedSignersFile`）。設計は `docs/allowed-signers.md`。
//!
//! 人の SSH の署名用の鍵と、それをどう確かめたかの記録（`ssh-signers.json`）を持ち、自分の GPG の鍵で分離署名する
//! （`ssh-signers.json.sig`）。人は一覧（チームやリポジトリごと）に入れ、git が読む allowed signers のファイルは
//! 一覧ごとに記録から書く（`<一覧の ID>.allowed_signers`）。どれも一時ファイルに書いてから rename で置き換え、読み手に
//! 半端な中身を見せない。利用者の `~/.ssh` と git の設定には触らない。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::gpg::{Gpg, check_fingerprint};
use crate::process::command;
use crate::signers_import::ParsedEntry;
use crate::staging::CodeHost;

pub const RECORD_FILE: &str = "ssh-signers.json";
pub const SIGNATURE_FILE: &str = "ssh-signers.json.sig";
/// 一覧ごとの allowed signers のファイルの名前の末尾（`<ID>.allowed_signers`）。
pub const SIGNERS_FILE_SUFFIX: &str = ".allowed_signers";

/// 記録の形の版。読めない版の記録は書き換えない。
const VERSION: u32 = 1;

/// 記録。人ごとに、追うアカウントと受け入れた鍵を持つ。一覧は、どの人を入れるかを持つ（同じ人が複数の一覧に入って
/// よい。鍵は人ごとに 1 か所）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerRecord {
    pub version: u32,
    pub people: Vec<Signer>,
    pub lists: Vec<SignerList>,
}

/// allowed signers の一覧。ファイル 1 つになる。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerList {
    /// ファイルの名前になる（英小文字・数字・`-`）。
    pub id: String,
    /// 画面に出す名前。
    pub name: String,
    /// 入れる人のメールアドレス。
    pub members: Vec<String>,
}

/// 署名する人。`email` は allowed signers の principal で、git が署名した人として表示する。git はコミットの
/// アドレスと比べないので、1 人に 1 つで足りる。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signer {
    pub email: String,
    pub accounts: Vec<Account>,
    pub keys: Vec<SignerKey>,
}

/// 鍵を取ってくるアカウント。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub host: CodeHost,
    pub user: String,
}

/// 受け入れた鍵。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerKey {
    /// 種類と本体（`ssh-ed25519 AAAA...`）。説明（comment）は持たない。
    pub key: String,
    /// `SHA256:...`（ssh-keygen が求めたもの）。
    pub fingerprint: String,
    /// どこから取ったか（手で入れた鍵なら `None`）。
    pub source: Option<KeySource>,
    pub checked: Checked,
    /// 受け入れた日時（UTC、RFC 3339）。
    pub accepted: String,
    /// 退役させた日時（UTC、RFC 3339）。これより後の署名は検証しない（allowed signers の `valid-before`）。
    pub valid_before: Option<String>,
    /// これより前の署名は検証しない日時（UTC、RFC 3339。allowed signers の `valid-after`）。取り込んだファイルにあったときだけ。
    #[serde(default)]
    pub valid_after: Option<String>,
    /// 既存の allowed signers のファイルから取り込んだ鍵なら、そのファイルと行。
    #[serde(default)]
    pub imported: Option<ImportedFrom>,
}

/// 鍵を取り込んだファイル。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedFrom {
    pub path: String,
    /// 1 始まり。
    pub line: u32,
    /// 取り込んだ日時（UTC、RFC 3339）。
    pub imported: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySource {
    pub host: CodeHost,
    pub user: String,
    /// 取ってきた日時（UTC、RFC 3339）。
    pub fetched: String,
}

/// 鍵をどう確かめたか。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Checked {
    /// アカウントから取ったまま。
    Account,
    /// 持ち主とフィンガープリントを照らし合わせた。
    Fingerprint,
    /// 既存の allowed signers のファイルから取り込んだ（そのファイルを書いた人が確かめたもの）。
    File,
}

/// 記録の署名の状態。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordSignature {
    /// 記録がまだない。
    NoRecord,
    /// 自分の鍵（究極の信頼）の正しい署名。`signer` は署名した鍵（主鍵）のフィンガープリント。
    Valid { signer: String },
    /// 署名のファイルがない。
    Missing,
    /// 署名が合わない、または自分の鍵の署名ではない。
    Invalid,
}

/// 一覧の allowed signers のファイルが記録と合っているか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    Matches,
    Missing,
    /// 記録から書いたものと違う（知らないうちに変えられた、または記録だけが変わった）。
    Differs,
}

/// 読み込んだ記録と、その確かめの結果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedSigners {
    pub record: SignerRecord,
    pub signature: RecordSignature,
    /// 一覧ごとのファイルの状態（記録の一覧の順）。
    pub files: Vec<SignersFile>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignersFile {
    pub list: String,
    pub path: PathBuf,
    pub state: FileState,
}

/// 一覧 `id` の allowed signers のファイル。
pub fn signers_file(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}{SIGNERS_FILE_SUFFIX}"))
}

impl SignerRecord {
    pub fn new() -> Self {
        SignerRecord {
            version: VERSION,
            people: Vec::new(),
            lists: Vec::new(),
        }
    }

    /// 一覧を足す。
    pub fn add_list(&mut self, id: &str, name: &str) -> Result<()> {
        let id = check_list_id(id)?;
        if self.lists.iter().any(|l| l.id == id) {
            return Err(invalid("id", &format!("a list `{id}` already exists")));
        }
        self.lists.push(SignerList {
            id: id.to_owned(),
            name: check_list_name(name)?.to_owned(),
            members: Vec::new(),
        });
        Ok(())
    }

    pub fn rename_list(&mut self, id: &str, name: &str) -> Result<()> {
        let name = check_list_name(name)?.to_owned();
        self.list_mut(id)?.name = name;
        Ok(())
    }

    /// 一覧を除く（保存すると、そのファイルも消える。人と鍵は残る）。
    pub fn remove_list(&mut self, id: &str) -> Result<()> {
        let before = self.lists.len();
        self.lists.retain(|l| l.id != id);
        if self.lists.len() == before {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// 人を一覧に入れる（もう入っていれば何もしない）。
    pub fn add_member(&mut self, id: &str, email: &str) -> Result<()> {
        if !self.people.iter().any(|p| p.email == email) {
            return Err(Error::NotFound);
        }
        let list = self.list_mut(id)?;
        if !list.members.iter().any(|m| m == email) {
            list.members.push(email.to_owned());
        }
        Ok(())
    }

    pub fn remove_member(&mut self, id: &str, email: &str) -> Result<()> {
        let members = &mut self.list_mut(id)?.members;
        let before = members.len();
        members.retain(|m| m != email);
        if members.len() == before {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    fn list_mut(&mut self, id: &str) -> Result<&mut SignerList> {
        self.lists
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or(Error::NotFound)
    }

    /// 人を足す（同じアドレスの人がいれば、アカウントだけを足す）。
    pub fn add_person(&mut self, email: &str, account: Option<Account>) -> Result<()> {
        let email = check_email(email)?.to_owned();
        if let Some(a) = &account {
            a.host.check_user(&a.user)?;
        }
        let person = match self.people.iter_mut().position(|p| p.email == email) {
            Some(i) => &mut self.people[i],
            None => {
                self.people.push(Signer {
                    email,
                    accounts: Vec::new(),
                    keys: Vec::new(),
                });
                self.people.last_mut().expect("just pushed")
            }
        };
        if let Some(a) = account
            && !person.accounts.contains(&a)
        {
            person.accounts.push(a);
        }
        Ok(())
    }

    /// 人と、その人の鍵をすべて除く（どの一覧からも外れる）。
    pub fn remove_person(&mut self, email: &str) -> Result<()> {
        let before = self.people.len();
        self.people.retain(|p| p.email != email);
        if self.people.len() == before {
            return Err(Error::NotFound);
        }
        for list in &mut self.lists {
            list.members.retain(|m| m != email);
        }
        Ok(())
    }

    /// `email` の人の鍵として受け入れる。フィンガープリントは ssh-keygen で求める。同じ鍵がもうあれば、確かめ方
    /// （照らし合わせたほうを残す）と入手元を新しくし、退役を取り消す。
    pub fn accept_key(
        &mut self,
        email: &str,
        key: &str,
        source: Option<KeySource>,
        checked: Checked,
    ) -> Result<()> {
        let key = normalize_key(key)?;
        let fingerprint = ssh_fingerprint(&key)?;
        let person = self.person_mut(email)?;
        let accepted = rfc3339(now());
        match person
            .keys
            .iter_mut()
            .find(|k| k.fingerprint == fingerprint)
        {
            Some(k) => {
                if checked == Checked::Fingerprint {
                    k.checked = Checked::Fingerprint;
                }
                if source.is_some() {
                    k.source = source;
                }
                k.valid_before = None;
                k.accepted = accepted;
            }
            None => person.keys.push(SignerKey {
                key,
                fingerprint,
                source,
                checked,
                accepted,
                valid_before: None,
                valid_after: None,
                imported: None,
            }),
        }
        Ok(())
    }

    /// 既存の allowed signers のファイルの行（`parse_allowed_signers`）を、`email` の人の鍵として受け入れる。
    /// 確かめ方は「ファイルから」、期限（`valid-after`・`valid-before`）はファイルのまま。同じ鍵がもうあれば、
    /// 取り込んだ印だけを足す（確かめ方と期限は変えない）。
    pub fn import_key(&mut self, email: &str, entry: &ParsedEntry, path: &str) -> Result<()> {
        let key = normalize_key(&entry.key)?;
        let fingerprint = ssh_fingerprint(&key)?;
        for time in [&entry.valid_after, &entry.valid_before]
            .into_iter()
            .flatten()
        {
            if ssh_time(time).is_none() {
                return Err(invalid("time", "not a UTC time"));
            }
        }
        let imported = ImportedFrom {
            path: path.to_owned(),
            line: entry.line,
            imported: rfc3339(now()),
        };
        let person = self.person_mut(email)?;
        match person
            .keys
            .iter_mut()
            .find(|k| k.fingerprint == fingerprint)
        {
            Some(k) => {
                if k.imported.is_none() {
                    k.imported = Some(imported);
                }
            }
            None => person.keys.push(SignerKey {
                key,
                fingerprint,
                source: None,
                checked: Checked::File,
                accepted: rfc3339(now()),
                valid_before: entry.valid_before.clone(),
                valid_after: entry.valid_after.clone(),
                imported: Some(imported),
            }),
        }
        Ok(())
    }

    /// 鍵を今の時刻で退役させる。それまでの署名は検証できたまま。
    pub fn retire_key(&mut self, email: &str, fingerprint: &str) -> Result<()> {
        let key = self
            .person_mut(email)?
            .keys
            .iter_mut()
            .find(|k| k.fingerprint == fingerprint)
            .ok_or(Error::NotFound)?;
        if key.valid_before.is_none() {
            key.valid_before = Some(rfc3339(now()));
        }
        Ok(())
    }

    /// 鍵を記録から除く（その鍵の署名は、過去のものも検証できなくなる）。
    pub fn remove_key(&mut self, email: &str, fingerprint: &str) -> Result<()> {
        let keys = &mut self.person_mut(email)?.keys;
        let before = keys.len();
        keys.retain(|k| k.fingerprint != fingerprint);
        if keys.len() == before {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    fn person_mut(&mut self, email: &str) -> Result<&mut Signer> {
        self.people
            .iter_mut()
            .find(|p| p.email == email)
            .ok_or(Error::NotFound)
    }

    /// 一覧 `id` の、git が読む allowed signers の中身。人は記録の順に並べる。
    pub fn allowed_signers(&self, id: &str) -> Result<String> {
        let list = self
            .lists
            .iter()
            .find(|l| l.id == id)
            .ok_or(Error::NotFound)?;
        let mut out = format!(
            "# Written by Amonhen GPG from {RECORD_FILE} (list `{}`); edits here are overwritten.\n",
            list.id
        );
        let members = self
            .people
            .iter()
            .filter(|p| list.members.contains(&p.email));
        for person in members {
            for key in &person.keys {
                let mut options = String::from("namespaces=\"git\"");
                if let Some(after) = key.valid_after.as_deref().and_then(ssh_time) {
                    options.push_str(&format!(",valid-after=\"{after}\""));
                }
                if let Some(before) = key.valid_before.as_deref().and_then(ssh_time) {
                    options.push_str(&format!(",valid-before=\"{before}\""));
                }
                out.push_str(&format!("{} {options} {}\n", person.email, key.key));
            }
        }
        Ok(out)
    }

    /// 読んだ記録を確かめる（ファイルから読んだものは、書いたときの確かめを通っているとは限らない）。
    fn validate(&self) -> Result<()> {
        if self.version != VERSION {
            return Err(Error::Parse {
                line: 0,
                message: format!("unsupported record version {}", self.version),
            });
        }
        for (i, list) in self.lists.iter().enumerate() {
            check_list_id(&list.id)?;
            check_list_name(&list.name)?;
            if self.lists[..i].iter().any(|l| l.id == list.id) {
                return Err(invalid("id", "two lists have the same id"));
            }
            if let Some(m) = list
                .members
                .iter()
                .find(|m| !self.people.iter().any(|p| &p.email == *m))
            {
                return Err(invalid("members", &format!("`{m}` is not in the record")));
            }
        }
        for (i, person) in self.people.iter().enumerate() {
            check_email(&person.email)?;
            if self.people[..i].iter().any(|p| p.email == person.email) {
                return Err(invalid("email", "two people have the same address"));
            }
            for a in &person.accounts {
                a.host.check_user(&a.user)?;
            }
            for key in &person.keys {
                if normalize_key(&key.key)? != key.key {
                    return Err(invalid("key", "a key in the record has extra text"));
                }
                for time in [&key.valid_before, &key.valid_after].into_iter().flatten() {
                    if ssh_time(time).is_none() {
                        return Err(invalid("valid_before", "not a UTC time"));
                    }
                }
            }
        }
        Ok(())
    }
}

impl Gpg {
    /// `dir` の記録を読み、署名と allowed signers のファイルを確かめる。記録がなければ空の記録を返す。
    pub fn load_signers(&self, dir: &Path) -> Result<LoadedSigners> {
        let record_path = dir.join(RECORD_FILE);
        let data = match std::fs::read(&record_path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadedSigners {
                    record: SignerRecord::new(),
                    signature: RecordSignature::NoRecord,
                    files: Vec::new(),
                });
            }
            Err(source) => {
                return Err(Error::Io {
                    path: record_path,
                    source,
                });
            }
        };
        let record: SignerRecord = serde_json::from_slice(&data).map_err(|e| Error::Parse {
            line: e.line(),
            message: e.to_string(),
        })?;
        record.validate()?;
        let signature = self.verify_record(dir)?;
        let files = record
            .lists
            .iter()
            .map(|l| file_state(dir, &record, &l.id))
            .collect::<Result<_>>()?;
        Ok(LoadedSigners {
            record,
            signature,
            files,
        })
    }

    /// 記録を `signer`（自分の鍵）で署名して保存し、一覧ごとの allowed signers のファイルを書き直す。なくなった
    /// 一覧のファイルは消す。署名を取り消したら（`Error::Canceled`）、どのファイルも変えない。
    pub fn save_signers(&self, dir: &Path, record: &SignerRecord, signer: &str) -> Result<()> {
        let signer = check_fingerprint(signer)?;
        record.validate()?;
        std::fs::create_dir_all(dir).map_err(|source| Error::Io {
            path: dir.to_owned(),
            source,
        })?;
        let mut json = serde_json::to_vec_pretty(record).map_err(|e| Error::Parse {
            line: 0,
            message: e.to_string(),
        })?;
        json.push(b'\n');
        let record_tmp = write_temp(dir, RECORD_FILE, &json)?;
        let sig_tmp = dir.join(format!(".{SIGNATURE_FILE}.tmp"));
        let _ = std::fs::remove_file(&sig_tmp);
        let signed = self.run(
            &[
                "--local-user",
                signer,
                "--detach-sign",
                "--output",
                path_str(&sig_tmp)?,
                "--",
                path_str(&record_tmp)?,
            ],
            None,
        );
        if let Err(e) = signed {
            let _ = std::fs::remove_file(&record_tmp);
            let _ = std::fs::remove_file(&sig_tmp);
            return Err(e);
        }
        rename(&sig_tmp, &dir.join(SIGNATURE_FILE))?;
        rename(&record_tmp, &dir.join(RECORD_FILE))?;
        for list in &record.lists {
            let name = format!("{}{SIGNERS_FILE_SUFFIX}", list.id);
            let tmp = write_temp(dir, &name, record.allowed_signers(&list.id)?.as_bytes())?;
            rename(&tmp, &dir.join(&name))?;
        }
        // なくなった一覧のファイル（このフォルダの `*.allowed_signers` で、記録にない一覧のもの）を消す
        let entries = std::fs::read_dir(dir).map_err(|source| Error::Io {
            path: dir.to_owned(),
            source,
        })?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|n| n.strip_suffix(SIGNERS_FILE_SUFFIX))
            else {
                continue;
            };
            if check_list_id(id).is_ok() && !record.lists.iter().any(|l| l.id == id) {
                std::fs::remove_file(entry.path()).map_err(|source| Error::Io {
                    path: entry.path(),
                    source,
                })?;
            }
        }
        Ok(())
    }

    /// 記録の署名が、自分の鍵（gpg が究極の信頼とみなす鍵）の正しい署名かを確かめる。
    fn verify_record(&self, dir: &Path) -> Result<RecordSignature> {
        let sig = dir.join(SIGNATURE_FILE);
        if !sig.exists() {
            return Ok(RecordSignature::Missing);
        }
        let out = self.run_raw(
            &[
                "--verify",
                "--",
                path_str(&sig)?,
                path_str(&dir.join(RECORD_FILE))?,
            ],
            None,
        )?;
        let valid = out
            .status
            .iter()
            .find(|s| s.keyword == "VALIDSIG")
            .and_then(|s| s.arg(9).or(s.arg(0)))
            .map(str::to_owned);
        let ultimate = out.status.iter().any(|s| s.keyword == "TRUST_ULTIMATE");
        Ok(match valid {
            Some(signer) if out.success() && ultimate => RecordSignature::Valid { signer },
            _ => RecordSignature::Invalid,
        })
    }
}

/// 一覧 `id` のファイルが、記録から書いたものと同じか。
fn file_state(dir: &Path, record: &SignerRecord, id: &str) -> Result<SignersFile> {
    let path = signers_file(dir, id);
    let state = match std::fs::read_to_string(&path) {
        Ok(text) if text == record.allowed_signers(id)? => FileState::Matches,
        Ok(_) => FileState::Differs,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileState::Missing,
        Err(source) => return Err(Error::Io { path, source }),
    };
    Ok(SignersFile {
        list: id.to_owned(),
        path,
        state,
    })
}

/// 一覧の ID。ファイルの名前になるので、英小文字・数字・`-`（英小文字か数字で始まる）、40 文字まで。
fn check_list_id(id: &str) -> Result<&str> {
    let ok = (1..=40).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit());
    if ok {
        Ok(id)
    } else {
        Err(invalid(
            "id",
            &format!("`{id}` is not a list id (a-z, 0-9 and -)"),
        ))
    }
}

fn check_list_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(invalid("name", "a list needs a short name"));
    }
    Ok(name)
}

/// SSH の公開鍵の行から、種類と本体だけを取り出す（説明は捨てる）。種類は OpenSSH が署名に使えるものだけ。
pub fn normalize_key(line: &str) -> Result<String> {
    const TYPES: &[&str] = &[
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ];
    let mut words = line.split_ascii_whitespace();
    let (Some(kind), Some(body)) = (words.next(), words.next()) else {
        return Err(invalid("key", "not an SSH public key"));
    };
    if !TYPES.contains(&kind) {
        return Err(invalid("key", &format!("unsupported key type `{kind}`")));
    }
    let base64 = |c: char| c.is_ascii_alphanumeric() || "+/=".contains(c);
    if body.len() < 16 || !body.chars().all(base64) {
        return Err(invalid("key", "not an SSH public key"));
    }
    Ok(format!("{kind} {body}"))
}

/// 公開鍵の SHA256 のフィンガープリント（`SHA256:...`）を ssh-keygen で求める。鍵として読めなければ誤り。
pub fn ssh_fingerprint(key: &str) -> Result<String> {
    let key = normalize_key(key)?;
    let program = format!("ssh-keygen{}", std::env::consts::EXE_SUFFIX);
    let spawn_error = |source| Error::Spawn {
        program: program.clone(),
        source,
    };
    let mut child = command(&program)
        .args(["-l", "-E", "sha256", "-f", "-"])
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(spawn_error)?;
    if let Some(mut stdin) = child.stdin.take() {
        // 1 行だけなので、読む前に書き切ってもパイプは詰まらない
        stdin
            .write_all(format!("{key}\n").as_bytes())
            .map_err(spawn_error)?;
    }
    let out = child.wait_with_output().map_err(spawn_error)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    match stdout.split_ascii_whitespace().nth(1) {
        Some(f) if out.status.success() && f.starts_with("SHA256:") => Ok(f.to_owned()),
        _ => Err(Error::Tool {
            program,
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }),
    }
}

/// allowed signers の principal にするメールアドレス。空白・カンマ・引用符・`*`・`?`（パターンになる）を含まない。
pub(crate) fn check_email(email: &str) -> Result<&str> {
    let ok = !email.is_empty()
        && email.len() <= 254
        && email.contains('@')
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.starts_with('#')
        && email
            .chars()
            .all(|c| c.is_ascii_graphic() && !",\"'*?!".contains(c));
    if ok {
        Ok(email)
    } else {
        Err(invalid(
            "email",
            &format!("`{email}` is not an email address"),
        ))
    }
}

fn invalid(name: &'static str, message: &str) -> Error {
    Error::InvalidArgument {
        name,
        message: message.to_owned(),
    }
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| invalid("dir", "the folder name is not valid UTF-8"))
}

/// `dir` の中に、`name` の隣の一時ファイルとして書く（同じファイルシステムで rename できるように）。
fn write_temp(dir: &Path, name: &str, data: &[u8]) -> Result<PathBuf> {
    let path = dir.join(format!(".{name}.tmp"));
    std::fs::write(&path, data).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

fn rename(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to).map_err(|source| Error::Io {
        path: to.to_owned(),
        source,
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// UTC の RFC 3339（`2026-11-21T04:30:00Z`）。
pub(crate) fn rfc3339(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let t = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        t / 3600,
        t / 60 % 60,
        t % 60
    )
}

/// RFC 3339 の UTC の時刻（`rfc3339` が書く形）を、allowed signers の時刻（`20261121043000Z`）にする。
pub(crate) fn ssh_time(rfc3339: &str) -> Option<String> {
    let b = rfc3339.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let ok = b.len() == 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[19] == b'Z';
    ok.then(|| {
        format!(
            "{}{}{}{}{}{}Z",
            &rfc3339[0..4],
            &rfc3339[5..7],
            &rfc3339[8..10],
            &rfc3339[11..13],
            &rfc3339[14..16],
            &rfc3339[17..19]
        )
    })
}

/// 1970-01-01 からの日数を年月日にする（Howard Hinnant の civil_from_days）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9vaIjchjlw1Meq/+2WNnjXNbJMV6vLwmwhn4OE4LZZ";

    #[test]
    fn formats_times() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_795_235_400), "2026-11-21T04:30:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(
            ssh_time("2026-11-21T04:30:00Z").as_deref(),
            Some("20261121043000Z")
        );
        for bad in [
            "2026-11-21",
            "2026-11-21T04:30:00+09:00",
            "2026-11-21T04:30:0xZ",
        ] {
            assert_eq!(ssh_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn normalizes_keys() {
        assert_eq!(
            normalize_key(&format!("  {KEY} alice@laptop ")).unwrap(),
            KEY
        );
        for bad in [
            "",
            "ssh-ed25519",
            "ssh-dss AAAAB3NzaC1kc3MAAACBAP",
            "ssh-ed25519 not\"base64\"atall",
            "ssh-ed25519 AAAA",
        ] {
            assert!(normalize_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn checks_email_addresses() {
        assert!(check_email("alice@example.com").is_ok());
        for bad in [
            "",
            "alice",
            "@example.com",
            "alice@",
            "a b@example.com",
            "a,b@example.com",
            "*@example.com",
            "#a@example.com",
            "a\"@example.com",
        ] {
            assert!(check_email(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn writes_allowed_signers() {
        let mut record = SignerRecord::new();
        record.add_person("alice@example.com", None).unwrap();
        record.add_person("bob@example.com", None).unwrap();
        record.add_list("work", "Work").unwrap();
        record.add_member("work", "alice@example.com").unwrap();
        record.people[1].keys.push(SignerKey {
            key: KEY.into(),
            fingerprint: "SHA256:y".into(),
            source: None,
            checked: Checked::Account,
            accepted: "2026-11-21T04:30:00Z".into(),
            valid_before: None,
            valid_after: None,
            imported: None,
        });
        record.people[0].keys.push(SignerKey {
            key: KEY.into(),
            fingerprint: "SHA256:x".into(),
            source: None,
            checked: Checked::Account,
            accepted: "2026-11-21T04:30:00Z".into(),
            valid_before: Some("2026-11-22T00:00:00Z".into()),
            valid_after: None,
            imported: None,
        });
        assert_eq!(
            record.allowed_signers("work").unwrap(),
            format!(
                "# Written by Amonhen GPG from ssh-signers.json (list `work`); edits here are overwritten.\n\
                 alice@example.com namespaces=\"git\",valid-before=\"20261122000000Z\" {KEY}\n"
            )
        );
        assert!(matches!(
            record.allowed_signers("oss"),
            Err(Error::NotFound)
        ));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"checked\":\"account\""), "{json}");
        assert_eq!(serde_json::from_str::<SignerRecord>(&json).unwrap(), record);
    }

    #[test]
    fn adds_and_removes_people() {
        let mut record = SignerRecord::new();
        let account = Account {
            host: CodeHost::GitHub,
            user: "alice".into(),
        };
        record
            .add_person("alice@example.com", Some(account.clone()))
            .unwrap();
        record
            .add_person("alice@example.com", Some(account.clone()))
            .unwrap();
        assert_eq!(record.people.len(), 1);
        assert_eq!(record.people[0].accounts, vec![account]);
        assert!(
            record
                .add_person(
                    "bob@example.com",
                    Some(Account {
                        host: CodeHost::GitHub,
                        user: "-bad".into()
                    })
                )
                .is_err()
        );
        assert!(matches!(
            record.remove_person("bob@example.com"),
            Err(Error::NotFound)
        ));
        record.remove_person("alice@example.com").unwrap();
        assert!(record.people.is_empty());
    }
}

#[cfg(test)]
mod list_tests {
    use super::*;

    #[test]
    fn keeps_lists() {
        let mut record = SignerRecord::new();
        record.add_person("alice@example.com", None).unwrap();
        record.add_list("work", " Work ").unwrap();
        assert_eq!(record.lists[0].name, "Work");
        for bad in ["", "Work", "-a", "a/b", "a.b", &"a".repeat(41)] {
            assert!(record.add_list(bad, "x").is_err(), "{bad}");
        }
        assert!(record.add_list("work", "Again").is_err());
        assert!(record.add_list("oss", " ").is_err());
        assert!(matches!(
            record.add_member("work", "bob@example.com"),
            Err(Error::NotFound)
        ));
        record.add_member("work", "alice@example.com").unwrap();
        record.add_member("work", "alice@example.com").unwrap();
        assert_eq!(record.lists[0].members, ["alice@example.com"]);
        record.rename_list("work", "Day job").unwrap();
        record.validate().unwrap();
        record.remove_person("alice@example.com").unwrap();
        assert!(record.lists[0].members.is_empty());
        assert!(matches!(
            record.remove_member("work", "alice@example.com"),
            Err(Error::NotFound)
        ));
        record.remove_list("work").unwrap();
        assert!(matches!(record.remove_list("work"), Err(Error::NotFound)));
    }

    #[test]
    fn rejects_inconsistent_records() {
        let mut record = SignerRecord::new();
        record.add_list("work", "Work").unwrap();
        record.lists[0].members.push("ghost@example.com".into());
        assert!(record.validate().is_err());
        let mut record = SignerRecord::new();
        record.add_list("work", "Work").unwrap();
        record.lists.push(record.lists[0].clone());
        assert!(record.validate().is_err());
    }
}
