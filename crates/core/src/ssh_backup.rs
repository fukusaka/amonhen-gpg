//! 取り込んだ SSH の鍵（OpenPGP の鍵でないもの）のバックアップ。
//!
//! gpg-agent が保存している形（パスフレーズで守ったままの S 式）で書き出し、戻す。パスフレーズは聞かず、平文の秘密鍵は
//! 扱わない: パスフレーズで守られていない鍵は書き出さず、守られていない形のものは取り込まない。
//! 書き出しは `EXPORT_KEY --mode1003`（gpg 2.4.0 から）、戻すのは `IMPORT_KEY --mode1003`（2.5.14 から）。
//! 書き出したものは、そのまま `private-keys-v1.d/<keygrip>.key` に置いても gpg-agent が読む（2.4 系で戻す手段）。
//!
//! gpg-agent との受け渡しは、セッションごとの鍵で包まれる（AES key wrap、RFC 3394）。鍵の中身はパスフレーズで守られた
//! ままで、包みは受け渡しのためだけのもの。包みを開き・包み直すため、ここだけは gpg-agent のソケットに直接話す
//! （gpg-connect-agent は出力を溜めるので、同じセッションの中で応答を読んでから次を送れない）。

#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::path::PathBuf;

use aes_kw::{KeyInit, KwAes128};

#[cfg(unix)]
use crate::gpg::percent_decode;
use crate::ssh::check_keygrip;
use crate::{Error, Gpg, Result, Version};

/// バックアップから戻せる一番古い gpg（`IMPORT_KEY --mode1003`）。
pub const SSH_RESTORE_MINIMUM: Version = Version {
    major: 2,
    minor: 5,
    patch: 14,
};

/// パスフレーズで守られた秘密鍵の S 式の始まり。
const PROTECTED: &[u8] = b"(21:protected-private-key";

impl Gpg {
    /// 取り込んだ SSH の鍵を、gpg-agent が保存している形（パスフレーズで守ったまま）で返す。パスフレーズは聞かない。
    /// OpenPGP の鍵・カードの鍵・パスフレーズで守られていない鍵は断る（`Error::InvalidArgument`）。
    pub fn export_ssh_key_backup(&self, keygrip: &str) -> Result<Vec<u8>> {
        let keygrip = check_keygrip(keygrip)?;
        if self.belongs_to_openpgp_key(keygrip)? {
            return Err(invalid("the key belongs to an OpenPGP key"));
        }
        let key = self
            .ssh_keys()?
            .into_iter()
            .find(|k| k.keygrip.eq_ignore_ascii_case(keygrip))
            .ok_or(Error::NotFound)?;
        if key.card.is_some() {
            return Err(invalid("the key is on a card"));
        }
        if key.protected != Some(true) {
            return Err(invalid("the key is not protected by a passphrase"));
        }
        let mut agent = Assuan::connect(self)?;
        let kek = agent.command("KEYWRAP_KEY --export")?;
        let wrapped = agent.command(&format!("EXPORT_KEY --mode1003 {keygrip}"))?;
        agent.bye();
        let plain = unwrap(&kek, &wrapped)?;
        let len = canonical_len(&plain).ok_or_else(|| parse("gpg-agent returned no key"))?;
        let backup = plain[..len].to_vec();
        // 鍵が変わっていても、守られていない形は書き出さない
        if !backup.starts_with(PROTECTED) {
            return Err(invalid("the key is not protected by a passphrase"));
        }
        Ok(backup)
    }

    /// `export_ssh_key_backup` で書き出したものを gpg-agent に戻し、SSH に出す。戻した鍵の keygrip を返す。
    /// gpg 2.5.14 より古い・SSH サポートが有効でないときは `Error::InvalidArgument`。同じ鍵がもうあれば
    /// `Error::Agent`（gpg-agent の EEXIST）。パスフレーズは聞かず、鍵はバックアップのパスフレーズで守られたまま。
    pub fn import_ssh_key_backup(&self, backup: &[u8]) -> Result<String> {
        if self.version()? < SSH_RESTORE_MINIMUM {
            return Err(Error::InvalidArgument {
                name: "gpg",
                message: "restoring needs gpg 2.5.14 or later".into(),
            });
        }
        if !self.ssh_support()?.enabled {
            return Err(Error::InvalidArgument {
                name: "ssh",
                message: "ssh support of gpg-agent is not enabled".into(),
            });
        }
        let len = canonical_len(backup).filter(|_| backup.starts_with(PROTECTED));
        // 末尾の詰め物（0 のバイト）は許す
        if len.is_none_or(|n| backup[n..].iter().any(|&b| b != 0)) {
            return Err(Error::InvalidArgument {
                name: "backup",
                message: "not a protected key from gpg-agent".into(),
            });
        }
        let mut key = backup[..len.unwrap_or_default()].to_vec();
        // AES key wrap は 8 バイトの倍数を包む。gpg-agent は S 式の長さで読むので、0 で詰める
        key.resize(key.len().div_ceil(8) * 8, 0);
        let before: Vec<String> = self.ssh_keys()?.into_iter().map(|k| k.keygrip).collect();

        let mut agent = Assuan::connect(self)?;
        let kek = agent.command("KEYWRAP_KEY --import")?;
        let wrapped = wrap(&kek, &key)?;
        agent.inquire("IMPORT_KEY --mode1003", "KEYDATA", &wrapped)?;
        agent.bye();

        let keygrip = self
            .ssh_keys()?
            .into_iter()
            .map(|k| k.keygrip)
            .find(|g| !before.contains(g))
            .ok_or_else(|| Error::NotApplied {
                message: "gpg-agent did not add the key".into(),
            })?;
        self.set_ssh_key_enabled(&keygrip, true)?;
        Ok(keygrip)
    }
}

/// gpg-agent のセッションの鍵（`KEYWRAP_KEY`）で包む。
fn wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0; key.len() + 8];
    kw(kek)?
        .wrap_key(key, &mut out)
        .map_err(|_| parse("cannot wrap the key for gpg-agent"))?;
    Ok(out)
}

/// gpg-agent のセッションの鍵で包まれたものを開く。
fn unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0; wrapped.len().saturating_sub(8)];
    kw(kek)?
        .unwrap_key(wrapped, &mut out)
        .map_err(|_| parse("cannot unwrap the key from gpg-agent"))?;
    Ok(out)
}

fn kw(kek: &[u8]) -> Result<KwAes128> {
    KwAes128::new_from_slice(kek)
        .map_err(|_| parse("gpg-agent returned a wrapping key of a wrong size"))
}

fn invalid(message: &str) -> Error {
    Error::InvalidArgument {
        name: "keygrip",
        message: message.into(),
    }
}

fn parse(message: &str) -> Error {
    Error::Parse {
        line: 0,
        message: message.into(),
    }
}

/// canonical な S 式の長さ（先頭から、最初の式が閉じるまで）。形が違えば `None`。表示用のヒント（`[...]`）は扱わない。
fn canonical_len(bytes: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = 0;
    loop {
        match *bytes.get(i)? {
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth = depth.checked_sub(1)?;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'0'..=b'9' if depth > 0 => {
                let start = i;
                while bytes.get(i)?.is_ascii_digit() {
                    i += 1;
                }
                if bytes[i] != b':' {
                    return None;
                }
                let n: usize = std::str::from_utf8(&bytes[start..i]).ok()?.parse().ok()?;
                i = i.checked_add(1 + n)?;
                if i > bytes.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

/// gpg-agent のソケットとの Assuan のやり取り（このモジュールの、包みを開き・包み直す操作だけで使う）。
#[cfg(unix)]
struct Assuan {
    reader: BufReader<std::os::unix::net::UnixStream>,
    writer: std::os::unix::net::UnixStream,
    socket: PathBuf,
}

/// 応答の終わり。
#[cfg(unix)]
enum End {
    Ok,
    Inquire(String),
}

#[cfg(unix)]
impl Assuan {
    fn connect(gpg: &Gpg) -> Result<Self> {
        // gpg-connect-agent と違い、ソケットに話すだけでは gpg-agent は起動しない
        gpg.run_tool("gpgconf", &["--launch", "gpg-agent"], None)?;
        let socket = gpg.run_tool("gpgconf", &["--list-dirs", "agent-socket"], None)?;
        let socket = PathBuf::from(percent_decode(socket.trim_end_matches(['\r', '\n'])));
        let writer =
            std::os::unix::net::UnixStream::connect(&socket).map_err(|source| Error::Io {
                path: socket.clone(),
                source,
            })?;
        let reader = BufReader::new(writer.try_clone().map_err(|source| Error::Io {
            path: socket.clone(),
            source,
        })?);
        let mut agent = Assuan {
            reader,
            writer,
            socket,
        };
        agent.read_reply()?;
        Ok(agent)
    }

    /// コマンドを送り、`D` の行のデータを返す。
    fn command(&mut self, line: &str) -> Result<Vec<u8>> {
        self.send(line.as_bytes())?;
        match self.read_reply()? {
            (End::Ok, data) => Ok(data),
            (End::Inquire(_), _) => {
                self.send(b"CAN")?;
                let _ = self.read_reply();
                Err(parse("gpg-agent asked for unexpected data"))
            }
        }
    }

    /// コマンドを送り、`name` を聞かれたら `data` を渡して、終わりを待つ。
    fn inquire(&mut self, line: &str, name: &str, data: &[u8]) -> Result<()> {
        self.send(line.as_bytes())?;
        match self.read_reply()? {
            (End::Inquire(asked), _) if asked == name => {
                // Assuan の 1 行は 1000 バイトまで。エスケープで 3 倍になっても収まる長さに分ける
                for chunk in data.chunks(300) {
                    let mut out = b"D ".to_vec();
                    for &b in chunk {
                        match b {
                            b'%' | b'\r' | b'\n' => out.extend(format!("%{b:02X}").bytes()),
                            _ => out.push(b),
                        }
                    }
                    self.send(&out)?;
                }
                self.send(b"END")?;
                match self.read_reply()? {
                    (End::Ok, _) => Ok(()),
                    (End::Inquire(_), _) => Err(parse("gpg-agent asked for more data")),
                }
            }
            (End::Inquire(_), _) => {
                self.send(b"CAN")?;
                let _ = self.read_reply();
                Err(parse("gpg-agent asked for unexpected data"))
            }
            (End::Ok, _) => Err(parse("gpg-agent did not ask for the key")),
        }
    }

    fn bye(mut self) {
        let _ = self.send(b"BYE");
    }

    fn send(&mut self, line: &[u8]) -> Result<()> {
        let io = |source| Error::Io {
            path: self.socket.clone(),
            source,
        };
        self.writer.write_all(line).map_err(io)?;
        self.writer.write_all(b"\n").map_err(io)
    }

    /// `OK`・`ERR`・`INQUIRE` まで読み、その間の `D` の行のデータ（エスケープを解いたもの）と一緒に返す。
    fn read_reply(&mut self) -> Result<(End, Vec<u8>)> {
        let mut data = Vec::new();
        loop {
            let mut line = Vec::new();
            let n = self
                .reader
                .read_until(b'\n', &mut line)
                .map_err(|source| Error::Io {
                    path: self.socket.clone(),
                    source,
                })?;
            if n == 0 {
                return Err(parse("gpg-agent closed the connection"));
            }
            if line.ends_with(b"\n") {
                line.pop();
            }
            if let Some(rest) = line.strip_prefix(b"D ") {
                unescape_into(rest, &mut data);
            } else if line == b"OK" || line.starts_with(b"OK ") {
                return Ok((End::Ok, data));
            } else if let Some(rest) = line.strip_prefix(b"ERR ") {
                let rest = String::from_utf8_lossy(rest);
                let (code, message) = rest.split_once(' ').unwrap_or((&rest, ""));
                return Err(Error::Agent {
                    code: code.parse().unwrap_or(0),
                    message: message.to_owned(),
                });
            } else if let Some(rest) = line.strip_prefix(b"INQUIRE ") {
                let rest = String::from_utf8_lossy(rest);
                let name = rest.split(' ').next().unwrap_or_default().to_owned();
                return Ok((End::Inquire(name), data));
            }
            // `S`・`#` の行は読み飛ばす
        }
    }
}

/// ソケットで話せない環境（Windows の gpg-agent はソケットの代わりに TCP と nonce を使う）。まだ扱わない。
#[cfg(not(unix))]
struct Assuan;

#[cfg(not(unix))]
impl Assuan {
    fn connect(_gpg: &Gpg) -> Result<Self> {
        Err(Error::InvalidArgument {
            name: "platform",
            message: "talking to gpg-agent directly is not supported here".into(),
        })
    }
    fn command(&mut self, _line: &str) -> Result<Vec<u8>> {
        unreachable!()
    }
    fn inquire(&mut self, _line: &str, _name: &str, _data: &[u8]) -> Result<()> {
        unreachable!()
    }
    fn bye(self) {}
}

/// Assuan のエスケープ（`%XX`）を解いて足す。
#[cfg(any(unix, test))]
fn unescape_into(bytes: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_canonical_s_expressions() {
        assert_eq!(canonical_len(b"(1:a)"), Some(5));
        assert_eq!(canonical_len(b"(1:a(2:bc))\0\0\0"), Some(11));
        // 長さの中に括弧があっても数えない
        assert_eq!(canonical_len(b"(3:a)b)"), Some(7));
        assert_eq!(canonical_len(b"(5:ab)"), None);
        assert_eq!(canonical_len(b"(1:a"), None);
        assert_eq!(canonical_len(b"1:a"), None);
        assert_eq!(canonical_len(b"(a)"), None);
        assert_eq!(canonical_len(b""), None);
    }

    #[test]
    fn unescapes_assuan_data() {
        let mut out = Vec::new();
        unescape_into(b"a%25b%0Ac%0D%zz", &mut out);
        assert_eq!(out, b"a%b\nc\r%zz");
    }

    #[test]
    fn wraps_like_rfc_3394() {
        // RFC 3394 4.1（128 ビットの鍵で 128 ビットを包む）
        let kek: Vec<u8> = (0..16).collect();
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let wrapped = wrap(&kek, &key).unwrap();
        assert_eq!(
            wrapped,
            [
                0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
                0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
            ]
        );
        assert_eq!(unwrap(&kek, &wrapped).unwrap(), key);
        // 包みが壊れていれば開けない
        let mut broken = wrapped.clone();
        broken[3] ^= 1;
        assert!(unwrap(&kek, &broken).is_err());
        assert!(wrap(&kek[..15], &key).is_err());
    }
}
