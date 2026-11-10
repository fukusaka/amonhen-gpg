//! `--status-fd` の出力。仕様は GnuPG の `doc/DETAILS` の「Format of the --status-fd output」。
//!
//! 1 行が `[GNUPG:] KEYWORD arg1 arg2 ...` の形。操作の成否と結果は、終了コードや人間向けの文ではなく、
//! これで判断する。gpg は status と人間向けのメッセージを同じ stderr に出すので、接頭辞で分ける。

const PREFIX: &str = "[GNUPG:] ";

/// status の 1 行。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub keyword: String,
    pub args: Vec<String>,
}

impl Status {
    pub fn arg(&self, n: usize) -> Option<&str> {
        self.args.get(n).map(String::as_str)
    }
}

/// gpg の stderr を、status の行と人間向けのメッセージに分ける。
pub fn split(stderr: &str) -> (Vec<Status>, String) {
    let mut status = Vec::new();
    let mut messages = String::new();
    for line in stderr.lines() {
        match line.strip_prefix(PREFIX) {
            Some(rest) => {
                let mut words = rest.split(' ').filter(|w| !w.is_empty());
                if let Some(keyword) = words.next() {
                    status.push(Status {
                        keyword: keyword.to_owned(),
                        args: words.map(str::to_owned).collect(),
                    });
                }
            }
            None => {
                messages.push_str(line);
                messages.push('\n');
            }
        }
    }
    (status, messages)
}

/// gpg が報告した失敗（`ERROR`・`FAILURE`）。`code` は gpg-error の値（上位 8 ビットが発生源、下位 16 ビットが種類）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// 失敗した場所（`keygen.create`・`delete_key` など）。
    pub location: String,
    pub code: u32,
}

impl Failure {
    /// 発生源を除いた種類（`GPG_ERR_CANCELED` = 99、`GPG_ERR_BAD_PASSPHRASE` = 11 など）。
    pub fn kind(&self) -> u32 {
        self.code & 0xffff
    }

    pub fn from_status(status: &[Status]) -> Vec<Failure> {
        status
            .iter()
            .filter(|s| s.keyword == "ERROR" || s.keyword == "FAILURE")
            .filter_map(|s| {
                Some(Failure {
                    location: s.arg(0)?.to_owned(),
                    code: s.arg(1)?.parse().ok()?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_status_from_messages() {
        let stderr = "\
gpg: key 1111222233334444: public key \"Alice\" imported
[GNUPG:] IMPORT_OK 1 AAAABBBBCCCCDDDDEEEEFFFF1111222233334444
[GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0
gpg: Total number processed: 1
[GNUPG:] FAILURE keygen.create 33554531
";
        let (status, messages) = split(stderr);
        assert_eq!(status.len(), 3);
        assert_eq!(status[0].keyword, "IMPORT_OK");
        assert_eq!(status[0].arg(0), Some("1"));
        assert_eq!(status[1].args.len(), 15);
        assert_eq!(
            messages,
            "gpg: key 1111222233334444: public key \"Alice\" imported\ngpg: Total number processed: 1\n"
        );

        let failures = Failure::from_status(&status);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].location, "keygen.create");
        assert_eq!(failures[0].kind(), 99);
    }
}
