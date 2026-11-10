//! コアのエラー。文言は FE が決めるので、種類と材料だけを持つ。

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// gpg を起動できなかった（見つからない、権限がない）。
    Spawn {
        program: String,
        source: std::io::Error,
    },
    /// gpg が失敗した。`code` は終了コード（シグナルで止まったときは `None`）、`stderr` は gpg の出力そのまま。
    Gpg { code: Option<i32>, stderr: String },
    /// gpg の出力を解釈できなかった。`line` は 1 始まり（出力全体の問題で、行を決められないときは 0）。
    Parse { line: usize, message: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Spawn { program, source } => write!(f, "cannot start {program}: {source}"),
            Error::Gpg {
                code: Some(c),
                stderr,
            } => write!(f, "gpg exited with {c}: {}", stderr.trim()),
            Error::Gpg { code: None, stderr } => write!(f, "gpg was terminated: {}", stderr.trim()),
            Error::Parse { line, message } => {
                write!(f, "unexpected gpg output at line {line}: {message}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Spawn { source, .. } => Some(source),
            _ => None,
        }
    }
}
