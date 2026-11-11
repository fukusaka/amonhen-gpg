//! コアのエラー。文言は FE が決めるので、種類と材料だけを持つ。

use std::fmt;

use crate::status::Failure;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// gpg を起動できなかった（見つからない、権限がない）。
    Spawn {
        program: String,
        source: std::io::Error,
    },
    /// gpg が失敗した。`code` は終了コード（シグナルで止まったときは `None`）、`failures` は gpg が status で
    /// 報告した失敗（取り消し・パスフレーズの誤りなどは `Failure::kind` で分かる）、`stderr` は人間向けのメッセージ。
    Gpg {
        code: Option<i32>,
        failures: Vec<Failure>,
        stderr: String,
    },
    /// gpg の出力を解釈できなかった。`line` は 1 始まり（出力全体の問題で、行を決められないときは 0）。
    Parse { line: usize, message: String },
    /// 引数が正しくない（gpg を起動する前に止めた）。
    InvalidArgument { name: &'static str, message: String },
    /// 指した鍵がない。
    NotFound,
    /// gpg は成功を返したが、鍵が思ったとおりに変わらなかった（対話で答える操作の確かめ）。
    NotApplied { message: String },
    /// ファイルの操作に失敗した（一時保管の鍵束を作る・消すなど）。
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Spawn { program, source } => write!(f, "cannot start {program}: {source}"),
            Error::Gpg {
                code: Some(c),
                stderr,
                ..
            } => write!(f, "gpg exited with {c}: {}", stderr.trim()),
            Error::Gpg {
                code: None, stderr, ..
            } => write!(f, "gpg was terminated: {}", stderr.trim()),
            Error::Parse { line, message } => {
                write!(f, "unexpected gpg output at line {line}: {message}")
            }
            Error::InvalidArgument { name, message } => write!(f, "invalid {name}: {message}"),
            Error::NotFound => write!(f, "key not found"),
            Error::NotApplied { message } => write!(f, "{message}"),
            Error::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Spawn { source, .. } | Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
