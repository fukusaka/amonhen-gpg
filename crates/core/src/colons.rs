//! `--with-colons` の出力を、行ごとのレコードに分ける。仕様は GnuPG の `doc/DETAILS`。
//!
//! 1 行が 1 レコードで、フィールドは `:` で区切る。フィールドの中の `:` や制御文字は C の文字列のように
//! `\x3a` の形で書かれる（UID など）。新しいフィールドは末尾に足されるので、知らないフィールドは無視する。

/// 1 行分のレコード。フィールドはエスケープを解く前のまま持つ。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    fields: Vec<&'a str>,
}

impl<'a> Record<'a> {
    pub fn parse(line: &'a str) -> Self {
        Record {
            fields: line.split(':').collect(),
        }
    }

    /// レコードの種類（1 番目のフィールド。`pub`・`sub`・`uid`・`fpr` など）。
    pub fn kind(&self) -> &'a str {
        self.fields[0]
    }

    /// `n` 番目のフィールド（`doc/DETAILS` と同じく 1 始まり）。ないとき・空のときは `None`。
    pub fn field(&self, n: usize) -> Option<&'a str> {
        n.checked_sub(1)
            .and_then(|i| self.fields.get(i))
            .copied()
            .filter(|f| !f.is_empty())
    }
}

/// `\xHH` のエスケープを解く。UID は UTF-8 なので、壊れたバイト列は置き換え文字にする。
pub fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && bytes.get(i + 1) == Some(&b'x')
            && let Some(b) = bytes.get(i + 2..i + 4).and_then(hex_byte)
        {
            out.push(b);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_byte(pair: &[u8]) -> Option<u8> {
    let s = std::str::from_utf8(pair).ok()?;
    u8::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_one_based_and_empty_is_none() {
        let r = Record::parse("pub:u:255:22:ABCD:1700000000:::u:::scSC:");
        assert_eq!(r.kind(), "pub");
        assert_eq!(r.field(2), Some("u"));
        assert_eq!(r.field(7), None);
        assert_eq!(r.field(12), Some("scSC"));
        assert_eq!(r.field(40), None);
        assert_eq!(r.field(0), None);
    }

    #[test]
    fn unescape_colon_and_utf8() {
        assert_eq!(
            unescape(r"Alice \x3a Ops <a@example.com>"),
            "Alice : Ops <a@example.com>"
        );
        assert_eq!(unescape(r"\xe7\x A"), "\u{fffd}\\x A");
        assert_eq!(unescape("福坂 <f@example.jp>"), "福坂 <f@example.jp>");
        assert_eq!(unescape(r"tail\x"), r"tail\x");
        assert_eq!(unescape(r"back\x5cslash"), r"back\slash");
    }
}
