//! スマートカード（OpenPGP カード・YubiKey など）の状態（`gpg --card-status --with-colons`）。
//!
//! 鍵一覧からは「秘密鍵はシリアル番号 X のカードにある」までしか分からない。カードが今挿さっているかは、
//! これで確かめる。

use serde::{Deserialize, Serialize};

use crate::colons::{Record, unescape};
use crate::{Gpg, Result};

/// 挿さっているカード。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    /// アプリケーション ID（`D276000124010304...`）。鍵一覧の `SecretState::OnCard` のシリアル番号と同じもの。
    pub aid: String,
    pub reader: Option<String>,
    /// 製造元（`Yubico` など）。
    pub vendor: Option<String>,
    /// カードに書かれているシリアル番号（AID の一部。カードの本体に印刷されている番号）。
    pub serial: Option<String>,
    /// 署名した回数。
    pub signature_count: Option<u32>,
    /// 署名・暗号化・認証の鍵のフィンガープリント（空の枠は `None`）。
    pub signing_key: Option<String>,
    pub encryption_key: Option<String>,
    pub authentication_key: Option<String>,
    /// PIN を間違えられる残りの回数（ユーザー PIN、リセットコード、管理者 PIN）。
    pub pin_retries: Vec<u32>,
}

impl Card {
    /// 鍵一覧の `SecretState::OnCard` のシリアル番号が、このカードのものか。
    pub fn holds(&self, serial: &str) -> bool {
        self.aid.eq_ignore_ascii_case(serial)
    }
}

impl Gpg {
    /// 挿さっているカード。カードやリーダーがなければ `None`。
    pub fn card_status(&self) -> Result<Option<Card>> {
        let out = self.run_raw(&["--with-colons", "--card-status"], None)?;
        // CARDCTRL 4: カードがない、5: リーダーがない、6: カードを扱えない（scdaemon がないなど）
        let no_card = out
            .status
            .iter()
            .any(|s| s.keyword == "CARDCTRL" && matches!(s.arg(0), Some("4" | "5" | "6")));
        if no_card {
            return Ok(None);
        }
        if !out.success() {
            return Err(out.into_error());
        }
        Ok(parse_card(&String::from_utf8_lossy(&out.stdout)))
    }
}

/// `--card-status --with-colons` の出力。AID がなければカードはない。
fn parse_card(output: &str) -> Option<Card> {
    let mut card = Card::default();
    for line in output.lines() {
        let r = Record::parse(line);
        let text = |n| r.field(n).map(unescape);
        match r.kind() {
            "AID" => card.aid = r.field(2).unwrap_or_default().to_owned(),
            "Reader" => card.reader = text(2),
            "vendor" => card.vendor = text(3),
            "serial" => card.serial = text(2),
            "sigcount" => card.signature_count = r.field(2).and_then(|n| n.parse().ok()),
            "fpr" => {
                card.signing_key = r.field(2).map(str::to_owned);
                card.encryption_key = r.field(3).map(str::to_owned);
                card.authentication_key = r.field(4).map(str::to_owned);
            }
            "pinretry" => {
                card.pin_retries = (2..=4)
                    .filter_map(|n| r.field(n).and_then(|v| v.parse().ok()))
                    .collect();
            }
            _ => {}
        }
    }
    (!card.aid.is_empty()).then_some(card)
}

#[cfg(test)]
mod tests {
    use super::*;

    // gpg 2.4 の YubiKey の出力の形（`g10/card-util.c` の colon 出力をもとにした例）
    const STATUS: &str = "\
Reader:Yubico YubiKey OTP FIDO CCID 00 00:AID:D2760001240103040006123456780000:openpgp-card:
AID:D2760001240103040006123456780000:openpgp-card:
version:0304:
vendor:0006:Yubico:
serial:12345678:
name:::
lang::
sex:u:
url::
login::
forcepin:1:::
keyattr:1:22:Ed25519:
keyattr:2:18:Curve25519:
keyattr:3:22:Ed25519:
maxpinlen:127:127:127:
pinretry:3:0:3:
sigcount:42:::
cafpr::::
fpr:AAAABBBBCCCCDDDDEEEEFFFF1111222233334444:99990000AAAABBBBCCCCDDDD5555666677778888::
";

    #[test]
    fn parses_card() {
        let card = parse_card(STATUS).unwrap();
        assert_eq!(card.aid, "D2760001240103040006123456780000");
        assert_eq!(card.vendor.as_deref(), Some("Yubico"));
        assert_eq!(card.serial.as_deref(), Some("12345678"));
        assert_eq!(card.signature_count, Some(42));
        assert_eq!(
            card.signing_key.as_deref(),
            Some("AAAABBBBCCCCDDDDEEEEFFFF1111222233334444")
        );
        assert!(card.encryption_key.is_some());
        assert_eq!(card.authentication_key, None);
        assert_eq!(card.pin_retries, vec![3, 0, 3]);
        assert!(card.holds("d2760001240103040006123456780000"));
        assert!(!card.holds("D2760001240103040006000000000000"));
    }

    #[test]
    fn empty_aid_is_no_card() {
        assert_eq!(parse_card("AID:::\n"), None);
        assert_eq!(parse_card(""), None);
    }
}
