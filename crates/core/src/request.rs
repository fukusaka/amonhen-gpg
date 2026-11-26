//! 署名の依頼。主鍵のない Mac で、ローカル署名して欲しい他者の鍵を、自分の鍵（署名用のサブ鍵）で署名した 1 つの
//! ファイルにする。主鍵のある Mac で、自分の鍵からの依頼だと確かめてから開き、鍵を取り込んでローカル署名し、
//! `Gpg::export_local_signatures` で返す。依頼を書き換えて他人の鍵を混ぜることはできない（署名が合わなくなる）。

use serde::{Deserialize, Serialize};

use crate::gpg::check_fingerprint;
use crate::{Error, Gpg, ImportResult, Key, Result, SecretState};

/// 開いた署名の依頼（`Gpg::open_signing_request`）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequest {
    /// 依頼に署名した自分の鍵（主鍵のフィンガープリント）。
    pub requester: String,
    /// 依頼された鍵（鍵束には取り込んでいない）。
    pub keys: Vec<Key>,
}

impl Gpg {
    /// `fingerprints` の公開鍵を、`signer`（自分の鍵。gpg が署名用のサブ鍵を選ぶ）で署名した依頼にする（ASCII 形式）。
    /// パスフレーズは pinentry が聞く。
    pub fn create_signing_request(&self, fingerprints: &[&str], signer: &str) -> Result<Vec<u8>> {
        let signer = check_fingerprint(signer)?;
        let keys = self.export_public_keys(fingerprints, false)?;
        let out = self.run(&["--local-user", signer, "--armor", "--sign"], Some(&keys))?;
        Ok(out.stdout)
    }

    /// 依頼を確かめて、依頼された鍵を返す（鍵束には取り込まない）。自分の鍵（主鍵の秘密鍵がこの鍵束にある）の正しい
    /// 署名でなければ `Error::InvalidArgument`（`name` は `request`）。
    pub fn open_signing_request(&self, data: &[u8]) -> Result<SigningRequest> {
        let (requester, keys) = self.verify_signing_request(data)?;
        Ok(SigningRequest {
            requester,
            keys: self.show_keys(&keys)?,
        })
    }

    /// 依頼を確かめ直して、依頼された鍵をすべて鍵束に取り込む（入手元はファイル）。ローカル署名するには鍵束に
    /// 鍵が要る。どれに署名するかは FE が選ぶ。
    pub fn import_signing_request(&self, data: &[u8]) -> Result<ImportResult> {
        let (_, keys) = self.verify_signing_request(data)?;
        self.import_from_file(&keys)
    }

    /// 依頼の署名を確かめ、署名した主鍵と中身（公開鍵）を返す。
    fn verify_signing_request(&self, data: &[u8]) -> Result<(String, Vec<u8>)> {
        let not_yours = || Error::InvalidArgument {
            name: "request",
            message: "the signing request is not signed by your own key".into(),
        };
        let out = self.run_raw(&["--output", "-", "--decrypt"], Some(data))?;
        let good = out.status.iter().any(|s| s.keyword == "GOODSIG");
        let requester = out
            .status
            .iter()
            .find(|s| s.keyword == "VALIDSIG")
            .and_then(|s| s.arg(9))
            .map(str::to_owned);
        let ultimate = out.status.iter().any(|s| s.keyword == "TRUST_ULTIMATE");
        let Some(requester) = requester.filter(|_| out.success() && good && ultimate) else {
            return Err(not_yours());
        };
        let own = self.list_keys()?.into_iter().any(|k| {
            k.fingerprint.eq_ignore_ascii_case(&requester)
                && matches!(k.secret, SecretState::Available | SecretState::OnCard(_))
        });
        if !own {
            return Err(not_yours());
        }
        Ok((requester, out.stdout))
    }
}
