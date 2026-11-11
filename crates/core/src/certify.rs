//! 他者の鍵への署名（鍵の持ち主と UID を確かめたことを、自分の鍵で示す）。信頼の輪の材料になる。

use crate::gpg::{check_fingerprint, check_user_id};
use crate::{Gpg, Result};

impl Gpg {
    /// 鍵の UID に自分の鍵で署名する。`user_ids` が空なら有効な UID すべて（鍵一覧の `UserId::text` と同じ文字列で選ぶ）。
    /// `signer` は署名に使う自分の鍵のフィンガープリント（`None` なら gpg の既定の鍵）。`local` なら書き出さない署名
    /// （`--quick-lsign-key`）にし、自分の鍵束の中で有効性を決めるだけで、鍵サーバーには載らない。
    /// 署名済みの UID はそのままにする。FE は署名の前に、フィンガープリントを持ち主と照らし合わせるよう促す。
    pub fn sign_key(
        &self,
        fingerprint: &str,
        user_ids: &[&str],
        signer: Option<&str>,
        local: bool,
    ) -> Result<()> {
        let fingerprint = check_fingerprint(fingerprint)?;
        let mut args = Vec::new();
        if let Some(signer) = signer {
            args.extend(["--local-user", check_fingerprint(signer)?]);
        }
        args.push(if local {
            "--quick-lsign-key"
        } else {
            "--quick-sign-key"
        });
        args.extend(["--", fingerprint]);
        for u in user_ids {
            args.push(check_user_id(u)?);
        }
        self.run(&args, None)?;
        Ok(())
    }
}
