//! 子プロセスの起動。

use std::ffi::OsStr;
use std::process::Command;

/// `program` を起動する `Command`。Windows では窓を出さない（`CREATE_NO_WINDOW`）。Unix では、子のシグナルマスクを
/// 空にする。
///
/// Rust の `Command` は、起動したスレッドのシグナルマスクをそのまま子に渡す。macOS のアプリ（AppKit・Swift
/// Concurrency）のスレッドは SIGCHLD などを塞いでいるので、そこから起動した gpg も、gpg が起動する gpg-agent や
/// pinentry も、塞いだまま動いてしまう（amonhen-standalone では、子の終了に気づかず git が終わらなかった）。
pub fn command(program: impl AsRef<OsStr>) -> Command {
    // ここだけが Command::new を直接呼ぶ（clippy.toml の disallowed-methods）
    #[allow(unused_mut, clippy::disallowed_methods)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    clear_signal_mask(&mut cmd);
    cmd
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn clear_signal_mask(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: fork と exec の間で、ゼロ埋めの集合（空）を pthread_sigmask に渡すだけ。どちらも
    // async-signal-safe で、メモリを確保しない。
    unsafe {
        cmd.pre_exec(|| {
            let empty: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            Ok(())
        });
    }
}
