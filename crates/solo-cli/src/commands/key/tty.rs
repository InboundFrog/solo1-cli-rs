//! Secret prompts that turn terminal echo off before the prompt text is shown.
//!
//! `rpassword::prompt_password` prints the prompt first and turns echo off after that. Input that
//! arrives in between (a script that answers at once) would be echoed. On Unix, [`prompt_secret`]
//! turns echo off first and then calls `rpassword`. On other systems it is plain `rpassword`.

use crate::error::{Result, SoloError};
use zeroize::Zeroizing;

/// Print `prompt` on the terminal and read one line without echo.
///
/// # Errors
/// Returns [`SoloError::IoError`] if the prompt cannot be shown or the line cannot be read.
pub fn prompt_secret(prompt: &str) -> Result<Zeroizing<String>> {
    #[cfg(unix)]
    let line = unix::with_guard(unix::EchoOff::new(), || rpassword::prompt_password(prompt));
    #[cfg(not(unix))]
    let line = rpassword::prompt_password(prompt);
    Ok(Zeroizing::new(line.map_err(SoloError::IoError)?))
}

/// Put the terminal back as `prompt_secret` found it. The Ctrl-C handler calls this, because it
/// ends the process without running destructors. Does nothing when no prompt is active.
pub fn restore_tty() {
    #[cfg(unix)]
    unix::restore();
}

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::{Mutex, PoisonError};

    use libc::{ECHO, ECHONL, TCSANOW, tcgetattr, tcsetattr, termios};

    /// The terminal state to restore: its fd and the settings from before echo was turned off.
    static SAVED: Mutex<Option<(RawFd, termios)>> = Mutex::new(None);

    /// Turns echo off on `/dev/tty` while it lives. `rpassword` then saves the echo-off state as
    /// its "original" and restores that; this guard restores the real original afterwards.
    pub struct EchoOff {
        _tty: File,
    }

    impl EchoOff {
        /// `None` if there is no terminal; then `rpassword` reports its own error.
        pub fn new() -> Option<Self> {
            Self::on(File::options().read(true).write(true).open("/dev/tty").ok()?)
        }

        /// Turn echo off on the terminal `file`. `None` if it is not a terminal.
        pub fn on(file: File) -> Option<Self> {
            let fd = file.as_raw_fd();
            let orig = echo_off(fd)?;
            *SAVED.lock().unwrap_or_else(PoisonError::into_inner) = Some((fd, orig));
            Some(Self { _tty: file })
        }
    }

    /// Run `f` while `guard` is alive. The guard is dropped after `f` returns, also on a panic.
    pub fn with_guard<R>(guard: Option<EchoOff>, f: impl FnOnce() -> R) -> R {
        let _guard = guard;
        f()
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            restore();
        }
    }

    pub fn restore() {
        let mut saved = SAVED.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((fd, orig)) = saved.take() {
            // SAFETY: `fd` is the open `/dev/tty` of the guard that stored it. The guard closes it
            // only after its own `restore` has run, and that waits for this lock. `orig` came
            // from `tcgetattr`.
            if unsafe { tcsetattr(fd, TCSANOW, &raw const orig) } != 0 {
                // Drop and the Ctrl-C handler cannot return an error.
                log::warn!(
                    "Could not restore the terminal settings: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    /// Clear ECHO and ECHONL. Every other flag stays as it is. ECHONL must go too: with only ECHO
    /// off, the newline of an early `PIN\n` would still be echoed, and `rpassword` prints its own
    /// newline after the read.
    const fn without_echo(mut t: termios) -> termios {
        t.c_lflag &= !(ECHO | ECHONL);
        t
    }

    /// Turn echo off on `fd`. Returns the old settings, or `None` if `fd` is not a terminal.
    fn echo_off(fd: RawFd) -> Option<termios> {
        let mut t = MaybeUninit::<termios>::uninit();
        // SAFETY: `t` is valid for writes; `tcgetattr` fills it when it returns 0.
        if unsafe { tcgetattr(fd, t.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: `tcgetattr` returned 0, so `t` is initialised.
        let orig = unsafe { t.assume_init() };
        let quiet = without_echo(orig);
        // SAFETY: `quiet` is a valid termios.
        (unsafe { tcsetattr(fd, TCSANOW, &raw const quiet) } == 0).then_some(orig)
    }

    #[cfg(test)]
    mod tests {
        #![allow(
            clippy::indexing_slicing,
            clippy::unwrap_used,
            clippy::expect_used,
            clippy::panic,
            clippy::arithmetic_side_effects,
            clippy::as_conversions,
            clippy::cast_possible_truncation
        )]
        use super::*;
        use libc::ICANON;
        use std::os::fd::{FromRawFd, OwnedFd};

        /// The tests that use `EchoOff::on` share the `SAVED` static, so they run one at a time.
        static SERIAL: Mutex<()> = Mutex::new(());

        fn serial() -> std::sync::MutexGuard<'static, ()> {
            SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Both ends of a new pty. `OwnedFd` closes them also when an assert fails.
        fn pty() -> (OwnedFd, OwnedFd) {
            let (mut master, mut slave) = (0, 0);
            // SAFETY: both fd pointers are valid for writes; the name and termios pointers may be null.
            let rc = unsafe {
                libc::openpty(
                    &raw mut master,
                    &raw mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(rc, 0);
            // SAFETY: `openpty` returned two new fds that nothing else owns.
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
        }

        fn flags(fd: &OwnedFd) -> libc::tcflag_t {
            let mut t = MaybeUninit::<termios>::uninit();
            // SAFETY: `t` is valid for writes; `tcgetattr` fills it when it returns 0.
            assert_eq!(unsafe { tcgetattr(fd.as_raw_fd(), t.as_mut_ptr()) }, 0);
            // SAFETY: `tcgetattr` returned 0, so `t` is initialised.
            unsafe { t.assume_init() }.c_lflag
        }

        fn set_flags(fd: &OwnedFd, lflag: libc::tcflag_t) {
            let mut t = MaybeUninit::<termios>::uninit();
            // SAFETY: as in `flags`.
            assert_eq!(unsafe { tcgetattr(fd.as_raw_fd(), t.as_mut_ptr()) }, 0);
            // SAFETY: `tcgetattr` returned 0, so `t` is initialised.
            let mut t = unsafe { t.assume_init() };
            t.c_lflag = lflag;
            // SAFETY: `t` is a valid termios.
            assert_eq!(unsafe { tcsetattr(fd.as_raw_fd(), TCSANOW, &raw const t) }, 0);
        }

        fn guard_on(slave: &OwnedFd) -> EchoOff {
            EchoOff::on(File::from(slave.try_clone().unwrap())).unwrap()
        }

        #[test]
        fn without_echo_clears_echo_and_echonl_only() {
            // SAFETY: `termios` is plain integers and arrays; all-zero is a valid value.
            let mut t: termios = unsafe { std::mem::zeroed() };
            t.c_lflag = ECHO | ECHONL | ICANON;
            let q = without_echo(t);
            assert_eq!(q.c_lflag, ICANON);
        }

        #[test]
        fn echo_off_changes_a_pty_and_returns_the_old_state() {
            let (_master, slave) = pty();
            let before = flags(&slave);
            assert_ne!(before & ECHO, 0, "pty starts with echo on");
            let orig = echo_off(slave.as_raw_fd()).unwrap();
            assert_eq!(orig.c_lflag, before);
            assert_eq!(flags(&slave), before & !(ECHO | ECHONL));
        }

        #[test]
        fn echo_off_on_a_non_terminal_returns_none() {
            let f = File::open("/dev/null").unwrap();
            assert!(echo_off(f.as_raw_fd()).is_none());
        }

        #[test]
        fn guard_turns_echo_off_and_drop_restores_the_original_flags() {
            let _s = serial();
            let (_master, slave) = pty();
            let before = flags(&slave);
            let guard = guard_on(&slave);
            assert_eq!(flags(&slave), before & !(ECHO | ECHONL));
            drop(guard);
            assert_eq!(flags(&slave), before);
        }

        #[test]
        fn restore_with_a_live_guard_puts_the_flags_back_and_drop_does_not_restore_again() {
            let _s = serial();
            let (_master, slave) = pty();
            let before = flags(&slave);
            let guard = guard_on(&slave);
            restore();
            assert_eq!(flags(&slave), before);
            // A second restore would put `before` back over this.
            let other = before & !ICANON;
            set_flags(&slave, other);
            drop(guard);
            assert_eq!(flags(&slave), other);
        }

        #[test]
        fn restore_without_a_guard_does_nothing() {
            let _s = serial();
            restore();
        }

        #[test]
        fn with_guard_holds_echo_off_while_the_closure_runs() {
            let _s = serial();
            let (_master, slave) = pty();
            let before = flags(&slave);
            let seen = with_guard(Some(guard_on(&slave)), || flags(&slave));
            assert_eq!(seen, before & !(ECHO | ECHONL), "echo must be off inside the closure");
            assert_eq!(flags(&slave), before, "and back on after it");
        }
    }
}
