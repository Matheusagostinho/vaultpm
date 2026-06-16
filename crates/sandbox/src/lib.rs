//! A filesystem sandbox for Node.js lifecycle scripts, backed by Linux
//! [Landlock](https://docs.kernel.org/userspace-api/landlock.html).
//!
//! The model is *default-deny*: a sandboxed process may only read/write the
//! paths explicitly granted in the [`Policy`]. Anything not listed — `~/.ssh`,
//! `~/.aws`, `~/.npmrc`, the rest of `$HOME` — is invisible to the script, so a
//! malicious `postinstall` cannot exfiltrate credentials even if it runs.
//!
//! On kernels without Landlock (or non-Linux platforms) the command still runs,
//! but the returned [`Status`] is [`Status::Unavailable`] so callers can warn.
//!
//! This crate intentionally allows `unsafe` (it calls `pre_exec`); it is the one
//! place in the workspace permitted to, and the surface is kept tiny.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// Filesystem grants for a sandboxed process.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Directories/files the process may read (and execute).
    pub read: Vec<PathBuf>,
    /// Directories/files the process may read and write.
    pub write: Vec<PathBuf>,
}

impl Policy {
    /// Grant read (and exec) access to a path.
    pub fn allow_read(&mut self, p: impl Into<PathBuf>) -> &mut Self {
        self.read.push(p.into());
        self
    }
    /// Grant read+write access to a path.
    pub fn allow_write(&mut self, p: impl Into<PathBuf>) -> &mut Self {
        self.write.push(p.into());
        self
    }
}

/// Whether the sandbox was actually enforced for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Landlock restrictions were applied to the child process.
    Enforced,
    /// Landlock is unavailable; the command ran unsandboxed.
    Unavailable,
}

/// Whether Landlock is available on this system.
///
/// Uses the canonical probe from the kernel docs: call
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, which
/// returns the supported ABI version (>= 1) when Landlock is enabled, or fails
/// with `ENOSYS`/`EOPNOTSUPP` otherwise. (Reading `/sys/kernel/security/lsm` is
/// unreliable — that file is often not world-readable.)
pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // __NR_landlock_create_ruleset is 444 on x86_64 and aarch64.
        const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
        const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
        // SAFETY: a pure version query — null ruleset attr, size 0, version flag.
        let ret = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        ret >= 1
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Run `program` with `args` in `cwd`, with the given environment and sandbox
/// policy. Returns the child's exit status and whether the sandbox was enforced.
pub fn run(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    policy: &Policy,
) -> std::io::Result<(ExitStatus, Status)> {
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }

    let enforced = is_available();

    #[cfg(target_os = "linux")]
    {
        if enforced {
            use std::os::unix::process::CommandExt;
            let policy = policy.clone();
            // SAFETY: `enforce` only calls Landlock syscalls and allocates; it
            // does not touch shared mutable state of the parent. It runs in the
            // child between fork and exec.
            unsafe {
                cmd.pre_exec(move || enforce(&policy));
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
    }

    let status = cmd.status()?;
    Ok((
        status,
        if enforced {
            Status::Enforced
        } else {
            Status::Unavailable
        },
    ))
}

#[cfg(target_os = "linux")]
fn enforce(policy: &Policy) -> std::io::Result<()> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
    };

    let abi = ABI::V1;
    let read = AccessFs::from_read(abi);
    let read_write = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(to_io)?
        .create()
        .map_err(to_io)?;

    for p in &policy.read {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read))
                .map_err(to_io)?;
        }
    }
    for p in &policy.write {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_write))
                .map_err(to_io)?;
        }
    }

    ruleset.restrict_self().map_err(to_io)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(format!("landlock: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_builder_collects_paths() {
        let mut p = Policy::default();
        p.allow_read("/usr").allow_write("/tmp/x");
        assert_eq!(p.read, vec![PathBuf::from("/usr")]);
        assert_eq!(p.write, vec![PathBuf::from("/tmp/x")]);
    }

    fn base_system_policy() -> Policy {
        let mut p = Policy::default();
        for dir in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"] {
            p.allow_read(dir);
        }
        p
    }

    #[test]
    fn sandbox_denies_unlisted_path() {
        if !is_available() {
            eprintln!("landlock unavailable — skipping enforcement test");
            return;
        }
        // A "secret" the script must not be able to read.
        let secret_dir = std::env::temp_dir().join(format!("vault-secret-{}", std::process::id()));
        std::fs::create_dir_all(&secret_dir).unwrap();
        let secret = secret_dir.join("token");
        std::fs::write(&secret, b"super-secret").unwrap();

        let read_cmd = vec!["-c".into(), format!("cat {}", secret.display())];

        // Without the secret dir in the policy → read must fail.
        let (denied, status) = run(
            "/bin/sh",
            &read_cmd,
            Path::new("/"),
            &[],
            &base_system_policy(),
        )
        .unwrap();
        assert_eq!(status, Status::Enforced);
        assert!(!denied.success(), "reading an unlisted path must be denied");

        // Granting the secret dir → read succeeds, proving the policy is precise.
        let mut allowed = base_system_policy();
        allowed.allow_read(&secret_dir);
        let (ok, _) = run("/bin/sh", &read_cmd, Path::new("/"), &[], &allowed).unwrap();
        assert!(ok.success(), "an explicitly-granted path must be readable");

        let _ = std::fs::remove_dir_all(&secret_dir);
    }

    #[test]
    fn echo_runs_and_reports_status() {
        // A trivially-allowed command should succeed regardless of enforcement.
        let mut policy = Policy::default();
        policy
            .allow_read("/usr")
            .allow_read("/lib")
            .allow_read("/lib64")
            .allow_read("/bin")
            .allow_read("/etc");
        let (status, _sb) = run(
            "/bin/sh",
            &["-c".into(), "exit 0".into()],
            Path::new("/"),
            &[],
            &policy,
        )
        .expect("spawn");
        assert!(status.success());
    }
}
