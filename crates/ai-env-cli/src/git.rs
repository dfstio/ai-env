//! Git integration — advisory and PROMPTED, never automatic.
//!
//! An encrypted `.env` is safe (and useful) to commit, but existing repos
//! usually carry a bare `.env*` ignore rule that silently keeps it untracked
//! — leaving its only copies on this Mac. When `encrypt` detects that, it
//! offers (on a TTY) or prints instructions (non-interactive) to:
//!  * append a `!.env` negation to .gitignore, and
//!  * install a pre-commit hook refusing any staged .env WITHOUT the
//!    AI_ENV=1 marker — mandatory alongside the negation, so a later
//!    plaintext .env can never slip into history through it.
use crate::errors::Result;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const HOOK_MARK: &str = "# ai-env pre-commit guard";
const HOOK_BODY: &str = "#!/bin/sh\n\
# ai-env pre-commit guard\n\
# Refuse to commit any .env-like file that is not an ai-env container.\n\
# --diff-filter=d: skip staged DELETIONS (nothing to inspect, and `git show`\n\
# would fail on them). Templates (.env.example etc.) are exempt.\n\
git diff --cached --name-only --diff-filter=d | while IFS= read -r f; do\n\
  case \"$(basename \"$f\")\" in\n\
    *.example|*.sample|*.template|*.dist) continue;;\n\
  esac\n\
  case \"$(basename \"$f\")\" in\n\
    .env|.env.*|*.env)\n\
      if git show \":$f\" | head -32 | grep -q '^AI_ENV=1'; then :; else\n\
        echo \"pre-commit: $f looks like a PLAINTEXT env file - refusing.\" >&2\n\
        echo \"encrypt it first:  ai-env encrypt $f\" >&2\n\
        exit 1\n\
      fi\n\
      ;;\n\
  esac\n\
done\n\
# the while runs in a subshell; propagate its exit status\n\
exit $?\n";

fn git(repo_dir: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("git").arg("-C").arg(repo_dir).args(args).output().ok()
}

pub struct GitContext {
    pub repo_root: PathBuf,
    pub file_ignored: bool,
    pub ignore_rule: Option<String>,
    pub hook_installed: bool,
}

/// Inspect the repository around `file` (None when not in a git work tree).
pub fn inspect(file: &Path) -> Option<GitContext> {
    // A bare relative name like ".env" has an EMPTY parent — that means the
    // current directory, not "no directory".
    let dir = match file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let root = git(&dir, &["rev-parse", "--show-toplevel"])?;
    if !root.status.success() {
        return None;
    }
    let repo_root = PathBuf::from(String::from_utf8_lossy(&root.stdout).trim());
    let name = file.file_name()?.to_string_lossy().into_owned();
    let check = git(&dir, &["check-ignore", "-v", "--", &name])?;
    let file_ignored = check.status.success();
    let ignore_rule = file_ignored
        .then(|| String::from_utf8_lossy(&check.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    // Respect core.hooksPath (git only runs hooks from there when set).
    let hook = hooks_pre_commit_path(&repo_root);
    let hook_installed = std::fs::read_to_string(&hook)
        .map(|t| t.contains(HOOK_MARK))
        .unwrap_or(false);
    Some(GitContext { repo_root, file_ignored, ignore_rule, hook_installed })
}

/// Where git will actually look for the pre-commit hook (honors core.hooksPath).
fn hooks_pre_commit_path(repo_root: &Path) -> PathBuf {
    hook_path(repo_root, "pre-commit")
}

/// Where git runs the hook `name` of the repository at `repo_root` (honours
/// `core.hooksPath`): `rev-parse --git-path hooks/<name>` through this
/// module's plain `git` (never `gitrun::GitRun`, whose `core.hooksPath=/dev/null`
/// would answer `/dev/null/<name>`), relative to `repo_root`; when git cannot
/// answer, `<repo_root>/.git/hooks/<name>`. S9's pre-push hook
/// (`bridge::review`) and the pre-commit guard share it.
#[must_use]
pub fn hook_path(repo_root: &Path, name: &str) -> PathBuf {
    if let Some(out) = git(repo_root, &["rev-parse", "--git-path", &format!("hooks/{name}")]) {
        if out.status.success() {
            let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
            return if p.is_absolute() { p } else { repo_root.join(p) };
        }
    }
    repo_root.join(".git/hooks").join(name)
}

/// How much of a hook file [`install_hook`] reads for its mark (as
/// `bridge::review::hook_state` does).
const HOOK_HEAD_READ: u64 = 4096;

/// What [`install_hook`] found at a hook's path, and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookInstall {
    /// Nothing was there: the body is written (0755).
    Installed,
    /// A hook carrying the mark was there: kept as it is, or, when asked to
    /// replace it and its text was not the body or its mode not 0755,
    /// rewritten.
    Marked { rewritten: bool },
    /// Something else is there (a file without the mark, a directory, a
    /// link to nothing): never written over.
    Foreign,
}

/// Install the hook `body` at `path` (where git runs it: [`hook_path`])
/// unless another hook is there (S9 factors it out of [`apply_fix`]'s
/// pre-commit guard for the pre-push review hook, `ai-env box
/// hook-install`). Nothing at `path`: `body` is written. A regular file
/// (a link to one counts) carrying `mark` on a line of its own in its
/// first 4 KiB is ours: kept, or with `replace` rewritten when its text is
/// not `body` or its mode is not 0755 (git skips a hook it cannot execute,
/// whatever its bytes). Anything else is foreign and never touched: it may
/// end with `exit`, use another interpreter, or otherwise never reach
/// appended code.
/// A write makes the hooks directory, then renames a 0755 temporary file
/// beside `path` over it: a hook is never seen half written, and a link at
/// `path` is replaced, never written through.
pub fn install_hook(path: &Path, body: &str, mark: &str, replace: bool) -> std::io::Result<HookInstall> {
    use std::io::Read as _;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_hook(path, body)?;
            return Ok(HookInstall::Installed);
        }
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return Ok(HookInstall::Foreign);
    }
    let mut head = Vec::new();
    std::fs::File::open(path)?.take(HOOK_HEAD_READ).read_to_end(&mut head)?;
    if !String::from_utf8_lossy(&head).lines().any(|l| l.trim_end() == mark) {
        return Ok(HookInstall::Foreign);
    }
    if !replace || (std::fs::read(path)? == body.as_bytes() && is_mode_0755(path)?) {
        return Ok(HookInstall::Marked { rewritten: false });
    }
    write_hook(path, body)?;
    Ok(HookInstall::Marked { rewritten: true })
}

/// Whether the file at `path` (through a link) has the mode a hook is
/// written with, 0755.
pub fn is_mode_0755(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt as _;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o777 == 0o755)
}

/// `body` at `path`, 0755, through a temporary file in its directory
/// (made first) renamed over it; the temporary file goes on any failure.
fn write_hook(path: &Path, body: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&dir)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.ai-env-{}.tmp", std::process::id()));
    let written = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o755).open(&tmp)?;
        f.write_all(body.as_bytes())?;
        // The mode the umask left aside: a hook git cannot execute never runs.
        f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Append the `!NAME` negation and install the pre-commit hook. Only called
/// after an explicit yes on a TTY.
pub fn apply_fix(ctx: &GitContext, file_name: &str) -> Result<()> {
    let gitignore = ctx.repo_root.join(".gitignore");
    let mut text = std::fs::read_to_string(&gitignore).unwrap_or_default();
    let negation = format!("!{file_name}");
    if !text.lines().any(|l| l.trim() == negation) {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!(
            "# ai-env: the encrypted {file_name} is ciphertext and SHOULD be committed\n{negation}\n"
        ));
        std::fs::write(&gitignore, text)?;
    }
    let hook_path = hooks_pre_commit_path(&ctx.repo_root);
    if let Some(parent) = hook_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::read_to_string(&hook_path) {
        Ok(existing) if existing.contains(HOOK_MARK) => {} // already installed
        Ok(_) => {
            // NEVER modify a foreign hook: it may end with `exit`, use a
            // different interpreter, or otherwise never reach appended code.
            use std::io::Write as _;
            let mut err = std::io::stderr().lock();
            writeln!(
                err,
                "warning: a pre-commit hook already exists at {} — leaving it untouched. \
                 To add the ai-env guard, merge this check into it manually:\n  \
                 git show :FILE | head -32 | grep -q '^AI_ENV=1' || exit 1",
                hook_path.display()
            )?;
        }
        Err(_) => {
            std::fs::write(&hook_path, HOOK_BODY)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
            }
        }
    }
    Ok(())
}

/// After an in-place encrypt: warn/offer the git fix, print the honest
/// rotate-don't-scrub notice.
pub fn post_encrypt_advice(file: &Path) -> Result<()> {
    let mut err = std::io::stderr().lock();
    if let Some(ctx) = inspect(file) {
        let name = file.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if ctx.file_ignored {
            writeln!(
                err,
                "note: {} is gitignored ({}) — the ENCRYPTED file is safe to commit, and \
                 committing it is what backs it up.",
                name,
                ctx.ignore_rule.as_deref().unwrap_or("matched an ignore rule"),
            )?;
            if is_tty() && ask_yes_no(&format!(
                "add `!{name}` to .gitignore and install the ai-env pre-commit guard \
                 (refuses plaintext .env commits)? [y/N] "
            ))? {
                apply_fix(&ctx, &name)?;
                writeln!(err, "updated .gitignore and .git/hooks/pre-commit")?;
            } else {
                writeln!(
                    err,
                    "to do it later: echo '!{name}' >> .gitignore   (ai-env will also \
                     install a pre-commit guard next time you accept)"
                )?;
            }
        }
    }
    writeln!(
        err,
        "note: the previous PLAINTEXT may survive in APFS snapshots, Time Machine, git \
         history, or editor backups — treat any secret that was ever plaintext on this \
         disk as still exposed until rotated."
    )?;
    Ok(())
}

fn is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn ask_yes_no(prompt: &str) -> Result<bool> {
    use std::io::BufRead;
    let mut err = std::io::stderr().lock();
    err.write_all(prompt.as_bytes())?;
    err.flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

#[cfg(test)]
mod hook_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const MARK: &str = "# ai-env test hook";

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The pre-commit guard `apply_fix` installs stays byte for byte what it
    /// was before S9 factored `install_hook` out beside it.
    #[test]
    fn the_pre_commit_guard_is_byte_identical() {
        use sha2::{Digest, Sha256};
        assert!(HOOK_BODY.starts_with("#!/bin/sh\n# ai-env pre-commit guard\n") && HOOK_BODY.ends_with("exit $?\n"));
        assert_eq!(hex::encode(Sha256::digest(HOOK_BODY.as_bytes())), "1b0a9f4a5d7795336d8e5ac28c0fb41ef8b6d66c2e7b15ce5f666b07b72dd32c");
    }

    /// Nothing there: written, 0755, through no temporary file left behind;
    /// ours (the mark on a line of its own): kept, or rewritten when asked
    /// and different or no longer 0755; anything else, never touched: a
    /// file without the mark, the mark past the first 4 KiB, a directory, a
    /// dangling link.
    #[test]
    fn install_hook_writes_only_where_nothing_or_its_own_hook_is() {
        let tmp = tempfile::tempdir().unwrap();
        let hook = tmp.path().join("hooks").join("pre-push");
        let body = format!("#!/bin/sh\n{MARK}\nexit 0\n");
        assert_eq!(install_hook(&hook, &body, MARK, true).unwrap(), HookInstall::Installed);
        assert_eq!(std::fs::read_to_string(&hook).unwrap(), body);
        assert_eq!(mode(&hook), 0o755);
        assert_eq!(std::fs::read_dir(hook.parent().unwrap()).unwrap().count(), 1, "no temporary file is left");
        assert_eq!(install_hook(&hook, &body, MARK, true).unwrap(), HookInstall::Marked { rewritten: false });
        let newer = format!("#!/bin/sh\n{MARK}\nexit 1\n");
        assert_eq!(install_hook(&hook, &newer, MARK, false).unwrap(), HookInstall::Marked { rewritten: false });
        assert_eq!(std::fs::read_to_string(&hook).unwrap(), body, "kept unless asked to replace");
        assert_eq!(install_hook(&hook, &newer, MARK, true).unwrap(), HookInstall::Marked { rewritten: true });
        assert_eq!(std::fs::read_to_string(&hook).unwrap(), newer);
        // The body, but no longer executable: git would skip it, so it is rewritten 0755.
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_mode_0755(&hook).unwrap());
        assert_eq!(install_hook(&hook, &newer, MARK, false).unwrap(), HookInstall::Marked { rewritten: false }, "kept unless asked to replace");
        assert_eq!(install_hook(&hook, &newer, MARK, true).unwrap(), HookInstall::Marked { rewritten: true });
        assert_eq!((std::fs::read_to_string(&hook).unwrap(), mode(&hook)), (newer.clone(), 0o755));
        assert_eq!(install_hook(&hook, &newer, MARK, true).unwrap(), HookInstall::Marked { rewritten: false });
        for foreign in ["#!/bin/sh\n# someone's own hook\nexit 0\n".to_string(), format!("#!/bin/sh\n# {MARK} inside a line\n"), format!("#!/bin/sh\n{}\n{MARK}\n", "#".repeat(5000))] {
            std::fs::write(&hook, &foreign).unwrap();
            assert_eq!(install_hook(&hook, &body, MARK, true).unwrap(), HookInstall::Foreign);
            assert_eq!(std::fs::read_to_string(&hook).unwrap(), foreign);
        }
        std::fs::remove_file(&hook).unwrap();
        std::fs::create_dir(&hook).unwrap();
        assert_eq!(install_hook(&hook, &body, MARK, true).unwrap(), HookInstall::Foreign);
        std::fs::remove_dir(&hook).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("nowhere"), &hook).unwrap();
        assert_eq!(install_hook(&hook, &body, MARK, true).unwrap(), HookInstall::Foreign);
        assert!(!tmp.path().join("nowhere").exists(), "never written through a link");
    }

    /// A link to a hook of ours is replaced by the new body; the file it
    /// pointed at stays as it was.
    #[test]
    fn install_hook_replaces_a_link_never_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let (target, hook) = (tmp.path().join("shared-hook"), tmp.path().join("pre-push"));
        let old = format!("#!/bin/sh\n{MARK}\nexit 0\n");
        std::fs::write(&target, &old).unwrap();
        std::os::unix::fs::symlink(&target, &hook).unwrap();
        let body = format!("#!/bin/sh\n{MARK}\nexit 1\n");
        assert_eq!(install_hook(&hook, &body, MARK, true).unwrap(), HookInstall::Marked { rewritten: true });
        assert!(!std::fs::symlink_metadata(&hook).unwrap().file_type().is_symlink());
        assert_eq!((std::fs::read_to_string(&hook).unwrap(), std::fs::read_to_string(&target).unwrap()), (body, old));
    }

    /// `hook_path` answers where git runs a hook: `.git/hooks`, or
    /// `core.hooksPath` (relative to the repository's top level).
    #[test]
    fn hook_path_follows_core_hooks_path() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = std::fs::canonicalize(tmp.path()).unwrap();
        let git = |args: &[&str]| assert!(Command::new("git").args(args).current_dir(&repo).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap().status.success());
        git(&["init", "-q"]);
        git(&["config", "core.hooksPath", ".git/hooks"]);
        assert_eq!(hook_path(&repo, "pre-push"), repo.join(".git/hooks/pre-push"));
        git(&["config", "core.hooksPath", "githooks"]);
        assert_eq!(hook_path(&repo, "pre-push"), repo.join("githooks/pre-push"));
    }
}
