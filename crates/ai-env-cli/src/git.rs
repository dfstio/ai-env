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
    if let Some(out) = git(repo_root, &["rev-parse", "--git-path", "hooks/pre-commit"]) {
        if out.status.success() {
            let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
            return if p.is_absolute() { p } else { repo_root.join(p) };
        }
    }
    repo_root.join(".git/hooks/pre-commit")
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
