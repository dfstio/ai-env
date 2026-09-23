//! clap tree and dispatch for the `ai-env` bin: the classic Touch ID
//! commands plus, behind features, the bridge operator commands and the VM
//! `shim` mode. Moved verbatim from the old `src/main.rs`.

use crate::errors::Result;
use crate::store::Keystore;
use crate::{age_cmd, ceremony, commands, edit};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

fn default_file() -> PathBuf {
    PathBuf::from(".env")
}

#[derive(Parser)]
#[command(
    name = "ai-env",
    version,
    about = "Protect .env files from misconfigured AI agents: the file stays a valid .env, \
             but the secrets are age-encrypted to a Secure Enclave key behind Touch ID",
    after_help = "Encryption never prompts (public-key only). Decryption asks for Touch ID.\n\
        Exit codes: 0 ok, 1 error, 2 usage, 3 cancelled, 4 no/wrong key,\n\
        5 auth unavailable, 6 corrupt file, 7 AWS/infra, 8 VM lost, 9 policy.\n\
        Broken pipes exit 0."
)]
pub struct Cli {
    /// Keystore directory (default: ~/.config/ai-env)
    #[arg(long, global = true, env = "AI_ENV_DIR", value_name = "DIR")]
    key_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Create a named key: Secure Enclave identity + recovery identity ceremony
    Keygen {
        /// Key name, e.g. myproject-devnet (lowercase, digits, dashes)
        name: String,
        /// Authentication required to use the key
        #[arg(long, default_value = "any-biometry-or-passcode")]
        access_control: String,
        /// Name for the Strongbox entry shown during the ceremony
        #[arg(long, value_name = "TEXT")]
        strongbox_entry: Option<String>,
        /// Skip the recovery identity (files die with this Mac — testing only)
        #[arg(long)]
        no_recovery: bool,
    },
    /// Encrypt a .env file IN PLACE (no Touch ID prompt)
    Encrypt {
        /// File to encrypt (default: .env; "-" reads stdin with --stdout implied)
        #[arg(default_value = ".env")]
        file: PathBuf,
        /// Key to encrypt with (default: .ai-env.toml rule, then the default key)
        #[arg(short, long, value_name = "NAME")]
        key: Option<String>,
        /// Write the container to stdout instead of replacing FILE
        #[arg(long)]
        stdout: bool,
        /// Encrypt even with a --no-recovery key
        #[arg(long)]
        force: bool,
    },
    /// Decrypt and print to stdout (ONE Touch ID prompt)
    Show {
        #[arg(default_value = ".env")]
        file: PathBuf,
        /// Key override (normally auto-detected from the file's recipient tag)
        #[arg(short, long, value_name = "NAME")]
        key: Option<String>,
        /// Recovery: decrypt with an age identity FILE instead of the enclave
        #[arg(short = 'i', long, value_name = "FILE")]
        identity: Option<PathBuf>,
    },
    /// Decrypt to a file or back to plaintext in place (Touch ID prompt)
    Decrypt {
        #[arg(default_value = ".env")]
        file: PathBuf,
        /// Output path (default: restore FILE in place, which requires --force)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        #[arg(short, long, value_name = "NAME")]
        key: Option<String>,
        /// Recovery: decrypt with an age identity FILE instead of the enclave
        #[arg(short = 'i', long, value_name = "FILE")]
        identity: Option<PathBuf>,
        /// Confirm in-place plaintext restore / overwrite existing output
        #[arg(long)]
        force: bool,
    },
    /// Run a command with the decrypted variables injected (ONE Touch ID prompt)
    ///
    /// Secrets travel only in the child's environment — never argv, never disk.
    Run {
        /// Encrypted env file (default: .env)
        #[arg(long, short = 'f', value_name = "FILE", default_value = ".env")]
        file: PathBuf,
        #[arg(short, long, value_name = "NAME")]
        key: Option<String>,
        #[arg(short = 'i', long, value_name = "FILE")]
        identity: Option<PathBuf>,
        /// The command to run (everything after --)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Edit an encrypted .env in a secure form (ONE Touch ID prompt);
    /// values stay sealed in memory, at most one revealed at a time
    Edit {
        #[arg(default_value = ".env")]
        file: PathBuf,
        /// Key override (normally auto-detected from the file's recipient tag)
        #[arg(short, long, value_name = "NAME")]
        key: Option<String>,
        /// Recovery: open with an age identity FILE instead of the enclave
        #[arg(short = 'i', long, value_name = "FILE")]
        identity: Option<PathBuf>,
        /// Allow running inside tmux/screen (their servers keep a copy of the screen)
        #[arg(long)]
        insecure_terminal: bool,
    },
    /// Which key opens this file? (no prompt, no decryption)
    Which {
        #[arg(default_value = ".env")]
        file: PathBuf,
    },
    /// Inspect an encrypted file's header (no prompt)
    Info {
        #[arg(default_value = ".env")]
        file: PathBuf,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Manage keys
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Re-encrypt every ai-env container under DIR to its key's current recipients
    Rekey {
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// List what would be re-encrypted, change nothing
        #[arg(long)]
        dry_run: bool,
        /// Proceed even for more than 10 files (one Touch ID prompt each)
        #[arg(long)]
        yes: bool,
    },
    /// Quarterly drill: prove the Strongbox recovery identity still works
    VerifyRecovery {
        /// Key name
        name: String,
    },
    /// Check age, the plugin, the keystore, and the current directory's .env
    /// (exit 1 when any row is [NO ], 5 when credentials are unavailable)
    Doctor {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Run the G1–G8 pre-code gates of the MicroVM bridge and write plans/gates.md
    #[cfg(feature = "bridge")]
    Gates {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
        /// Write the table to FILE instead of <repo>/plans/gates.md
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Run only these gates (comma-separated, e.g. G1,G3); the file is not rewritten
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
    /// Cursor wrapper: install the claudeProcessWrapper setting, inspect the invocation census
    #[cfg(feature = "bridge")]
    Wrapper {
        #[command(subcommand)]
        cmd: WrapperCmd,
    },
    /// VM mode: the MicroVM image entrypoint (PID 1); also runs natively for tests
    #[cfg(feature = "shim")]
    Shim(crate::shim::ShimArgs),
}

/// `ai-env wrapper …` (feature `bridge`): the two S1 operator commands.
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum WrapperCmd {
    /// Point Cursor's claudeCode.claudeProcessWrapper at the sibling ai-env-claude (dry run unless --write; backs up settings.json)
    Install {
        /// Edit settings.json (default: a dry run that prints the snippet)
        #[arg(long)]
        write: bool,
        /// claudeCode.initialPermissionMode to write: default, manual, acceptEdits, plan or bypassPermissions
        /// (default: [wrapper].initial_permission_mode from bridge.toml, else default)
        #[arg(long, value_name = "M")]
        permission_mode: Option<String>,
    },
    /// Print the invocation census (logs/census.jsonl); --record-probes writes the entrypoint/stock-ext-oauth verdicts to lab/probes.jsonl
    Census {
        /// Only the last N rows
        #[arg(long, value_name = "N")]
        last: Option<usize>,
        /// Raw JSON lines instead of the text table
        #[arg(long)]
        json: bool,
        /// Derive the S1 probe verdicts from the newest session row and append them to lab/probes.jsonl
        /// (exit 1 when a verdict differs from its expectation; the rows are written first)
        #[arg(long)]
        record_probes: bool,
    },
}

#[derive(Subcommand)]
pub enum KeysCmd {
    /// List keys with policy and recovery status
    List,
    /// Show one key's details and public recipients
    Show { name: String },
    /// Set the default key
    Default { name: String },
    /// Add a public recipient (e.g. a server's age key) to a named key
    AddRecipient {
        /// Key name
        name: String,
        /// The PUBLIC recipient (age1…, from `age-keygen -y`) — never the
        /// AGE-SECRET-KEY private half
        recipient: String,
        /// Note stored beside the recipient in recipients.txt
        #[arg(long, value_name = "TEXT")]
        label: Option<String>,
        /// Also re-encrypt this key's existing containers under DIR
        /// (one Touch ID prompt per file)
        #[arg(long, value_name = "DIR")]
        rekey: Option<PathBuf>,
        /// Skip the >10-files confirmation for --rekey
        #[arg(long)]
        yes: bool,
    },
    /// Recreate a key from its Strongbox recovery identity (new SE key;
    /// optionally re-encrypt existing files to it)
    Restore {
        /// Key name (may reuse a forgotten key's name)
        name: String,
        /// Authentication required to use the new key
        #[arg(long, default_value = "any-biometry-or-passcode")]
        access_control: String,
        /// Name of the Strongbox entry (informational)
        #[arg(long, value_name = "TEXT")]
        strongbox_entry: Option<String>,
        /// After restoring, re-encrypt every container under DIR that the
        /// pasted identity opens (no Touch ID prompts). If the key already
        /// exists, only this sweep runs — no new key is created
        #[arg(long, value_name = "DIR")]
        rekey: Option<PathBuf>,
        /// Generate a FRESH recovery identity (full ceremony) instead of
        /// keeping the pasted one — for suspected-compromise restores
        #[arg(long)]
        new_recovery: bool,
    },
    /// Remove a key's LOCAL files (the enclave key is orphaned forever)
    Forget {
        name: String,
        /// Confirm
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(cli: Cli) -> Result<()> {
    // The VM entrypoint runs as PID 1 with a bare environment: it must never
    // depend on `HOME` or a keystore directory.
    #[cfg(feature = "shim")]
    if let Cmd::Shim(args) = cli.cmd {
        return crate::shim::run(args);
    }
    let store = Keystore::resolve(cli.key_dir)?;
    match cli.cmd {
        Cmd::Keygen { name, access_control, strongbox_entry, no_recovery } => {
            let age = age_cmd::AgeTool::probe()?;
            ceremony::keygen(
                &store,
                &age,
                &ceremony::KeygenOpts { name, access_control, strongbox_entry, no_recovery },
            )
        }
        Cmd::Encrypt { file, key, stdout, force } => {
            let age = age_cmd::AgeTool::probe()?;
            let stdout = stdout || file == std::path::Path::new("-");
            commands::encrypt(&store, &age, &commands::EncryptOpts { file, key, stdout, force })
        }
        Cmd::Show { file, key, identity } => {
            let age = age_cmd::AgeTool::probe()?;
            commands::show(
                &store,
                &age,
                &commands::DecryptOpts { file, output: None, key, identity, force: false },
            )
        }
        Cmd::Decrypt { file, output, key, identity, force } => {
            let age = age_cmd::AgeTool::probe()?;
            commands::decrypt(
                &store,
                &age,
                &commands::DecryptOpts { file, output, key, identity, force },
            )
        }
        Cmd::Run { file, key, identity, command } => {
            let age = age_cmd::AgeTool::probe()?;
            commands::run(&store, &age, &commands::RunOpts { file, key, identity, command })
        }
        Cmd::Edit { file, key, identity, insecure_terminal } => {
            let age = age_cmd::AgeTool::probe()?;
            edit::run_edit(&store, &age, &edit::EditOpts { file, key, identity, insecure_terminal })
        }
        Cmd::Which { file } => commands::which(&store, &file),
        Cmd::Info { file, json } => commands::info(&store, &file, json),
        Cmd::Keys { cmd } => match cmd {
            KeysCmd::List => commands::keys_list(&store),
            KeysCmd::Show { name } => commands::keys_show(&store, &name),
            KeysCmd::Default { name } => commands::keys_default(&store, &name),
            KeysCmd::AddRecipient { name, recipient, label, rekey, yes } => {
                let age = age_cmd::AgeTool::probe()?;
                commands::keys_add_recipient(
                    &store,
                    &age,
                    &name,
                    &recipient,
                    label.as_deref(),
                    rekey.as_deref(),
                    yes,
                )
            }
            KeysCmd::Restore { name, access_control, strongbox_entry, rekey, new_recovery } => {
                let age = age_cmd::AgeTool::probe()?;
                ceremony::restore(
                    &store,
                    &age,
                    &ceremony::RestoreOpts { name, access_control, strongbox_entry, rekey, new_recovery },
                )
            }
            KeysCmd::Forget { name, yes } => commands::keys_forget(&store, &name, yes),
        },
        Cmd::Rekey { dir, dry_run, yes } => {
            let age = age_cmd::AgeTool::probe()?;
            commands::rekey(&store, &age, &dir, dry_run, yes)
        }
        Cmd::VerifyRecovery { name } => {
            let age = age_cmd::AgeTool::probe()?;
            commands::verify_recovery(&store, &age, &name)
        }
        Cmd::Doctor { json } => doctor(&store, &default_file(), json),
        #[cfg(feature = "bridge")]
        Cmd::Gates { json, out, only } => crate::bridge::gates::main(json, out, only),
        #[cfg(feature = "bridge")]
        Cmd::Wrapper { cmd } => match cmd {
            WrapperCmd::Install { write, permission_mode } => crate::bridge::wrapper::install(write, permission_mode),
            WrapperCmd::Census { last, json, record_probes } => crate::bridge::wrapper::census(last, json, record_probes),
        },
        #[cfg(feature = "shim")]
        Cmd::Shim(_) => unreachable!("shim is dispatched before the keystore is resolved"),
    }
}

/// `ai-env doctor`: the classic rows, plus the bridge rows when built with
/// the `bridge` feature. Exit 1 on any `[NO ]`, 5 when credentials are
/// unavailable, else 0.
fn doctor(store: &Keystore, file: &std::path::Path, json: bool) -> Result<()> {
    #[allow(unused_mut)]
    let mut lines = commands::doctor_lines(store, file)?;
    let auth_unavailable = {
        #[cfg(feature = "bridge")]
        {
            let bridge = crate::bridge::doctor::rows(store);
            lines.extend(bridge.lines);
            bridge.auth_unavailable
        }
        #[cfg(not(feature = "bridge"))]
        {
            false
        }
    };
    commands::doctor_report(&lines, json, auth_unavailable)
}
