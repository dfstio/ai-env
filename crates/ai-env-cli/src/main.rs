//! `ai-env` — encrypted `.env` files that stay `.env`, unlocked by Touch ID.
mod age_cmd;
mod ceremony;
mod commands;
mod config;
mod container;
mod dotenv;
mod edit;
mod errors;
mod git;
mod select;
mod store;

use clap::{Parser, Subcommand};
use errors::Result;
use std::path::PathBuf;
use store::Keystore;

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
        5 auth unavailable, 6 corrupt file. Broken pipes exit 0."
)]
struct Cli {
    /// Keystore directory (default: ~/.config/ai-env)
    #[arg(long, global = true, env = "AI_ENV_DIR", value_name = "DIR")]
    key_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
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
    Doctor,
}

#[derive(Subcommand)]
enum KeysCmd {
    /// List keys with policy and recovery status
    List,
    /// Show one key's details and public recipients
    Show { name: String },
    /// Set the default key
    Default { name: String },
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
        /// pasted identity opens (no Touch ID prompts)
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

fn run(cli: Cli) -> Result<()> {
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
        Cmd::Doctor => commands::doctor(&store, &default_file()),
    }
}

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => {}
        Err(e) => {
            let code = e.exit_code();
            if code != 0 {
                eprintln!("ai-env: {e}");
            }
            std::process::exit(code);
        }
    }
}
