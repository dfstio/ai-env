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
    /// Sessions the wrapper registered (state/sessions/*.toml): list, show, forget
    #[cfg(feature = "bridge")]
    Session {
        #[command(subcommand)]
        cmd: SessionCmd,
    },
    /// MicroVM infrastructure: image scan, claude pin, stack outputs → bridge.toml, base image, version diffs
    #[cfg(feature = "bridge")]
    Infra {
        #[command(subcommand)]
        cmd: InfraCmd,
    },
    /// Bridge credentials sealed under the bridge keystore key (credentials/*.env)
    #[cfg(feature = "bridge")]
    Creds {
        #[command(subcommand)]
        cmd: CredsCmd,
    },
    /// MicroVMs of the ai-env image: images, run, list, status, health, token, suspend, resume, terminate, gc, shell, smoke
    #[cfg(feature = "bridge")]
    Vm {
        #[command(subcommand)]
        cmd: VmCmd,
    },
    /// Platform probes (lab/probes.jsonl): list, show, run
    #[cfg(feature = "bridge")]
    Lab {
        #[command(subcommand)]
        cmd: LabCmd,
    },
    /// VM mode: the MicroVM image entrypoint (PID 1); also runs natively for tests
    #[cfg(feature = "shim")]
    Shim(crate::shim::ShimArgs),
}

/// `--egress` of `ai-env vm run`.
#[cfg(feature = "bridge")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum EgressArg {
    /// The platform default (INTERNET_EGRESS); audited. Only for VMs that never receive a credential
    Internet,
    /// [aws].egress_connector_arn (S5); exit 9 when none is configured
    Vpc,
}

/// `--auth` of `ai-env vm shell`.
#[cfg(feature = "bridge")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ShellAuthArg {
    /// x-aws-proxy-auth + x-aws-proxy-port headers (default)
    Header,
    /// The documented subprotocol form (fails when the proxy echoes no subprotocol)
    Subprotocol,
}

/// `ai-env vm …` (feature `bridge`): the MicroVM lifecycle (plan S4 §6). Every
/// command unseals the runtime key (one Touch ID) once its flags passed.
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum VmCmd {
    /// The image, its versions (state, status, memory) and the one `vm run` uses
    Images {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
        /// List the managed base images instead
        #[arg(long)]
        managed: bool,
    },
    /// Start a MicroVM (or reuse the workspace's), wait until RUNNING, record it in state/vms
    Run {
        /// Image ARN (default: [aws].image_arn)
        #[arg(long, value_name = "ARN")]
        image: Option<String>,
        /// Image version: N, N.M or active (default: [aws].image_version)
        #[arg(long, value_name = "V")]
        version: Option<String>,
        /// Maximum duration in seconds, running + suspended (default: [vm].max_duration_s)
        #[arg(long, value_name = "S", value_parser = clap::value_parser!(u32).range(1..=28_800))]
        max_duration: Option<u32>,
        /// Suspend after this many idle seconds (>= 300; default: [vm].max_idle_s)
        #[arg(long, value_name = "S")]
        idle: Option<u32>,
        /// Terminate after this many seconds suspended (<= max duration; default: min([vm].suspended_s, max duration))
        #[arg(long, value_name = "S")]
        suspended: Option<u32>,
        /// Do not resume automatically on the next request
        #[arg(long)]
        no_auto_resume: bool,
        /// Egress: internet (audited) or vpc (default: vpc when [aws].egress_connector_arn is set)
        #[arg(long, value_enum)]
        egress: Option<EgressArg>,
        /// Workspace directory (under [workspaces].roots): locks it and reuses its VM
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
        /// Start a new VM even when the workspace has one
        #[arg(long, requires = "workspace")]
        new: bool,
        /// A label stored in the row
        #[arg(long, value_name = "TEXT")]
        label: Option<String>,
        /// Also attach the SHELL_INGRESS connector (for `vm shell`)
        #[arg(long)]
        shell: bool,
        /// Do not pass [aws].execution_role_arn (no runtime logs)
        #[arg(long)]
        no_execution_role: bool,
        /// Return once RunMicrovm answered (do not wait for RUNNING)
        #[arg(long)]
        no_wait: bool,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// VMs of the image (ListMicrovms) joined with state/vms; TERMINATED hidden without --all
    List {
        /// Include TERMINATED VMs and terminated rows
        #[arg(long)]
        all: bool,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// GetMicrovm of one VM (state, reason, idle policy, connectors); refreshes its row
    Status {
        /// MicroVM id
        id: String,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// GET /health through the endpoint (a 5-minute Port(8080) token)
    Health {
        /// MicroVM id
        id: String,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Mint an endpoint token for one port; the value is printed only with --reveal
    Token {
        /// MicroVM id
        id: String,
        /// Port the token is scoped to: 8080, 8082 or 9418
        #[arg(long, default_value_t = 8080)]
        port: u16,
        /// Lifetime in minutes
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u16).range(1..=60))]
        minutes: u16,
        /// Print the token value (alone, on stdout)
        #[arg(long)]
        reveal: bool,
    },
    /// Suspend a RUNNING VM and wait until SUSPENDED
    Suspend {
        /// MicroVM id
        id: String,
        /// Do not wait
        #[arg(long)]
        no_wait: bool,
    },
    /// Resume a SUSPENDED VM and wait until RUNNING
    Resume {
        /// MicroVM id
        id: String,
        /// Do not wait
        #[arg(long)]
        no_wait: bool,
    },
    /// Terminate one VM, or --all of yours (rows + own orphans)
    Terminate {
        /// MicroVM id
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        id: Option<String>,
        /// Every VM you started (registry rows and your own orphans; never another owner's)
        #[arg(long)]
        all: bool,
        /// Confirm (needed for --all and for a VM without a row)
        #[arg(long)]
        yes: bool,
        /// Do not wait for TERMINATED
        #[arg(long)]
        no_wait: bool,
    },
    /// Reconcile ListMicrovms with state/vms: report (default), --yes acts on registry VMs, --include-orphans also on your own orphans
    Gc {
        /// Act (terminate expired registry VMs, adopt, clear stale rows)
        #[arg(long)]
        yes: bool,
        /// Also terminate your own orphans older than AGE (90s, 30m, 1h, 2d)
        #[arg(long, value_name = "AGE", requires = "yes")]
        include_orphans: Option<String>,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Interactive shell in the VM host (experimental; the VM needs `vm run --shell`)
    Shell {
        /// MicroVM id
        id: String,
        /// Shell token lifetime in minutes
        #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u16).range(1..=60))]
        minutes: u16,
        /// How the token is presented
        #[arg(long, value_enum, default_value_t = ShellAuthArg::Header)]
        auth: ShellAuthArg,
    },
    /// T4.1: run → RUNNING → token → /health → terminate → TERMINATED, with timings
    Smoke {
        /// Maximum duration of the smoke VM in seconds
        #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u32).range(60..=28_800))]
        max_duration: u32,
        /// Do not pass [aws].execution_role_arn
        #[arg(long)]
        no_execution_role: bool,
        /// Leave the VM running
        #[arg(long)]
        keep: bool,
        /// One JSON record on stdout (the step lines go to stderr)
        #[arg(long)]
        json: bool,
    },
}

/// `ai-env lab …` (feature `bridge`): the probe records (plan §7, S4 §8).
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum LabCmd {
    /// Every probe with its expectation and last recorded verdict
    List {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// The recorded rows of one probe
    Show {
        /// Probe name (ai-env lab list)
        probe: String,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Run a probe and append its verdict to lab/probes.jsonl (exit 1 after writing when it misses the expectation)
    Run {
        /// Probe name (ai-env lab list)
        probe: String,
        /// MicroVM id (cloudtrail-payload)
        id: Option<String>,
        /// Derive the verdict from this runtime log (`make logs SINCE=30m > FILE`), or for cloudtrail-payload from a trail's gunzipped CloudTrail log file
        #[arg(long, value_name = "FILE")]
        log: Option<PathBuf>,
        /// Record this verdict by hand (what you observed)
        #[arg(long, value_name = "VERDICT", conflicts_with = "log")]
        manual: Option<String>,
        /// A note stored with the row
        #[arg(long, value_name = "TEXT")]
        note: Option<String>,
    },
}

/// `ai-env infra …` (feature `bridge`): the S3 infrastructure helpers the Makefile drives.
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum InfraCmd {
    /// Scan a directory (the staged image tree) for secrets and unsafe Claude settings; exit 9 on any finding
    Scan {
        /// Directory to scan
        dir: PathBuf,
        /// Rule profile: image (tripwires + the baked-settings rules) or repo (tripwires only)
        #[arg(long, value_enum, default_value_t = crate::bridge::scan::Profile::Image)]
        profile: crate::bridge::scan::Profile,
        /// Extra tripwire patterns, one per line (default: [review].tripwires when that file exists)
        #[arg(long, value_name = "FILE")]
        tripwires: Option<PathBuf>,
        /// Allowed settings.json permission entries, one `allow <entry>` per line (default: [review].settings_policy when that file exists)
        #[arg(long, value_name = "FILE")]
        settings_policy: Option<PathBuf>,
        /// Machine-readable findings
        #[arg(long)]
        json: bool,
    },
    /// Write image/claude.lock from a release manifest.json, print it, or compare it with the installed Cursor bundle
    Pin {
        /// Release manifest.json to pin from (downloaded and signature-checked by `make claude-pin`)
        #[arg(long, value_name = "FILE", conflicts_with = "check_bundle")]
        manifest: Option<PathBuf>,
        /// The lock file to write or read
        #[arg(long, value_name = "FILE", default_value = "image/claude.lock")]
        lock: PathBuf,
        /// Exit 1 unless the lock's version equals the installed Cursor extension bundle's
        #[arg(long)]
        check_bundle: bool,
        /// With --manifest: refuse a manifest whose version is not this one (lock not written)
        #[arg(long, value_name = "V", requires = "manifest")]
        expect_version: Option<String>,
    },
    /// Read the Pulumi stack outputs plus one live read-only get-microvm-image, and show (or --write) the bridge.toml [aws] table and state/infra.toml
    Status {
        /// Edit bridge.toml [aws] in place (backup first) and write state/infra.toml
        #[arg(long)]
        write: bool,
        /// Read the outputs from FILE instead of `pulumi stack output --json` (tests; the live get-microvm-image read still runs, so tests put a fake aws first on PATH)
        #[arg(long, value_name = "FILE", hide = true)]
        json_in: Option<PathBuf>,
        /// Pulumi stack
        #[arg(long, default_value = "dev")]
        stack: String,
        /// Pulumi project directory
        #[arg(long, value_name = "DIR", default_value = "infra")]
        cwd: PathBuf,
    },
    /// Check that the pinned managed base image version is AVAILABLE (exit 1 otherwise)
    BaseImage {
        /// Managed base image name
        #[arg(long, default_value = "al2023-1")]
        name: String,
        /// Pinned version
        #[arg(long, default_value = "1")]
        version: String,
        /// Read `list-managed-microvm-image-versions` JSON from FILE instead of calling AWS (tests)
        #[arg(long, value_name = "FILE", hide = true)]
        json_in: Option<PathBuf>,
    },
    /// Compare two `list-microvm-image-versions` snapshots taken around a deploy
    VersionsDiff {
        /// Snapshot taken before the deploy
        #[arg(long, value_name = "FILE")]
        before: PathBuf,
        /// Snapshot taken after the deploy
        #[arg(long, value_name = "FILE")]
        after: PathBuf,
        /// Append the image-version-delete probe verdict to lab/probes.jsonl
        #[arg(long)]
        record_probe: bool,
    },
}

/// `ai-env creds …` (feature `bridge`): credentials the bridge holds, sealed to the bridge keystore key.
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum CredsCmd {
    /// Seal the JSON of `aws iam create-access-key` (read from stdin) into credentials/aws.env
    AwsSet {
        /// IAM user the access key must belong to
        #[arg(long, default_value = "ai-env-runtime")]
        user: String,
        /// Preflight only: keystore key, recovery recipient, age, writable target, fewer than two existing keys
        #[arg(long)]
        check: bool,
        /// Seal even when the keystore key has no recovery recipient
        #[arg(long)]
        force: bool,
    },
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

/// `ai-env session …` (feature `bridge`): the session registry the S2 pump writes.
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum SessionCmd {
    /// List registered sessions, newest first
    List {
        /// Pretty JSON array instead of text
        #[arg(long)]
        json: bool,
    },
    /// Print one session row
    Show {
        /// Session id (a uuid)
        uuid: String,
        /// Pretty JSON instead of TOML
        #[arg(long)]
        json: bool,
    },
    /// Delete a session's row and its scratch config dir (refused while the session is active)
    Forget {
        /// Session id (a uuid)
        uuid: String,
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
        #[cfg(feature = "bridge")]
        Cmd::Session { cmd } => match cmd {
            SessionCmd::List { json } => crate::bridge::registry::cmd_list(json),
            SessionCmd::Show { uuid, json } => crate::bridge::registry::cmd_show(&uuid, json),
            SessionCmd::Forget { uuid } => crate::bridge::registry::cmd_forget(&uuid),
        },
        #[cfg(feature = "bridge")]
        Cmd::Infra { cmd } => match cmd {
            InfraCmd::Scan { dir, profile, tripwires, settings_policy, json } => {
                crate::bridge::scan::cmd_scan(&dir, profile, tripwires.as_deref(), settings_policy.as_deref(), json)
            }
            InfraCmd::Pin { manifest, lock, check_bundle, expect_version } => crate::bridge::imagepin::cmd_pin(manifest.as_deref(), &lock, check_bundle, expect_version.as_deref()),
            InfraCmd::Status { write, json_in, stack, cwd } => crate::bridge::infra::cmd_status(write, json_in.as_deref(), &stack, &cwd),
            InfraCmd::BaseImage { name, version, json_in } => crate::bridge::infra::cmd_base_image(&name, &version, json_in.as_deref()),
            InfraCmd::VersionsDiff { before, after, record_probe } => crate::bridge::infra::cmd_versions_diff(&before, &after, record_probe),
        },
        #[cfg(feature = "bridge")]
        Cmd::Creds { cmd } => match cmd {
            CredsCmd::AwsSet { user, check, force } => crate::bridge::creds::cmd_aws_set(&store, &user, check, force),
        },
        #[cfg(feature = "bridge")]
        Cmd::Vm { cmd } => crate::bridge::vm::cmd::main(&store, cmd),
        #[cfg(feature = "bridge")]
        Cmd::Lab { cmd } => crate::bridge::vm::cmd::lab_main(&store, cmd),
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
