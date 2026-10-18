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
    /// (exit 1 when any row is [NO ], 5 when AWS refuses the key of the identity ai-env as declared)
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
    /// Cursor wrapper: install or uninstall the claudeProcessWrapper setting, show its status, inspect the invocation census, promote a session's approved settings
    #[cfg(feature = "bridge")]
    Wrapper {
        #[command(subcommand)]
        cmd: WrapperCmd,
    },
    /// Sessions the wrapper registered (state/sessions/*.toml): list, show, forget, drop-transport; a remote chat's transcript in S3 (S9): stage, sync, gc --remote, migrate-s9
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
    /// The workspace a VM works in (S8): seed it into the VM, fetch the VM's commits into refs/remotes/box/*; review what a push would carry, and install the pre-push hook that reviews every push (S9)
    #[cfg(feature = "bridge")]
    Box {
        #[command(subcommand)]
        cmd: BoxCmd,
    },
    /// Platform probes (lab/probes.jsonl): list, show, run
    #[cfg(feature = "bridge")]
    Lab {
        #[command(subcommand)]
        cmd: LabCmd,
    },
    /// The S5 egress allowlist on the shared proxy: status, allow, suspend, reload, env, check (as ai-env-ops: the key of ai-env as …, else credentials/ops.env; allow as ai-env-deployer)
    #[cfg(feature = "bridge")]
    Egress {
        #[command(subcommand)]
        cmd: EgressCmd,
    },
    /// The S5 egress proxy instance: stop, start, patch (as ai-env-ops: the key of ai-env as …, else credentials/ops.env)
    #[cfg(feature = "bridge")]
    Proxy {
        #[command(subcommand)]
        cmd: ProxyCmd,
    },
    /// Run CMD as one AWS operator identity: deployer (its key pasted from Strongbox), ops (credentials/ops.env, one Touch ID), root (the bootstrap and break-glass only) or ambient (the aws CLI's own credentials, never the root)
    #[cfg(feature = "bridge")]
    As {
        /// Who runs it: deployer, ops, root or ambient
        #[arg(value_enum)]
        identity: crate::bridge::identity::Identity,
        /// The stack's 12-digit account when neither state/infra.toml nor bridge.toml [aws] names it
        #[arg(long, value_name = "ACCOUNT")]
        account: Option<String>,
        /// Only check that this process already runs as IDENTITY (the make guard): exit 0 silently, else 9; nothing runs
        #[arg(long, conflicts_with = "command")]
        check: bool,
        /// The command to run (after --); it replaces ai-env and keeps its own exit status
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required_unless_present = "check")]
        command: Vec<String>,
    },
    /// VM mode: the MicroVM image entrypoint (PID 1); also runs natively for tests
    #[cfg(feature = "shim")]
    Shim(crate::shim::ShimArgs),
    /// The agent's workspace helper the shim starts (S8): one seed, code-out, transcript or settings operation
    #[cfg(feature = "shim")]
    #[command(hide = true)]
    ShimIo(crate::shim::wshelper::ShimIoArgs),
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

#[cfg(feature = "bridge")]
impl EgressArg {
    /// The run's egress.
    #[must_use]
    pub fn egress(self) -> crate::bridge::vm::run::Egress {
        match self {
            EgressArg::Internet => crate::bridge::vm::run::Egress::Internet,
            EgressArg::Vpc => crate::bridge::vm::run::Egress::Vpc,
        }
    }
}

/// `--deliver` of `ai-env vm exec` (S7).
#[cfg(feature = "bridge")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum DeliverArg {
    /// On fd 3, with CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3 (claude reads it once)
    Fd,
    /// As CLAUDE_CODE_OAUTH_TOKEN in the command's environment; needs [creds] deliver = "env", which also makes it the default
    Env,
}

#[cfg(feature = "bridge")]
impl DeliverArg {
    /// The wire's delivery.
    #[must_use]
    pub fn deliver(self) -> crate::wire::frame::Deliver {
        match self {
            DeliverArg::Fd => crate::wire::frame::Deliver::Fd,
            DeliverArg::Env => crate::wire::frame::Deliver::Env,
        }
    }
}

/// `--mode` of `ai-env wrapper install` (S8, L1): the `[wrapper].mode` to write.
#[cfg(feature = "bridge")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum WrapperModeArg {
    /// Cursor's chats run on this Mac
    Passthrough,
    /// Cursor's chats under [workspaces].roots run in the workspace's MicroVM
    Remote,
}

#[cfg(feature = "bridge")]
impl WrapperModeArg {
    /// The config's mode.
    #[must_use]
    pub fn mode(self) -> crate::bridge::config::WrapperMode {
        match self {
            WrapperModeArg::Passthrough => crate::bridge::config::WrapperMode::Passthrough,
            WrapperModeArg::Remote => crate::bridge::config::WrapperMode::Remote,
        }
    }
}

/// `--auth` of `ai-env vm shell`.
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
    /// GET /health through the endpoint (a 5-minute Port(8080) token); --detail reads /health/detail with the session bearer
    Health {
        /// MicroVM id
        id: String,
        /// GET /health/detail (guard, sockets, spawns, listeners; needs the row's session token)
        #[arg(long)]
        detail: bool,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Run a command in the VM as the agent (uid 1000) over /agent; stdio is byte-exact, the exit status is the command's
    Exec {
        /// MicroVM id (a VM `vm run` started: its row holds the session token)
        id: String,
        /// Working directory in the VM (absolute; created as the agent; default its HOME)
        #[arg(long, value_name = "PATH")]
        cwd: Option<String>,
        /// An environment variable for the command (repeatable; never AWS_*, CLAUDECODE, NODE_OPTIONS or a TOKEN/KEY/SECRET/PASSWORD name)
        #[arg(long = "env", value_name = "K=V")]
        env: Vec<String>,
        /// Seconds the command survives a lost connection before it is stopped (default 60)
        #[arg(long, value_name = "S", value_parser = clap::value_parser!(u32).range(1..=86_400))]
        detach_grace: Option<u32>,
        /// Give the command the sealed setup-token (CLAUDE_CODE_OAUTH_TOKEN); the VM keeps a copy until it is suspended or terminated
        #[arg(long, conflicts_with = "credential_file")]
        with_credential: bool,
        /// How the credential reaches the command: fd or env; the default is [creds] deliver ("fd" unless set to "env"), and env needs [creds] deliver = "env"
        #[arg(long, value_enum, value_name = "HOW")]
        deliver: Option<DeliverArg>,
        /// Give this one command the token sealed in this container (never kept on the VM)
        #[arg(long, value_name = "PATH")]
        credential_file: Option<PathBuf>,
        /// The command and its arguments (after --)
        #[arg(last = true, required = true, value_name = "ARGV")]
        argv: Vec<String>,
    },
    /// Start or reuse the workspace's VM (vpc egress), seed it (HEAD and the uncommitted changes, scanned before the Touch ID: a finding is exit 9; none for a workspace that is no git repository or an unsupported one) and deliver the sealed setup-token ahead of time: later credentialed commands there need no Touch ID for it until the VM is suspended
    Warm {
        /// Workspace directory (under [workspaces].roots)
        workspace: PathBuf,
        /// One JSON document
        #[arg(long)]
        json: bool,
        /// Say what it would do (the VM it would use, what the seed carries and its scans: a finding is exit 9) and do nothing: no AWS call, no Touch ID
        #[arg(long, conflicts_with = "prewarm")]
        dry_run: bool,
        /// Started by the wrapper on `auth status` (S8 prewarm): quiet, audited as purpose prewarm
        #[arg(long, hide = true)]
        prewarm: bool,
    },
    /// Reattach to a running command (the newest attachment wins; the previous client exits 8). A terminal's input feeds the command's stdin (Ctrl-D closes it for good); any other stdin is not read, and the command's stdin is left as it is
    Attach {
        /// MicroVM id
        id: String,
        /// The spawn's id (printed by vm exec on stderr)
        #[arg(long, value_name = "UUID")]
        spawn: String,
        /// Replay stdout from this seq (default: the oldest the VM still holds; a seq past the end shows what the command prints from then on)
        #[arg(long, value_name = "N")]
        from_seq: Option<u64>,
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
    /// Terminate one VM, or --all of yours (rows + own orphans); the remote chats a running one holds are synced to S3 first (a suspended one is never woken: its /suspend pushed their tails once) (S9)
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
        /// Act (terminate expired registry VMs, the remote chats each running one holds synced to S3 first (S9); adopt, clear stale rows)
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
        /// Egress: internet (audited) or vpc (default: vpc when [aws].egress_connector_arn is set, else internet); the VM must echo exactly that
        #[arg(long, value_enum)]
        egress: Option<EgressArg>,
        /// Do not pass [aws].execution_role_arn
        #[arg(long)]
        no_execution_role: bool,
        /// Leave the VM running
        #[arg(long)]
        keep: bool,
        /// Also run `claude --version` and `id -u` over /agent (S6) and check them
        #[arg(long)]
        exec: bool,
        /// With --exec: also deliver the sealed setup-token and run `claude -p 'Reply OK'` with it (vpc egress; S7)
        #[arg(long, requires = "exec")]
        with_credential: bool,
        /// One JSON record on stdout (the step lines go to stderr)
        #[arg(long)]
        json: bool,
    },
}

/// `ai-env box …` (feature `bridge`, S8): the workspace a VM works in. A seed
/// carries HEAD's commit and tree and a scanned snapshot of the uncommitted
/// changes (never the history); a fetch brings the VM's commits and
/// snapshots back into `refs/remotes/box/*`, never into your branches. S9: a
/// review of what a push would carry, and the pre-push hook that runs it on
/// every push.
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum BoxCmd {
    /// Seed the workspace's VM at the identical path: HEAD's commit and tree plus the scanned uncommitted changes (a shallow clone, no origin); a VM seeded before is fast-forwarded when its checkout is clean, on the same branch and its tip an ancestor of the commit seeded (HEAD, or --branch's), else kept (ai-env box fetch shows what changed)
    Seed {
        /// Workspace directory (under [workspaces].roots; default: the current directory)
        workspace: Option<PathBuf>,
        /// Seed this branch instead of the one checked out (its committed state only)
        #[arg(long, value_name = "B")]
        branch: Option<String>,
        /// Committed refs only: the uncommitted changes stay on this Mac (default: [[workspace]].seed_wip)
        #[arg(long)]
        no_wip: bool,
        /// Replace the VM's checkout (only while it is unchanged since its seed)
        #[arg(long)]
        replace: bool,
        /// Resolve, snapshot, pack and scan, then print the plan: no AWS call, no Touch ID
        #[arg(long)]
        dry_run: bool,
        /// The largest pack in MiB (default: [seed].max_mib)
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=1024))]
        max_mib: Option<u32>,
        /// One JSON document
        #[arg(long)]
        json: bool,
    },
    /// Fetch the VM's commits into refs/remotes/box/* (a ref with a scan finding into refs/remotes/box-quarantine/*); your branches and working tree are never touched
    Fetch {
        /// A session id or a workspace directory (default: the current directory)
        target: Option<String>,
        /// Also snapshot the VM's uncommitted changes into a refs/wip/* ref and fetch it (refs/remotes/box/wip/*)
        #[arg(long)]
        wip: bool,
        /// Read the VM's refs and print what would move: nothing is transferred
        #[arg(long)]
        dry_run: bool,
        /// The largest code-out in MiB (default: [seed].max_fetch_mib)
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=1024))]
        max_mib: Option<u32>,
        /// Fetch through git smart-HTTP (upload-pack, protocol v2) instead of POST /codeout; the VM must name git_http_v1
        #[arg(long, conflicts_with = "wip")]
        smart_http: bool,
        /// One JSON document
        #[arg(long)]
        json: bool,
    },
    /// Review what a push would carry: the tripwires, the settings policy, the dotenv rule, the Cargo.lock checks and the pre-push hook's own path (a file behind a link included) over REV's commits that BASES lack; a finding is exit 9 (no AWS call, no Touch ID)
    Review {
        /// The commit to review (a branch, a tag, a sha)
        #[arg(required_unless_present = "pre_push", conflicts_with = "pre_push")]
        rev: Option<String>,
        /// Where the range starts (repeatable; default: every remote-tracking ref but refs/remotes/box/* and box-quarantine/*)
        #[arg(long = "base", value_name = "REV", conflicts_with = "pre_push")]
        base: Vec<String>,
        /// The repository (default: the current directory's)
        #[arg(long, value_name = "DIR")]
        repo: Option<PathBuf>,
        /// One JSON document
        #[arg(long)]
        json: bool,
        /// The pre-push hook's call: REMOTE and URL as git passes them, the pushed refs on stdin
        #[arg(long, num_args = 2, value_names = ["REMOTE", "URL"], hide = true)]
        pre_push: Option<Vec<String>>,
    },
    /// Install the pre-push review hook in REPO (where git runs hooks: core.hooksPath honoured): every push is then reviewed first, and refused while the ai-env it names is missing; never over another hook
    HookInstall {
        /// The repository (default: the current directory's)
        repo: Option<PathBuf>,
        /// Print the hook's path and body; write nothing
        #[arg(long)]
        dry_run: bool,
        /// One JSON document
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
        /// MicroVM id (cloudtrail-payload), or the ARN of a connector that is not ACTIVE yet (connector-pending)
        id: Option<String>,
        /// Derive the verdict from this runtime log (`make logs SINCE=30m > FILE`), or for cloudtrail-payload from a trail's gunzipped log file or `aws logs filter-log-events` output
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

/// `ai-env egress …` (feature `bridge`): the S5 allowlist on the shared proxy.
/// Every AWS call runs as the operator identity (S8: the key `ai-env as …`
/// left, else `credentials/ops.env`, one Touch ID; `allow` only as
/// ai-env-deployer), of the account of `[aws].egress_connector_arn`, never
/// the runtime key.
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum EgressCmd {
    /// Connector, VPC, routes, security groups, proxy and parameters against the stack (exit 1 on any drift)
    Status {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Allow HOST for workspace SLUG (global: the host stays allowed while any workspace lists it)
    Allow {
        /// Workspace slug (its project dir name)
        slug: String,
        /// An exact host name (no wildcard, IP literal, port, scheme or path)
        host: String,
        /// Remove SLUG's entry instead
        #[arg(long)]
        remove: bool,
    },
    /// Deny HOST on the proxy even when it is allowed (--restore lifts it)
    Suspend {
        /// An exact host name
        host: String,
        /// Lift the suspension
        #[arg(long)]
        restore: bool,
    },
    /// Make the proxy re-read its parameters (squid -k parse first; on any error the old config keeps serving)
    Reload {
        /// Only when a parameter changed since the proxy's last reload
        #[arg(long)]
        if_changed: bool,
    },
    /// Print the proxy environment a vpc VM needs (https_proxy, http_proxy, no_proxy, both spellings)
    Env {
        /// `export NAME=value` lines for a shell
        #[arg(long)]
        shell: bool,
    },
    /// From a vpc VM: direct egress and DNS closed, the allowlist working, S3 reached through the proxy for the transcripts bucket alone (S9); a pass is recorded in state/egress-verified.toml
    Check {
        /// A running VM started with `vm run --egress vpc --shell` (default: start one and terminate it after)
        #[arg(long, value_name = "ID")]
        vm: Option<String>,
        /// Leave the VM this check started running
        #[arg(long)]
        keep: bool,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
        /// Start nothing when the image version a new VM runs ([aws].image_version resolved live, as RunMicrovm does) already has a passing check with [aws].egress_connector_arn bound to that very build (createdAt) and to the connector's live facts, at most 7 days old and judged by the current DNS and egress rules (a pass recorded before DNS rule 1, or before S9's S3 cases, never counts: the check runs again and says why); an unaccepted DNS verdict is named (`make claude-update` runs it after every deploy)
        #[arg(long, conflicts_with_all = ["vm", "keep"])]
        if_needed: bool,
    },
}

/// `ai-env proxy …` (feature `bridge`): the S5 proxy instance, as the
/// operator identity (S8: the key `ai-env as …` left, else
/// `credentials/ops.env`).
#[cfg(feature = "bridge")]
#[derive(Subcommand)]
pub enum ProxyCmd {
    /// Stop the proxy instance (refused while vpc VMs run, unless --yes); every vpc VM loses egress
    Stop {
        /// Stop even while vpc VMs run
        #[arg(long)]
        yes: bool,
    },
    /// Start it and wait until squid serves (instance running, SSM online, reload --status)
    Start,
    /// Security updates through SSM (dnf upgrade --security), then restart squid
    Patch,
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
    /// Write image/claude.lock from a release manifest.json, print it, compare it with the installed Cursor bundle, or print the bundle's version
    Pin {
        /// Release manifest.json to pin from (downloaded and signature-checked by `make claude-pin`)
        #[arg(long, value_name = "FILE", conflicts_with_all = ["check_bundle", "bundle_version"])]
        manifest: Option<PathBuf>,
        /// The lock file to write or read
        #[arg(long, value_name = "FILE", default_value = "image/claude.lock")]
        lock: PathBuf,
        /// Exit 1 unless the lock's version equals the installed Cursor extension bundle's
        #[arg(long, conflicts_with = "bundle_version")]
        check_bundle: bool,
        /// Print the installed Cursor extension bundle's Claude Code version (the one the image must carry) and nothing else; exit 1 without a bundle
        #[arg(long)]
        bundle_version: bool,
        /// With --manifest: refuse a manifest whose version is not this one (lock not written)
        #[arg(long, value_name = "V", requires = "manifest", conflicts_with_all = ["check_bundle", "bundle_version"])]
        expect_version: Option<String>,
    },
    /// Read the Pulumi stack outputs plus live read-only get-microvm-image and (S5) get-network-connector, and show (or --write) the bridge.toml [aws] table and state/infra.toml
    Status {
        /// Edit bridge.toml [aws] in place (backup first) and write state/infra.toml
        #[arg(long)]
        write: bool,
        /// Read the outputs from FILE instead of `pulumi stack output --json` (tests; the live get-microvm-image and get-network-connector reads still run, so tests put a fake aws first on PATH)
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
    /// Seal the JSON of `aws iam create-access-key` (read from stdin): ai-env-runtime's key into credentials/aws.env, ai-env-ops' into credentials/ops.env
    AwsSet {
        /// IAM user the access key must belong to: ai-env-runtime (credentials/aws.env) or ai-env-ops (credentials/ops.env); the deployer's key is never stored here (creds deployer-key)
        #[arg(long, default_value = "ai-env-runtime")]
        user: String,
        /// Preflight only: keystore key, recovery recipient, age, writable target, fewer than two existing keys
        #[arg(long)]
        check: bool,
        /// Seal even when the keystore key has no recovery recipient
        #[arg(long)]
        force: bool,
    },
    /// Check a sealed AWS key (one Touch ID): aws sts get-caller-identity with that key alone must answer as its user, retried while IAM propagates; `id` and `arn` lines on stdout when it is not a terminal
    AwsVerify {
        /// ai-env-runtime (credentials/aws.env) or ai-env-ops (credentials/ops.env)
        #[arg(long, default_value = "ai-env-runtime")]
        user: String,
    },
    /// Hand a new ai-env-deployer key over to its Strongbox entry: pipe in the JSON of `aws iam create-access-key --user-name ai-env-deployer --output json`; this Mac's clipboard (concealed) carries it, it is pasted back, then checked with sts; it is never stored here
    DeployerKey {
        /// The stack's 12-digit account when neither state/infra.toml nor bridge.toml [aws] names it
        #[arg(long, value_name = "ACCOUNT", conflicts_with = "clipboard_check")]
        account: Option<String>,
        /// Only check the clipboard: a harmless marker goes on it as the key would (this Mac only, concealed); it must not paste on another Apple device
        #[arg(long)]
        clipboard_check: bool,
    },
    /// Seal the Claude setup-token (what `claude setup-token` prints) into credentials/setup-token.env; asks for it hidden
    SetupToken {
        /// Read one line from stdin (a pipe; a terminal is refused) instead of asking
        #[arg(long, conflicts_with = "from_env")]
        stdin: bool,
        /// Read CLAUDE_CODE_OAUTH_TOKEN from the environment instead of asking
        #[arg(long)]
        from_env: bool,
        /// Do not rebuild credentials/combined.env (a credentialed command then asks for Touch ID twice)
        #[arg(long)]
        no_combined: bool,
        /// Seal even when the keystore key has no recovery recipient
        #[arg(long)]
        force: bool,
    },
    /// What is sealed under credentials/, without Touch ID (unless --unseal)
    Status {
        /// One JSON document
        #[arg(long)]
        json: bool,
        /// Unseal the setup-token once (one Touch ID) and time it
        #[arg(long)]
        unseal: bool,
    },
    /// Delete the sealed setup-token, combined.env and their backups (a dry run without --yes); with --ops only credentials/ops.env and its backups
    Forget {
        /// Delete (default: list what would be deleted)
        #[arg(long)]
        yes: bool,
        /// The ops key instead: credentials/ops.env and its backups, nothing else (its key is then deleted in IAM: the commands are printed)
        #[arg(long)]
        ops: bool,
    },
}

/// The parse checks of the S8 operators' creds commands (`aws-set --user`,
/// `aws-verify`, `deployer-key`, `forget --ops`).
#[cfg(all(test, feature = "bridge"))]
#[allow(clippy::items_after_test_module)]
mod creds_cmd_tests {
    use super::{Cli, Cmd, CredsCmd};
    use clap::{CommandFactory as _, Parser as _};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(["ai-env", "creds"].into_iter().chain(args.iter().copied()))
    }

    fn creds(args: &[&str]) -> CredsCmd {
        match parse(args).unwrap_or_else(|e| panic!("{args:?}: {e}")).cmd {
            Cmd::Creds { cmd } => cmd,
            _ => panic!("{args:?}: not creds"),
        }
    }

    #[test]
    fn the_operator_key_commands_parse() {
        let CredsCmd::AwsSet { user, check: true, force: false } = creds(&["aws-set", "--user", "ai-env-ops", "--check"]) else { panic!("aws-set --user --check") };
        assert_eq!(user, "ai-env-ops");
        let CredsCmd::AwsVerify { user } = creds(&["aws-verify"]) else { panic!("aws-verify") };
        assert_eq!(user, "ai-env-runtime", "the default user");
        let CredsCmd::AwsVerify { user } = creds(&["aws-verify", "--user", "ai-env-ops"]) else { panic!("aws-verify --user") };
        assert_eq!(user, "ai-env-ops");
        let CredsCmd::DeployerKey { account: None, clipboard_check: false } = creds(&["deployer-key"]) else { panic!("deployer-key") };
        let CredsCmd::DeployerKey { account, clipboard_check: false } = creds(&["deployer-key", "--account", "123456789012"]) else { panic!("deployer-key --account") };
        assert_eq!(account.as_deref(), Some("123456789012"));
        let CredsCmd::DeployerKey { account: None, clipboard_check: true } = creds(&["deployer-key", "--clipboard-check"]) else { panic!("deployer-key --clipboard-check") };
        let CredsCmd::Forget { yes: true, ops: true } = creds(&["forget", "--ops", "--yes"]) else { panic!("forget --ops --yes") };
        let CredsCmd::Forget { yes: false, ops: false } = creds(&["forget"]) else { panic!("forget") };
        for bad in [&["deployer-key", "--clipboard-check", "--account", "123456789012"][..], &["deployer-key", "--account"], &["aws-verify", "--user"], &["aws-verify", "extra"]] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        // Listed in `creds --help`, each with its one-line about.
        let mut cli = Cli::command();
        let help = cli.find_subcommand_mut("creds").expect("creds").render_help().to_string();
        for sub in ["aws-set", "aws-verify", "deployer-key", "setup-token", "status", "forget"] {
            assert!(help.contains(sub), "{sub}: {help}");
        }
    }
}

/// `ai-env wrapper …` (feature `bridge`): the two S1 operator commands, S8's
/// settings sync, and the setting's status and uninstall.
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
        /// Also set [wrapper].mode in bridge.toml (backup first): remote runs Cursor's chats under the roots in a MicroVM, passthrough on this Mac
        #[arg(long, value_enum, value_name = "MODE")]
        mode: Option<WrapperModeArg>,
    },
    /// Take claudeCode.claudeProcessWrapper out of Cursor's settings: what Cursor starts afterwards is its bundled claude (dry run unless --write; backs up settings.json; initialPermissionMode and bridge.toml stay); it warns first while remote chats keep only their view on this Mac, which Cursor would then resume here (S9)
    Uninstall {
        /// Edit settings.json (default: a dry run that shows what would be removed)
        #[arg(long)]
        write: bool,
    },
    /// Promote the permission rules a session approved in its VMs into the image's settings (dry run unless --write; never a broad allow, a repo-scan finding or defaultMode)
    SettingsSync {
        /// Session id (a uuid)
        session: String,
        /// Promote this rule (repeatable): an entry the session added to permissions.allow, deny or ask
        #[arg(long = "rule", value_name = "R")]
        rule: Vec<String>,
        /// Promote every rule the session added that is safe
        #[arg(long)]
        all_safe: bool,
        /// Write image/claude/settings.json and the settings policy (backups first), then re-scan (default: a dry run)
        #[arg(long)]
        write: bool,
        /// The image directory (default: image/ under the git toplevel of the current directory; it must hold MANIFEST)
        #[arg(long, value_name = "DIR")]
        image_dir: Option<PathBuf>,
    },
    /// Print the invocation census (logs/census.jsonl); --record-probes writes the entrypoint and stock-ext-oauth verdicts and, once remote end rows exist, init-wrapper to lab/probes.jsonl
    Census {
        /// Only the last N rows
        #[arg(long, value_name = "N")]
        last: Option<usize>,
        /// Raw JSON lines instead of the text table
        #[arg(long)]
        json: bool,
        /// Derive the S1 verdicts (entrypoint, stock-ext-oauth) from the newest session row and, once the census
        /// holds remote end rows, S8's init-wrapper from the newest cold and warm ones (gap:cold or gap:warm while
        /// either is missing), and append them to lab/probes.jsonl (exit 1 when a verdict differs from its
        /// expectation, a gap included; the rows are written first)
        #[arg(long)]
        record_probes: bool,
    },
    /// Show whether Cursor's claudeProcessWrapper is set, which ai-env-claude it runs, the effective wrapper mode and roots, whether bridge.toml passes a remote session's start checks, which extension Cursor last ran, and which one each open Cursor window runs (read-only: no AWS, no Touch ID)
    Status {
        /// Machine-readable output (doctor --json's shape)
        #[arg(long)]
        json: bool,
    },
}

/// `ai-env session …` (feature `bridge`): the session registry the S2 pump
/// writes, and (S9) the store in S3 of a remote chat's transcript.
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
        /// The settings the session's claude changed in its VMs: the rules added in any VM's last capture, then each VM's other changes against the start, per scope (env values masked); written to quarantine/UUID/settings/diff.json
        #[arg(long)]
        settings_diff: bool,
    },
    /// Delete a session's row, its scratch config dir and its quarantine (the settings captures, diff.json and settings-sync's backups); refused while the session is active
    Forget {
        /// Session id (a uuid)
        uuid: String,
        /// Also delete its S3 transcript, its manifest, the original kept under state/transcripts and the view
        #[arg(long)]
        purge: bool,
    },
    /// Close a remote session's socket from the wrapper's side; the session reattaches (T8.6)
    DropTransport {
        /// Session id (a uuid)
        uuid: String,
    },
    /// Upload a chat that began on this Mac to S3 (scanned first, resumable), then leave its view in place of the file: a chat over 64 MiB needs this, with --warm, before it reopens remote; refused (exit 9) when the cwd its transcript records is outside bridge.toml's roots or in no git repository, where it could never reopen
    Stage {
        /// Session id (a uuid)
        uuid: String,
        /// Then start or resume the VM of the chat's workspace now (ai-env vm warm of the cwd the chat began in, as its transcript records it, or as a remote chat's row does; it must lie in a git repository under bridge.toml's roots) and restore the chat from S3 into that VM, whatever its size: a reopen there keeps it, where a reopen pulls at most 64 MiB inside Cursor's window; a reopen takes that VM only with [vm].reuse_per_workspace on and no AI_ENV_BRIDGE_VM pin to another VM
        #[arg(long)]
        warm: bool,
        /// One JSON document
        #[arg(long)]
        json: bool,
    },
    /// Push a remote session's transcript from its VM to S3 now and rewrite its view
    Sync {
        /// Session id (a uuid)
        uuid: String,
        /// One JSON document
        #[arg(long)]
        json: bool,
    },
    /// Remove the S3 transcripts of sessions closed more than DAYS ago (a dry run without --yes)
    Gc {
        /// The store in S3 (required)
        #[arg(long, required = true)]
        remote: bool,
        /// Days since the session's last activity
        #[arg(long, value_name = "DAYS", default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=3650))]
        older_than: u32,
        /// Remove them (without it: list them)
        #[arg(long)]
        yes: bool,
        /// One JSON document
        #[arg(long)]
        json: bool,
    },
    /// Move S8's mirrored transcripts of remote chats into S3 and leave their views (a dry run without --yes)
    #[command(name = "migrate-s9")]
    MigrateS9 {
        /// Migrate them (without it: list them)
        #[arg(long)]
        yes: bool,
        /// One JSON document
        #[arg(long)]
        json: bool,
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
    // The agent's helper in the VM (S8) runs with the environment the shim gives it: no keystore either.
    #[cfg(feature = "shim")]
    if let Cmd::ShimIo(args) = cli.cmd {
        return crate::shim::wshelper::run(args);
    }
    let store = Keystore::resolve(cli.key_dir)?;
    #[cfg(feature = "bridge")]
    crate::bridge::identity::init(&store);
    let r = match cli.cmd {
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
            WrapperCmd::Install { write, permission_mode, mode: None } => crate::bridge::wrapper::install(write, permission_mode),
            WrapperCmd::Install { write, permission_mode, mode: Some(mode) } => crate::bridge::wrapper::install_mode(write, permission_mode, mode.mode()),
            WrapperCmd::Uninstall { write } => crate::bridge::wrapper::uninstall(write),
            WrapperCmd::Census { last, json, record_probes } => crate::bridge::wrapper::census(last, json, record_probes),
            WrapperCmd::SettingsSync { session, rule, all_safe, write, image_dir } => crate::bridge::wrapper::settings_sync(&session, &rule, all_safe, write, image_dir.as_deref()),
            WrapperCmd::Status { json } => crate::bridge::wrapper_status::status(json),
        },
        #[cfg(feature = "bridge")]
        Cmd::Session { cmd } => match cmd {
            SessionCmd::List { json } => crate::bridge::registry::cmd_list(json),
            SessionCmd::Show { uuid, json, settings_diff: false } => crate::bridge::registry::cmd_show(&uuid, json),
            SessionCmd::Show { uuid, json, settings_diff: true } => crate::bridge::settings_capture::cmd_settings_diff(&uuid, json),
            SessionCmd::Forget { uuid, purge } => crate::bridge::registry::cmd_forget(&store, &uuid, purge),
            SessionCmd::DropTransport { uuid } => crate::bridge::registry::cmd_drop_transport(&uuid),
            SessionCmd::Stage { uuid, warm, json } => crate::bridge::s3::stage::cmd_stage(&store, &uuid, warm, json),
            SessionCmd::Sync { uuid, json } => crate::bridge::s3::cmd_sync(&store, &uuid, json),
            SessionCmd::Gc { remote: _, older_than, yes, json } => crate::bridge::s3::cmd_gc(&store, older_than, yes, json),
            SessionCmd::MigrateS9 { yes, json } => crate::bridge::s3::cmd_migrate_s9(&store, yes, json),
        },
        #[cfg(feature = "bridge")]
        Cmd::Infra { cmd } => match cmd {
            InfraCmd::Scan { dir, profile, tripwires, settings_policy, json } => {
                crate::bridge::scan::cmd_scan(&dir, profile, tripwires.as_deref(), settings_policy.as_deref(), json)
            }
            InfraCmd::Pin { manifest, lock, check_bundle, bundle_version, expect_version } => crate::bridge::imagepin::cmd_pin(manifest.as_deref(), &lock, check_bundle, bundle_version, expect_version.as_deref()),
            InfraCmd::Status { write, json_in, stack, cwd } => crate::bridge::infra::cmd_status(write, json_in.as_deref(), &stack, &cwd),
            InfraCmd::BaseImage { name, version, json_in } => crate::bridge::infra::cmd_base_image(&name, &version, json_in.as_deref()),
            InfraCmd::VersionsDiff { before, after, record_probe } => crate::bridge::infra::cmd_versions_diff(&before, &after, record_probe),
        },
        #[cfg(feature = "bridge")]
        Cmd::Creds { cmd } => match cmd {
            CredsCmd::AwsSet { user, check, force } => crate::bridge::creds::cmd_aws_set(&store, &user, check, force),
            CredsCmd::AwsVerify { user } => crate::bridge::creds::cmd_aws_verify(&store, &user),
            CredsCmd::DeployerKey { account, clipboard_check } => crate::bridge::handover::cmd_deployer_key(&store, account.as_deref(), clipboard_check),
            CredsCmd::SetupToken { stdin, from_env, no_combined, force } => {
                crate::bridge::setup_token::cmd_setup_token(&store, crate::bridge::setup_token::SetupTokenOpts { stdin, from_env, no_combined, force })
            }
            CredsCmd::Status { json, unseal } => crate::bridge::setup_token::cmd_status(&store, json, unseal),
            CredsCmd::Forget { yes, ops: false } => crate::bridge::setup_token::cmd_forget(yes),
            CredsCmd::Forget { yes, ops: true } => crate::bridge::setup_token::cmd_forget_ops(yes),
        },
        #[cfg(feature = "bridge")]
        Cmd::Vm { cmd } => crate::bridge::vm::cmd::main(&store, cmd),
        #[cfg(feature = "bridge")]
        Cmd::Box { cmd } => crate::bridge::boxcmd::main(&store, cmd),
        #[cfg(feature = "bridge")]
        Cmd::Lab { cmd } => crate::bridge::vm::cmd::lab_main(&store, cmd),
        #[cfg(feature = "bridge")]
        Cmd::Egress { cmd } => crate::bridge::egress::cli::main(&store, cmd),
        #[cfg(feature = "bridge")]
        Cmd::Proxy { cmd } => crate::bridge::egress::cli::proxy_main(cmd),
        #[cfg(feature = "bridge")]
        Cmd::As { identity, account, check, command } => crate::bridge::identity::cmd_as(&store, identity, account.as_deref(), check, &command),
        #[cfg(feature = "shim")]
        Cmd::Shim(_) => unreachable!("shim is dispatched before the keystore is resolved"),
        #[cfg(feature = "shim")]
        Cmd::ShimIo(_) => unreachable!("shim-io is dispatched before the keystore is resolved"),
    };
    #[cfg(feature = "bridge")]
    crate::bridge::identity::forget();
    r
}

/// `ai-env doctor`: the classic rows, plus the bridge rows when built with
/// the `bridge` feature. Exit 1 on any `[NO ]`, 5 when AWS refuses the key
/// of the identity `ai-env as` declared (S8 operators: the only case, §8.2),
/// else 0.
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

#[cfg(all(test, feature = "bridge"))]
mod tests {
    use super::{BoxCmd, Cli, Cmd, SessionCmd, VmCmd, WrapperCmd, WrapperModeArg};
    use clap::{CommandFactory as _, Parser as _};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("ai-env").chain(args.iter().copied()))
    }

    fn cmd(args: &[&str]) -> Cmd {
        parse(args).unwrap_or_else(|e| panic!("{args:?}: {e}")).cmd
    }

    /// S8's commands and flags (C8) parse with their values; what clap
    /// bounds is refused (a cap of 0 MiB, a mode the config cannot hold,
    /// `vm warm --dry-run` with the prewarm's flag).
    #[test]
    fn the_s8_commands_parse_with_their_flags() {
        let Cmd::Box { cmd: BoxCmd::Seed { workspace, branch, no_wip: true, replace: true, dry_run: true, max_mib: Some(64), json: true } } = cmd(&["box", "seed", "/w", "--branch", "dev", "--no-wip", "--replace", "--dry-run", "--max-mib", "64", "--json"]) else {
            panic!("box seed")
        };
        assert_eq!((workspace, branch.as_deref()), (Some(std::path::PathBuf::from("/w")), Some("dev")));
        let Cmd::Box { cmd: BoxCmd::Seed { workspace: None, branch: None, no_wip: false, replace: false, dry_run: false, max_mib: None, json: false } } = cmd(&["box", "seed"]) else {
            panic!("box seed, every default")
        };
        let Cmd::Box { cmd: BoxCmd::Fetch { target, wip: true, dry_run: true, max_mib: Some(256), smart_http: false, json: true } } = cmd(&["box", "fetch", "ws", "--wip", "--dry-run", "--max-mib", "256", "--json"]) else {
            panic!("box fetch")
        };
        assert_eq!(target.as_deref(), Some("ws"));
        let Cmd::Vm { cmd: VmCmd::Warm { dry_run: true, prewarm: false, .. } } = cmd(&["vm", "warm", "/w", "--dry-run"]) else { panic!("vm warm --dry-run") };
        let Cmd::Vm { cmd: VmCmd::Warm { dry_run: false, prewarm: true, .. } } = cmd(&["vm", "warm", "/w", "--prewarm"]) else { panic!("vm warm --prewarm") };
        let Cmd::Session { cmd: SessionCmd::Show { settings_diff: true, json: true, .. } } = cmd(&["session", "show", "u", "--settings-diff", "--json"]) else { panic!("session show --settings-diff") };
        let Cmd::Session { cmd: SessionCmd::DropTransport { uuid } } = cmd(&["session", "drop-transport", "u"]) else { panic!("session drop-transport") };
        assert_eq!(uuid, "u");
        let Cmd::Wrapper { cmd: WrapperCmd::SettingsSync { session, rule, all_safe: true, write: true, image_dir } } =
            cmd(&["wrapper", "settings-sync", "u", "--rule", "Bash(git status)", "--rule", "Read", "--all-safe", "--write", "--image-dir", "/i"])
        else {
            panic!("wrapper settings-sync")
        };
        assert_eq!((session.as_str(), rule, image_dir), ("u", vec!["Bash(git status)".to_string(), "Read".to_string()], Some(std::path::PathBuf::from("/i"))));
        let Cmd::Wrapper { cmd: WrapperCmd::Install { mode: Some(WrapperModeArg::Remote), write: true, .. } } = cmd(&["wrapper", "install", "--write", "--mode", "remote"]) else { panic!("wrapper install --mode") };
        let Cmd::Wrapper { cmd: WrapperCmd::Install { mode: None, .. } } = cmd(&["wrapper", "install"]) else { panic!("wrapper install") };
        let Cmd::Wrapper { cmd: WrapperCmd::Uninstall { write: true } } = cmd(&["wrapper", "uninstall", "--write"]) else { panic!("wrapper uninstall --write") };
        let Cmd::Wrapper { cmd: WrapperCmd::Uninstall { write: false } } = cmd(&["wrapper", "uninstall"]) else { panic!("wrapper uninstall") };
        assert_eq!(WrapperModeArg::Passthrough.mode().name(), "passthrough");
        assert_eq!(WrapperModeArg::Remote.mode().name(), "remote");
        for bad in [
            &["box", "seed", "--max-mib", "0"][..],
            &["box", "fetch", "--max-mib", "1025"],
            &["wrapper", "install", "--mode", "local-child"],
            // uninstall leaves bridge.toml and initialPermissionMode alone: no --mode, no --permission-mode.
            &["wrapper", "uninstall", "--mode", "remote"],
            &["wrapper", "uninstall", "--permission-mode", "plan"],
            &["vm", "warm", "/w", "--dry-run", "--prewarm"],
            &["vm", "warm", "--dry-run"],
            &["session", "drop-transport"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        // The prewarm's flag stays out of the help; box is listed.
        let mut cli = Cli::command();
        let warm = cli.find_subcommand_mut("vm").and_then(|vm| vm.find_subcommand_mut("warm")).expect("vm warm").render_help().to_string();
        assert!(warm.contains("--dry-run") && !warm.contains("--prewarm"), "{warm}");
        assert!(Cli::command().render_help().to_string().contains("box"));
    }

    /// S9's `box` commands (plans/s9-contracts.md §4.1 to §4.3): `review`
    /// takes REV or the hook's hidden `--pre-push REMOTE URL`, never both,
    /// and `--base` only with REV; `hook-install` its repository;
    /// `fetch --smart-http` never with `--wip` (the snapshot is `/codeout`'s).
    #[test]
    fn box_review_hook_install_and_smart_http_parse() {
        let Cmd::Box { cmd: BoxCmd::Review { rev: Some(rev), base, repo: None, json: false, pre_push: None } } = cmd(&["box", "review", "HEAD"]) else { panic!("box review HEAD") };
        assert_eq!((rev.as_str(), base.len()), ("HEAD", 0));
        let Cmd::Box { cmd: BoxCmd::Review { rev: Some(rev), base, repo: Some(repo), json: true, pre_push: None } } = cmd(&["box", "review", "dev", "--base", "origin/main", "--base", "origin/dev", "--repo", "/r", "--json"]) else {
            panic!("box review with bases")
        };
        assert_eq!((rev.as_str(), base, repo), ("dev", vec!["origin/main".to_string(), "origin/dev".to_string()], std::path::PathBuf::from("/r")));
        let Cmd::Box { cmd: BoxCmd::Review { rev: None, pre_push: Some(pushed), .. } } = cmd(&["box", "review", "--pre-push", "origin", "git@example.invalid:o/r.git"]) else { panic!("box review --pre-push") };
        assert_eq!(pushed, ["origin", "git@example.invalid:o/r.git"]);
        let Cmd::Box { cmd: BoxCmd::HookInstall { repo: None, dry_run: false, json: false } } = cmd(&["box", "hook-install"]) else { panic!("box hook-install") };
        let Cmd::Box { cmd: BoxCmd::HookInstall { repo: Some(repo), dry_run: true, json: true } } = cmd(&["box", "hook-install", "/r", "--dry-run", "--json"]) else { panic!("box hook-install /r") };
        assert_eq!(repo, std::path::PathBuf::from("/r"));
        let Cmd::Box { cmd: BoxCmd::Fetch { smart_http: true, wip: false, dry_run: true, .. } } = cmd(&["box", "fetch", "--smart-http", "--dry-run"]) else { panic!("box fetch --smart-http") };
        for bad in [
            &["box", "review"][..],
            &["box", "review", "HEAD", "--pre-push", "origin", "u"],
            &["box", "review", "--pre-push", "origin"],
            &["box", "review", "--base", "x", "--pre-push", "origin", "u"],
            &["box", "hook-install", "/r", "/s"],
            &["box", "fetch", "--smart-http", "--wip"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let review = long_help("box", "review");
        assert!(!review.contains("--pre-push") && review.contains("--base"), "the hook's flag stays out of the help:\n{review}");
    }

    /// S9's `session` commands (§4.4): `stage`, `sync`, `gc --remote` (90
    /// days unless told, 1 to 3650), `migrate-s9`, and `forget --purge`.
    #[test]
    fn session_s9_commands_parse() {
        let id = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let Cmd::Session { cmd: SessionCmd::Stage { uuid, warm: true, json: true } } = cmd(&["session", "stage", id, "--warm", "--json"]) else { panic!("session stage") };
        assert_eq!(uuid, id);
        let Cmd::Session { cmd: SessionCmd::Stage { warm: false, json: false, .. } } = cmd(&["session", "stage", id]) else { panic!("session stage, every default") };
        let Cmd::Session { cmd: SessionCmd::Sync { uuid, json: false } } = cmd(&["session", "sync", id]) else { panic!("session sync") };
        assert_eq!(uuid, id);
        let Cmd::Session { cmd: SessionCmd::Gc { remote: true, older_than: 90, yes: false, json: false } } = cmd(&["session", "gc", "--remote"]) else { panic!("session gc --remote") };
        let Cmd::Session { cmd: SessionCmd::Gc { remote: true, older_than: 30, yes: true, json: true } } = cmd(&["session", "gc", "--remote", "--older-than", "30", "--yes", "--json"]) else { panic!("session gc, every flag") };
        let Cmd::Session { cmd: SessionCmd::MigrateS9 { yes: true, json: false } } = cmd(&["session", "migrate-s9", "--yes"]) else { panic!("session migrate-s9") };
        let Cmd::Session { cmd: SessionCmd::Forget { uuid, purge: true } } = cmd(&["session", "forget", id, "--purge"]) else { panic!("session forget --purge") };
        assert_eq!(uuid, id);
        let Cmd::Session { cmd: SessionCmd::Forget { purge: false, .. } } = cmd(&["session", "forget", id]) else { panic!("session forget") };
        for bad in [
            &["session", "gc"][..],
            &["session", "gc", "--remote", "--older-than", "0"],
            &["session", "gc", "--remote", "--older-than", "3651"],
            &["session", "stage"],
            &["session", "sync"],
            &["session", "migrate_s9"],
            &["session", "migrate-s9", id],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// `session stage --help` says what `--warm` does (S9, R5-AWS-1): it
    /// starts or resumes the VM of the chat's workspace now (the cwd the
    /// chat began in, in a git repository under the roots) and restores the
    /// chat from S3 into that VM, whatever its size, since a reopen pulls
    /// at most 64 MiB inside Cursor's window; a chat over 64 MiB needs it. A
    /// reopen takes that VM only with reuse on and no pin to another.
    #[test]
    fn session_stage_help_says_what_warm_does() {
        let stage = long_help("session", "stage");
        let want = "Then start or resume the VM of the chat's workspace now (ai-env vm warm of the cwd the chat began in, as its transcript records it, or as a remote chat's row does; it must lie in a git repository under bridge.toml's roots) and restore the chat from S3 into that VM, whatever its size: a reopen there keeps it, where a reopen pulls at most 64 MiB inside Cursor's window; a reopen takes that VM only with [vm].reuse_per_workspace on and no AI_ENV_BRIDGE_VM pin to another VM";
        assert!(stage.contains(want) && stage.contains("a chat over 64 MiB needs this, with --warm, before it reopens remote"), "{stage}");
    }

    /// `vm terminate --help` and `vm gc --help` say whose chats are synced
    /// first (S9): a running VM's; a suspended one is never woken, its
    /// `/suspend` having pushed the tails once.
    #[test]
    fn vm_terminate_and_gc_helps_say_a_suspended_vm_is_never_woken() {
        let terminate = long_help("vm", "terminate");
        assert!(terminate.contains("the remote chats a running one holds are synced to S3 first (a suspended one is never woken: its /suspend pushed their tails once) (S9)"), "{terminate}");
        let gc = long_help("vm", "gc");
        assert!(gc.contains("the remote chats each running one holds synced to S3 first (S9)"), "{gc}");
    }

    /// Without the shim feature there is no `shim-io` (the bridge-only build).
    #[cfg(not(feature = "shim"))]
    #[test]
    fn shim_io_needs_the_shim_feature() {
        assert!(Cli::command().find_subcommand("shim-io").is_none());
        assert!(parse(&["shim-io", "seed-state", "--path", "/w"]).is_err());
    }

    /// `vm exec --deliver`'s help names the real default (S7):
    /// `[creds] deliver = "env"` makes env the default delivery, not only an
    /// allowed one, so the help never calls fd the default outright.
    #[test]
    fn vm_exec_deliver_help_names_the_configured_default() {
        let mut cli = Cli::command();
        let exec = cli.find_subcommand_mut("vm").and_then(|vm| vm.find_subcommand_mut("exec")).expect("vm exec");
        let help = exec.get_arguments().find(|a| a.get_id() == "deliver").and_then(clap::Arg::get_help).map(ToString::to_string).expect("--deliver has a help line");
        assert!(help.contains("the default is [creds] deliver") && !help.contains("fd (default)"), "{help}");
    }

    /// `ai-env <cmd> <sub> --help`.
    fn long_help(cmd: &str, sub: &str) -> String {
        let mut cli = Cli::command();
        cli.find_subcommand_mut(cmd).and_then(|c| c.find_subcommand_mut(sub)).unwrap_or_else(|| panic!("{cmd} {sub}")).render_long_help().to_string()
    }

    /// `wrapper census --help` names every probe `--record-probes` records
    /// (the catalog's: S8's init-wrapper too), and the gaps that fail it
    /// until both a cold and a warm remote row exist.
    #[test]
    fn wrapper_census_help_names_every_probe_record_probes_writes() {
        let census = long_help("wrapper", "census");
        let recorded: Vec<&str> = crate::bridge::probes::CATALOG.iter().filter(|p| p.recorded_by == "ai-env wrapper census --record-probes").map(|p| p.name).collect();
        assert_eq!(recorded, ["entrypoint", "stock-ext-oauth", "init-wrapper"]);
        let missing: Vec<&&str> = recorded.iter().chain(&["gap:cold", "gap:warm"]).filter(|w| !census.contains(**w)).collect();
        assert!(missing.is_empty(), "census --help does not name {missing:?}:\n{census}");
    }

    /// `session forget --help` names the quarantine it also removes (the
    /// settings captures and settings-sync's backups); `box seed --help`
    /// D3's whole rule, not only a clean checkout.
    #[test]
    fn session_forget_and_box_seed_helps_say_what_they_do() {
        let (forget, seed) = (long_help("session", "forget"), long_help("box", "seed"));
        let wants = [
            (&forget, "its quarantine (the settings captures, diff.json and settings-sync's backups)"),
            (&seed, "fast-forwarded when its checkout is clean, on the same branch and its tip an ancestor of the commit seeded"),
        ];
        let missing: Vec<&str> = wants.iter().filter(|(help, want)| !help.contains(want)).map(|(_, want)| *want).collect();
        assert!(missing.is_empty(), "missing {missing:?}:\n{forget}\n{seed}");
    }

    /// S8 operators: `egress` and `proxy` say who their AWS calls run as (the
    /// operator identity, never the shell's own aws CLI), and `doctor` what
    /// its exit 5 means now: the declared identity's key refused.
    #[test]
    fn the_operator_commands_name_their_identity_in_the_help() {
        let cli = Cli::command();
        let about = |name: &str| cli.find_subcommand(name).and_then(clap::Command::get_about).map(ToString::to_string).unwrap_or_else(|| panic!("{name} has an about"));
        for name in ["egress", "proxy"] {
            let text = about(name);
            assert!(text.contains("(as ai-env-ops: the key of ai-env as …, else credentials/ops.env") && !text.contains("aws CLI"), "{name}: {text}");
        }
        assert!(about("egress").ends_with("; allow as ai-env-deployer)"), "{}", about("egress"));
        let doctor = about("doctor");
        assert!(doctor.ends_with("(exit 1 when any row is [NO ], 5 when AWS refuses the key of the identity ai-env as declared)") && !doctor.contains("credentials are unavailable"), "{doctor}");
    }

    /// `wrapper status` parses with and without `--json`, takes nothing else
    /// (it writes nothing: no `--write`), and its help says it is read-only.
    #[test]
    fn wrapper_status_parses_with_its_json_flag() {
        let Cmd::Wrapper { cmd: WrapperCmd::Status { json: false } } = cmd(&["wrapper", "status"]) else { panic!("wrapper status") };
        let Cmd::Wrapper { cmd: WrapperCmd::Status { json: true } } = cmd(&["wrapper", "status", "--json"]) else { panic!("wrapper status --json") };
        for bad in [&["wrapper", "status", "--write"][..], &["wrapper", "status", "--mode", "remote"], &["wrapper", "status", "now"]] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let help = long_help("wrapper", "status");
        assert!(help.contains("(read-only: no AWS, no Touch ID)") && help.contains("--json"), "{help}");
    }
}

#[cfg(all(test, feature = "shim"))]
mod shim_io_tests {
    use super::{Cli, Cmd};
    use clap::{CommandFactory as _, Parser as _};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(["ai-env", "shim-io"].into_iter().chain(args.iter().copied()))
    }

    /// `shim-io` (S8 C8): hidden from the help, its subcommands are exactly
    /// `wshelper::OPS` with their flags (W3 added the shim's `--record` to
    /// `seed-state` and `seed-apply`). The ops themselves run in
    /// `shim::wshelper`'s tests and `tests/shim_local.rs`.
    #[test]
    fn shim_io_is_hidden_and_parses_its_ops() {
        let cli = Cli::command();
        let io = cli.find_subcommand("shim-io").expect("shim-io");
        assert!(io.is_hide_set());
        let names: Vec<&str> = io.get_subcommands().map(clap::Command::get_name).collect();
        assert_eq!(names, crate::shim::wshelper::OPS);
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("shim-io"), "{help}");
        for args in [
            &["seed-state", "--path", "/Users/mike/w"][..],
            &["seed-state", "--path", "/Users/mike/w", "--record", "{}"],
            &["seed-apply", "--path", "/Users/mike/w", "--mode", "clone", "--branch", "main", "--len", "3"],
            &["seed-apply", "--path", "/h/w", "--mode", "replace", "--branch", "main", "--expect", "abc", "--len", "3", "--record", "{}"],
            &["--home", "/h", "seed-apply", "--path", "/h/w", "--mode", "update", "--detached", "--expect", "abc", "--len", "3"],
            &["codeout", "--path", "/Users/mike/w", "--wip", "--max-bytes", "1024"],
            &["snapshot", "--path", "/Users/mike/w"],
            &["transcript-stat", "--projects", "/p", "--rel", "s/u.jsonl"],
            &["settings", "--path", "/Users/mike/w", "--git", "/usr/bin/git", "--fs-root", "/tmp/vm"],
            // S9 (plans/s9-contracts.md §3.5).
            &["transcript-stat", "--projects", "/p", "--rel", "s/u.jsonl", "--from", "9", "--fp", "ab", "--subtree"],
            &["transcript-read", "--projects", "/p", "--rel", "s/u.jsonl", "--from", "0", "--len", "9"],
            &["transcript-write", "--projects", "/p", "--rel", "s/u.jsonl", "--len", "9", "--sha256", "ab"],
            &["transcript-view", "--projects", "/p", "--rel", "s/u.jsonl", "--n", "10"],
            &["git-cgi", "--path", "/Users/mike/w", "--method", "GET", "--path-info", "/info/refs", "--query", "service=git-upload-pack", "--remote-addr", "10.0.0.1"],
            &[
                "git-cgi",
                "--path",
                "/Users/mike/w",
                "--method",
                "POST",
                "--path-info",
                "/git-upload-pack",
                "--content-type",
                "application/x-git-upload-pack-request",
                "--content-length",
                "9",
                "--git-protocol",
                "version=2",
                "--remote-addr",
                "10.0.0.1",
            ],
        ] {
            let parsed = parse(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
            let Cmd::ShimIo(io) = &parsed.cmd else { panic!("{args:?}") };
            let op = io.op.name();
            assert_eq!(args.iter().find(|a| crate::shim::wshelper::OPS.contains(*a)), Some(&op), "{args:?}");
        }
        // Refused by clap: a mode it does not know, both or neither of --branch and --detached; S9's method, a
        // fingerprint without its offset, a missing length; S8's transcript-put, gone at the S3 cut-over.
        for args in [
            &["seed-apply", "--path", "/w", "--mode", "merge", "--branch", "main", "--len", "1"][..],
            &["seed-apply", "--path", "/w", "--mode", "clone", "--branch", "main", "--detached", "--len", "1"],
            &["seed-apply", "--path", "/w", "--mode", "clone", "--len", "1"],
            &["git-cgi", "--path", "/Users/mike/w", "--method", "PUT", "--path-info", "/info/refs", "--remote-addr", "10.0.0.1"],
            &["git-cgi", "--path", "/Users/mike/w", "--method", "GET", "--path-info", "/HEAD", "--remote-addr", "10.0.0.1"],
            &["transcript-stat", "--projects", "/p", "--rel", "s/u.jsonl", "--fp", "ab"],
            &["transcript-read", "--projects", "/p", "--rel", "s/u.jsonl", "--from", "0"],
            &["transcript-put", "--projects", "/p", "--rel", "s/u.jsonl", "--len", "9"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }
}

#[cfg(all(test, feature = "bridge"))]
mod as_tests {
    use super::{Cli, Cmd};
    use crate::bridge::identity::Identity;
    use clap::{CommandFactory as _, Parser as _};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(["ai-env", "as"].into_iter().chain(args.iter().copied()))
    }

    /// `ai-env as` (S8 operators §3.2): the identity, `--account`, `--check`
    /// and the command after `--`, whose own flags stay its own; `--check`
    /// takes no command and a run needs one; the help says what each
    /// identity is.
    #[test]
    fn as_parses_identity_account_check_and_the_command() {
        let Cmd::As { identity: Identity::Deployer, account: None, check: false, command } = parse(&["deployer", "--", "make", "deploy", "-n"]).unwrap().cmd else { panic!("as deployer") };
        assert_eq!(command, ["make", "deploy", "-n"]);
        let Cmd::As { identity: Identity::Deployer, account: Some(account), command, .. } = parse(&["--account", "123456789012", "deployer", "--", "true"]).unwrap().cmd else { panic!("--account") };
        assert_eq!((account.as_str(), command), ("123456789012", vec!["true".to_string()]));
        let Cmd::As { identity: Identity::Ops, command, .. } = parse(&["ops", "aws", "sts", "get-caller-identity", "--region", "eu-central-1"]).unwrap().cmd else { panic!("without --") };
        assert_eq!(command, ["aws", "sts", "get-caller-identity", "--region", "eu-central-1"]);
        for (word, want) in [("ops", Identity::Ops), ("root", Identity::Root), ("ambient", Identity::Ambient), ("deployer", Identity::Deployer)] {
            let Cmd::As { identity, check: true, command, account: None } = parse(&["--check", word]).unwrap().cmd else { panic!("--check {word}") };
            assert_eq!((identity, command.is_empty()), (want, true));
        }
        for bad in [&["admin", "--", "true"][..], &["deployer"], &["--check", "ops", "--", "true"], &["--check"], &[]] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        // Right after the identity a flag is `as`'s own (`--help` is its help, never a command); once the command
        // starts, every word is the command's.
        assert_eq!(parse(&["deployer", "--help"]).err().map(|e| e.kind()), Some(clap::error::ErrorKind::DisplayHelp));
        let Cmd::As { identity: Identity::Ops, check: true, .. } = parse(&["ops", "--check"]).unwrap().cmd else { panic!("ops --check") };
        let Cmd::As { command, check: false, .. } = parse(&["ops", "make", "--help", "--check"]).unwrap().cmd else { panic!("the command's flags") };
        assert_eq!(command, ["make", "--help", "--check"]);
        let help = Cli::command().find_subcommand_mut("as").expect("as").render_help().to_string();
        let words = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(words.contains("Run CMD as one AWS operator identity: deployer (its key pasted from Strongbox), ops (credentials/ops.env, one Touch ID), root (the bootstrap and break-glass only) or ambient (the aws CLI's own credentials, never the root)"), "{help}");
        assert!(help.contains("--account") && help.contains("--check"), "{help}");
    }
}
