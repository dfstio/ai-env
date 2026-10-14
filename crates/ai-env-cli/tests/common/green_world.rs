//! S7's seeded green vpc world, shared (S8 phase 0, plans/s8-design-tests.md
//! §1.2): what a vpc VM needs before a credential may reach it, laid out
//! under one root. The made-up egress connector configured and answered by
//! the file-backed fake (its `/health` offering the credential cache), a
//! passing `egress check` recorded an hour ago for one image version with
//! that connector's facts and the fake's build, a `no-dns` dns-path verdict,
//! the fake age and the keystore key, and the runtime key and a dummy
//! setup-token sealed by the real `creds` commands. A remote session always
//! needs vpc egress, so S8's remote rig (`tests/common/remote.rs`) builds on
//! it; `tests/shim_bridge_local.rs` (S7, where it came from) includes it with
//! `#[path]`. No token, key or account literal: the token and the runtime key
//! are built at run time from parts.
#![allow(dead_code)]

use ai_env_cli::bridge::api::FAKE_IMAGE_ARN;
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The documentation account's made-up egress connector (the fixture's ARN).
pub const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
/// The public test recipients of tests/cli.rs: an SE tag one and an X25519 recovery one.
pub const SE_REC: &str = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
pub const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";
/// The fake image version's build (`FakeState::new`).
pub const BUILD: i64 = 1_789_804_800;
/// The fake age (tests/fakes/age.sh), copied into a world's `bin/` under each name the code looks up.
pub const FAKE_AGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh");
/// How long one `creds` command of the seeding may take.
const LIMIT: Duration = Duration::from_secs(60);

/// The connector's `GetNetworkConnector` answer (the fixture).
#[must_use]
pub fn connector_doc() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/egress/lambda-core.get-network-connector.json")).unwrap()
}

/// A stand-in setup-token of the real shape, built at run time with `tail`.
#[must_use]
pub fn setup_token(tail: &str) -> String {
    format!("sk-ant-oat01-{}{tail}", "Kq4_".repeat(20))
}

/// The secret of the runtime key [`Green::seed`] seals, built at run time.
#[must_use]
pub fn runtime_key_secret() -> String {
    format!("{}cred", "Tq8+".repeat(9))
}

/// How many decrypts (Touch IDs) the fake age logged in `age_log` so far.
#[must_use]
pub fn decrypts(age_log: &Path) -> usize {
    std::fs::read_to_string(age_log).unwrap_or_default().lines().filter(|l| l.starts_with("age -d ")).count()
}

/// One world's layout: `root` holds `bridge/` (its `AI_ENV_BRIDGE_DIR`),
/// `keys/` (its `AI_ENV_DIR`), `bin/` (the fake age, first on its `PATH`)
/// and `age.log` (the fake age's log); `fake` is the file-backed fake's
/// state; `roots` are its `[workspaces].roots`.
pub struct Green<'a> {
    pub root: &'a Path,
    pub fake: &'a Path,
    pub roots: &'a [PathBuf],
}

impl Green<'_> {
    #[must_use]
    pub fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }

    #[must_use]
    pub fn age_log(&self) -> PathBuf {
        self.root.join("age.log")
    }

    #[must_use]
    pub fn bridge(&self) -> PathBuf {
        self.root.join("bridge")
    }

    /// Everything but a VM a credential needs: the fake age (copies, which a
    /// test may replace in place) and the keystore key; bridge.toml with the
    /// fake image, the connector and the roots; the connector and its answer
    /// in the fake, whose `/health` offers the credential cache; a passing
    /// `egress check` recorded an hour ago for `image_version` with the
    /// connector's facts and the fake's build; a `no-dns` dns-path verdict;
    /// and the runtime key and `token` sealed by the real `creds` commands,
    /// run through `sealed` (`ai-env <args>` of this world, with the fake age
    /// first on `PATH`, its log, the fake API's unseal knob and the hidden
    /// paste read from stdin). `combined`: `creds setup-token` also builds
    /// combined.env (a Touch ID of its own: one prompt per credentialed
    /// command from then on); else `--no-combined` (the token is a Touch ID
    /// of its own).
    pub fn seed(&self, token: &str, image_version: &str, combined: bool, sealed: &dyn Fn(&[&str]) -> Command) {
        use ai_env_cli::bridge::egress::{ConnectorFacts, EgressVerified, VerifiedRecord, DNS_NONE, DNS_RULE};
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(self.bin()).unwrap();
        for name in ["age", "age-keygen", "age-plugin-se"] {
            let dst = self.bin().join(name);
            std::fs::copy(FAKE_AGE, &dst).unwrap();
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let key = self.root.join("keys").join("keys").join("ai-env-bridge");
        std::fs::create_dir_all(&key).unwrap();
        std::fs::write(key.join("identity.txt"), format!("# public key: {SE_REC}\nAGE-PLUGIN-SE-1FAKEFAKE\n")).unwrap();
        std::fs::write(key.join("recipients.txt"), format!("{SE_REC}\n{X_REC}\n")).unwrap();
        std::fs::write(key.join("meta.toml"), "created = \"2026-09-29\"\naccess_control = \"none\"\n").unwrap();
        let roots: Vec<String> = self.roots.iter().map(|r| format!("{:?}", r.display().to_string())).collect();
        let toml = format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\negress_connector_arn = \"{CONNECTOR}\"\n\n[workspaces]\nroots = [{}]\n", roots.join(", "));
        std::fs::create_dir_all(self.bridge()).unwrap();
        std::fs::write(self.bridge().join("bridge.toml"), toml).unwrap();
        FileFakeMicrovmApi::open(self.fake)
            .unwrap()
            .with(|s| {
                s.connectors.insert(CONNECTOR.to_string(), connector_doc());
                s.health_caps = vec![ai_env_cli::wire::frame::CAP_CREDENTIAL_CACHE.to_string()];
                Ok(())
            })
            .unwrap();
        let now = ai_env_cli::wire::time::unix_now();
        let record = VerifiedRecord {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: image_version.into(),
            connector: CONNECTOR.into(),
            vm_id: "microvm-checked".into(),
            at: ai_env_cli::wire::time::rfc3339_utc(now - 3600),
            dns: DNS_NONE.into(),
            dns_rule: DNS_RULE,
            connector_facts: ConnectorFacts::from_get(&connector_doc()).unwrap(),
            image_created_at: Some(BUILD),
            ..VerifiedRecord::default()
        };
        std::fs::create_dir_all(self.bridge().join("state")).unwrap();
        std::fs::write(self.bridge().join("state").join("egress-verified.toml"), toml::to_string(&EgressVerified { records: vec![record], ..EgressVerified::default() }).unwrap()).unwrap();
        std::fs::create_dir_all(self.bridge().join("lab")).unwrap();
        let dns_row = serde_json::json!({ "probe": "dns-path", "verdict": DNS_NONE, "ts": ai_env_cli::wire::time::rfc3339_utc(now - 7200) });
        std::fs::write(self.bridge().join("lab").join("probes.jsonl"), format!("{dns_row}\n")).unwrap();
        let aws = format!(
            "{{\"AccessKey\": {{\"UserName\": \"ai-env-runtime\", \"AccessKeyId\": \"AKIA{}\", \"Status\": \"Active\", \"SecretAccessKey\": \"{}\"}}}}",
            "CRED".repeat(4),
            runtime_key_secret()
        );
        let o = run(sealed(&["creds", "aws-set"]), aws.into_bytes());
        assert!(o.status.success(), "creds aws-set: {}", String::from_utf8_lossy(&o.stderr));
        let mut args = vec!["creds", "setup-token", "--stdin"];
        if !combined {
            args.push("--no-combined");
        }
        let o = run(sealed(&args), format!("{token}\n").into_bytes());
        assert!(o.status.success(), "creds setup-token: {}", String::from_utf8_lossy(&o.stderr));
    }
}

/// Run `cmd` to its end with `stdin`, bounded by [`LIMIT`] (killed and failed past it).
fn run(mut cmd: Command, stdin: Vec<u8>) -> Output {
    fn read_all(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = r.read_to_end(&mut v);
            v
        })
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
    let mut sink = child.stdin.take().expect("piped stdin");
    let feeder = std::thread::spawn(move || {
        let _ = sink.write_all(&stdin);
    });
    let (out, err) = (read_all(child.stdout.take().expect("piped stdout")), read_all(child.stderr.take().expect("piped stderr")));
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("a seeding command ran past {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    feeder.join().expect("the stdin feeder");
    Output { status, stdout: out.join().expect("stdout reader"), stderr: err.join().expect("stderr reader") }
}
