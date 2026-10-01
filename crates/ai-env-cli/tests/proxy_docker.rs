//! S5 proxy host in Docker (`make test-proxy`; opt-in: AI_ENV_PROXY_TESTS=1,
//! the Docker tests `#[ignore]`d and skipping with a message without it):
//! squid from the AL2023 container image (pinned by digest) running
//! infra/proxy/{squid.conf,allow.txt} as the stack renders them, installed by
//! infra/proxy/reload.sh, which fetches its four parameters through
//! tests/fakes/aws.sh (`FAKE_AWS_SSM_DIR`: a bind mount the tests write). A
//! dnsmasq stub is the proxy's only resolver and logs every query; curl and
//! python clients sit on the same private Docker network; a second network
//! (TEST-NET-3, outside `to_private`) holds a plain TCP echo server on :443,
//! so tunnels open without internet. One pair of networks per test, named
//! and labelled with the pid. Covered: the allowlist and its deny order, DNS
//! rebinding, the VM source ACL, no DNS for a denied name, hosts-only
//! logging, the golden parameter hashes and `applied=` of `--status`,
//! refusals, rollback, restart-on-shrink closing open tunnels,
//! `--if-changed`, the exit codes, the host grammar against
//! `egress::is_valid_host`, and the user-data bootstrap (a dry run with
//! stubbed dnf and systemctl; with AI_ENV_PROXY_SYSTEMD=1 also a boot under a
//! real systemd in a privileged container; the static checks run in every
//! `cargo test`).
//!
//! Needs Docker; only the upstream-401 case needs internet from Docker (it
//! fails, never skips, without it). AI_ENV_PROXY_IMAGE overrides the base
//! image ([`BASE_IMAGE`]); AI_ENV_PROXY_SUBNET and AI_ENV_PROXY_ECHO_SUBNET
//! the networks' IPv4 /24s ([`DEFAULT_SUBNET`], [`DEFAULT_ECHO_SUBNET`]).
//! Every docker call has a deadline; what a test creates is removed on drop,
//! and what a dead earlier run left is swept before the first lab.
use ai_env_cli::bridge::egress::{self, is_valid_host, parse_extras, parse_hosts, parse_reload_status, parse_squid_line, value_sha256, SquidLine, GOLDEN};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const FAKE_AWS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/aws.sh");
/// `public.ecr.aws/amazonlinux/amazonlinux:2023` of 30 Sep 2026
/// (2023.12.20260930), the multi-arch index; its arm64 repo has squid 6.13.
const BASE_IMAGE: &str = "public.ecr.aws/amazonlinux/amazonlinux@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061";
/// Outside Docker's default address pools (172.17–31/16, 192.168/16).
const DEFAULT_SUBNET: &str = "10.213.53.0/24";
/// TEST-NET-3: public to squid (not in `to_private`), so a tunnel may reach it.
const DEFAULT_ECHO_SUBNET: &str = "203.0.113.0/24";
/// The derived image, cached under a tag hashed from this text (base
/// included) and the fake: squid, jq, util-linux (flock, logger) and
/// logrotate as on the AMI, squid's RPM kept in /opt/rpms (the dry run
/// installs it over the deny-all placeholder); dnsmasq for the stub resolver;
/// systemd only for `systemd-analyze verify` (never PID 1, so the reload
/// script sees no systemd).
const DOCKERFILE: &str = "FROM {base}\n\
RUN dnf -y -q --setopt=install_weak_deps=0 install squid jq util-linux logrotate dnsmasq systemd \\\n \
 && dnf -y -q reinstall --downloadonly --downloaddir=/opt/rpms squid && dnf clean all && rm -rf /var/cache/dnf\n\
COPY aws.sh /usr/local/bin/aws\n\
RUN chmod 0755 /usr/local/bin/aws\n";
const PORT: &str = "3128";
// Host parts of the test networks' addresses.
const PROXY: u8 = 10;
const VM: u8 = 17;
const OUTSIDER: u8 = 99;
const RESOLVER: u8 = 53;
const ECHO: u8 = 10;
const PROXY_ON_ECHO: u8 = 2;
/// Allowed names the stub resolver answers with addresses squid must
/// refuse (DNS rebinding); one answer per family, `mixed` two A records.
const REBIND: [(&str, &str); 10] = [
    ("meta.rebind.test", "169.254.169.254"),
    ("ten.rebind.test", "10.1.2.3"),
    ("loop.rebind.test", "127.0.0.1"),
    ("cgnat.rebind.test", "100.64.0.1"),
    ("one72.rebind.test", "172.16.0.1"),
    ("one92.rebind.test", "192.168.1.1"),
    ("zero.rebind.test", "0.0.0.1"),
    ("ula.rebind.test", "fd00:ec2::254"),
    ("mapped.rebind.test", "::ffff:169.254.169.254"),
    ("mixed.rebind.test", "93.184.215.14 10.9.9.9"),
];
/// The echo server's names: `echo` is in the base allowlist, `extra` only
/// when a test adds it to `extras`.
const ECHO_HOST: &str = "echo.tunnel.test";
const EXTRA_HOST: &str = "extra.tunnel.test";
/// curl's text for a refused CONNECT (its exit code changed in 8.20: 56 → 7).
const DENIED: &str = "CONNECT tunnel failed, response 403";
const NO_EXTRAS: &str = "# extras: none\n";
const NO_SUSPENDED: &str = "# suspended: none\n";
const STATUS_KEYS: [&str; 10] = ["squid", "allowed", "extras", "suspended", "sha256_squid.conf", "sha256_allow", "sha256_extras", "sha256_suspended", "parse", "applied"];
/// A line echo server on :443 (no TLS: squid only relays bytes).
const ECHO_SERVER: &str = "import socketserver
class H(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.wfile.write(line)
            self.wfile.flush()
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
S(('0.0.0.0', 443), H).serve_forever()
";
/// A tunnel kept open: CONNECT host:443 through the proxy, then a ping
/// every 0.2 s; argv proxy port host state-file; the state file says
/// `open N`, `closed` or `refused <status line>`.
const TUNNEL_CLIENT: &str = "import os, socket, sys, time
proxy, port, host, state = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
def put(s):
    with open(state + '.new', 'w') as f:
        f.write(s + '\\n')
    os.replace(state + '.new', state)
c = socket.create_connection((proxy, port), timeout=5)
c.sendall(('CONNECT %s:443 HTTP/1.1\\r\\nHost: %s:443\\r\\n\\r\\n' % (host, host)).encode())
head = b''
while not head.endswith(b'\\r\\n\\r\\n'):
    d = c.recv(1)
    if not d:
        break
    head += d
status = head.split(b'\\r\\n')[0].decode(errors='replace')
if ' 200 ' not in status + ' ':
    put('refused ' + status)
    sys.exit(0)
f = c.makefile('rb')
n = 0
while True:
    try:
        c.sendall(b'ping\\n')
        if f.readline() != b'ping\\n':
            raise EOFError
    except Exception:
        put('closed')
        break
    n += 1
    put('open %d' % n)
    time.sleep(0.2)
";
/// Stands in for squid on the reload script's PATH: `-k reconfigure` fails
/// while /tmp/fail-reconfigure exists (`once`: it is removed on the way).
const SQUID_WRAPPER: &str = "#!/bin/sh
if [ \"$1 $2\" = '-k reconfigure' ] && [ -e /tmp/fail-reconfigure ]; then
  [ \"$(cat /tmp/fail-reconfigure)\" = always ] || rm -f /tmp/fail-reconfigure
  echo 'test wrapper: -k reconfigure refused' >&2
  exit 1
fi
exec /usr/sbin/squid \"$@\"
";

fn enabled() -> bool {
    if std::env::var("AI_ENV_PROXY_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: the S5 proxy Docker tests run only with AI_ENV_PROXY_TESTS=1 (make test-proxy)");
    false
}

fn repo(rel: &str) -> PathBuf {
    Path::new(REPO).join(rel).canonicalize().unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo(rel)).unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

/// `cmd` under a deadline; `Err` naming it when it cannot start or
/// overruns (it is killed then).
fn try_run(cmd: &mut Command, secs: u64) -> Result<Output, String> {
    let what = format!("{cmd:?}");
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{what}: {e}"))?;
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Output { status, stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default() }),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what}: no exit within {secs} s"));
            }
            Err(e) => return Err(format!("{what}: {e}")),
        }
    }
}

fn docker(args: &[&str], secs: u64) -> Output {
    try_run(Command::new("docker").args(args), secs).unwrap_or_else(|e| panic!("{e}"))
}

fn docker_ok(args: &[&str], secs: u64) -> String {
    let out = docker(args, secs);
    assert!(out.status.success(), "docker {args:?}: {}", text(&out.stderr));
    text(&out.stdout).trim().to_string()
}

static SEQ: AtomicUsize = AtomicUsize::new(0);
/// One lab at a time: they share the subnets (and `--test-threads` may be > 1).
static SERIAL: Mutex<()> = Mutex::new(());

/// A name unique to this process and call (`aienv-proxytest-<pid>-<n>`).
fn unique() -> String {
    format!("aienv-proxytest-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst))
}

/// The labels on everything a test creates: the sweep's key.
fn labels() -> [String; 4] {
    ["--label".into(), "ai-env.test=proxy_docker".into(), "--label".into(), format!("ai-env.test.pid={}", std::process::id())]
}

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Containers, then networks, labelled `ai-env.test=proxy_docker` whose
/// `ai-env.test.pid` is no live process (an earlier run that died before
/// its Drop guards): removed once per process.
fn sweep_leftovers() {
    static SWEPT: OnceLock<()> = OnceLock::new();
    SWEPT.get_or_init(|| {
        let live = |pid: &str| pid.parse::<u32>().is_ok_and(|p| try_run(Command::new("/bin/kill").args(["-0", &p.to_string()]), 10).is_ok_and(|o| o.status.success()));
        for (list, name, rm) in [(&["ps", "-a"][..], "{{.Names}}", &["rm", "-f"][..]), (&["network", "ls"][..], "{{.Name}}", &["network", "rm"][..])] {
            let format = format!("{name}\t{{{{.Label \"ai-env.test.pid\"}}}}");
            let mut args = list.to_vec();
            args.extend_from_slice(&["--filter", "label=ai-env.test=proxy_docker", "--format", &format]);
            for line in docker_ok(&args, 60).lines() {
                let (obj, pid) = line.split_once('\t').unwrap_or((line, ""));
                if !obj.is_empty() && !live(pid) {
                    eprintln!("proxy_docker: removing {obj}, left by pid {pid:?}");
                    let mut rm = rm.to_vec();
                    rm.push(obj);
                    let _ = docker(&rm, 60);
                }
            }
        }
    });
}

/// The derived image (built once per digest + Dockerfile + fake), its squid
/// version printed. A missing daemon or a failed build is a failure.
fn image() -> String {
    static IMAGE: OnceLock<String> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            let v = docker(&["version", "--format", "{{.Server.Version}}"], 30);
            assert!(v.status.success(), "the Docker daemon is not running: {}", text(&v.stderr));
            let base = std::env::var("AI_ENV_PROXY_IMAGE").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| BASE_IMAGE.to_string());
            let dockerfile = DOCKERFILE.replace("{base}", &base);
            let fake = std::fs::read_to_string(FAKE_AWS).unwrap();
            let tag = format!("ai-env-proxy-test:{}", &value_sha256(&format!("{dockerfile}\n{fake}"))[..16]);
            if !docker(&["image", "inspect", "--format", "{{.Id}}", &tag], 30).status.success() {
                if !docker(&["image", "inspect", "--format", "{{.Id}}", &base], 30).status.success() {
                    docker_ok(&["pull", "--platform", "linux/arm64", &base], 900);
                }
                let ctx = tempfile::tempdir().unwrap();
                std::fs::write(ctx.path().join("Dockerfile"), &dockerfile).unwrap();
                std::fs::copy(FAKE_AWS, ctx.path().join("aws.sh")).unwrap();
                docker_ok(&["build", "--platform", "linux/arm64", "--label", "ai-env.test=proxy_docker", "-t", &tag, &ctx.path().display().to_string()], 1200);
            }
            let name = unique();
            let v = docker_ok(&["run", "--rm", "--name", &name, "--network", "none", "--platform", "linux/arm64", &tag, "squid", "-v"], 60);
            let first = v.lines().next().unwrap_or_default().to_string();
            eprintln!("proxy_docker: {tag} from {base}: {first}");
            assert!(first.starts_with("Squid Cache: Version 6."), "{v}");
            tag
        })
        .clone()
}

/// What a test created, removed on drop (containers, then networks).
#[derive(Default)]
struct Cleanup {
    containers: Vec<String>,
    networks: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in self.containers.iter().rev() {
            let _ = try_run(Command::new("docker").args(["rm", "-f", c]), 60);
        }
        for n in self.networks.iter().rev() {
            let _ = try_run(Command::new("docker").args(["network", "rm", n]), 60);
        }
    }
}

/// curl through the proxy: `%{http_code}`, `%{http_connect}` and stderr.
#[derive(Debug)]
struct Reply {
    code: String,
    connect: String,
    err: String,
}

#[track_caller]
fn assert_denied(r: &Reply, what: &str) {
    assert!(r.err.contains(DENIED), "{what}: want curl's {DENIED:?}, got {r:?}");
    assert_eq!(r.connect, "403", "{what}: {r:?}");
}

/// The repo's allowlist plus the names the stub resolver answers.
fn base_allow() -> String {
    let rebind: String = REBIND.iter().map(|(h, _)| format!("{h}\n")).collect();
    format!("{}# names the test's stub resolver answers\n{rebind}{ECHO_HOST}\n", read("infra/proxy/allow.txt"))
}

/// The repo's squid.conf with the stack's placeholders filled.
fn render_squid(proxy_ip: &str, port: &str, vms: &str, resolvers: &str) -> String {
    read("infra/proxy/squid.conf").replace("@PROXY_IP@", proxy_ip).replace("@PORT@", port).replace("@VMS@", vms).replace("@RESOLVERS@", resolvers)
}

/// `(cidr, "a.b.c")` of an IPv4 /24 from `var`, else `default`.
fn subnet(var: &str, default: &str) -> (String, String) {
    let cidr = std::env::var(var).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string());
    let prefix = cidr.strip_suffix(".0/24").filter(|p| p.split('.').count() == 3 && p.split('.').all(|o| o.parse::<u8>().is_ok())).unwrap_or_else(|| panic!("{var}={cidr:?}: want an IPv4 /24 like {default}")).to_string();
    (cidr, prefix)
}

/// Two private networks: the lab's (stub resolver, proxy, a VM client at
/// the one address `@VMS@` names) and the echo network (the echo server;
/// the proxy has a leg there). The proxy has the base parameters applied
/// and squid running. Fields drop in order: containers and networks first,
/// the parameter directory next, the serial lock last.
struct Lab {
    cleanup: Cleanup,
    name: String,
    prefix: String,
    echo_prefix: String,
    image: String,
    ssm: tempfile::TempDir,
    _serial: MutexGuard<'static, ()>,
}

impl Lab {
    /// `None` (the test skips) without AI_ENV_PROXY_TESTS=1.
    fn up() -> Option<Lab> {
        Lab::create(false)
    }

    /// The proxy container runs systemd as PID 1 (privileged), nothing
    /// applied yet: the test runs user-data. `None` (skips) without
    /// AI_ENV_PROXY_TESTS=1 and AI_ENV_PROXY_SYSTEMD=1.
    fn up_systemd() -> Option<Lab> {
        if enabled() && std::env::var("AI_ENV_PROXY_SYSTEMD").as_deref() != Ok("1") {
            eprintln!("skipped: the systemd boot test needs a privileged container; set AI_ENV_PROXY_SYSTEMD=1 too");
            return None;
        }
        Lab::create(true)
    }

    fn create(systemd: bool) -> Option<Lab> {
        if !enabled() {
            return None;
        }
        let serial = serial();
        sweep_leftovers();
        let image = image();
        let (cidr, prefix) = subnet("AI_ENV_PROXY_SUBNET", DEFAULT_SUBNET);
        let (echo_cidr, echo_prefix) = subnet("AI_ENV_PROXY_ECHO_SUBNET", DEFAULT_ECHO_SUBNET);
        let name = unique();
        let mut lab = Lab { cleanup: Cleanup::default(), name: name.clone(), prefix, echo_prefix, image, ssm: tempfile::tempdir().unwrap(), _serial: serial };
        for (net, cidr) in [(name.clone(), cidr), (format!("{name}-echo"), echo_cidr)] {
            let labels = labels();
            let mut args = vec!["network", "create", "--driver", "bridge", "--subnet", &cidr];
            args.extend(labels.iter().map(String::as_str));
            args.push(&net);
            let out = docker(&args, 60);
            assert!(out.status.success(), "docker network create --subnet {cidr}: {} (another network on it? set AI_ENV_PROXY_SUBNET / AI_ENV_PROXY_ECHO_SUBNET to a free /24)", text(&out.stderr));
            lab.cleanup.networks.push(net);
        }
        // --conf-file=/dev/null: the package's dnsmasq.conf listens on lo only. Other names
        // go upstream (Docker's resolver); --local keeps the test domains' answers local.
        let mut dns: Vec<String> = ["dnsmasq", "-k", "--conf-file=/dev/null", "--log-queries", "--log-facility=-", "--no-hosts", "--cache-size=0", "--local=/rebind.test/", "--local=/tunnel.test/"].map(String::from).to_vec();
        for (host, addrs) in REBIND {
            dns.extend(addrs.split(' ').map(|a| format!("--address=/{host}/{a}")));
        }
        for host in [ECHO_HOST, EXTRA_HOST] {
            dns.push(format!("--address=/{host}/{}", lab.echo_ip(ECHO)));
        }
        lab.start("dns", &name, RESOLVER, &["--init"], &dns.iter().map(String::as_str).collect::<Vec<_>>());
        lab.start("echo", &format!("{name}-echo"), ECHO, &["--init"], &["python3", "-c", ECHO_SERVER]);
        let ssm_mount = format!("{}:/ssm:ro", lab.ssm.path().canonicalize().unwrap().display());
        let script = format!("{}:/usr/local/sbin/ai-env-proxy-reload:ro", repo("infra/proxy/reload.sh").display());
        if systemd {
            // systemd must be PID 1 (no --init); `docker restart` reboots it.
            lab.start("proxy", &name, PROXY, &["--privileged", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock", "-e", "FAKE_AWS_SSM_DIR=/ssm", "-v", &ssm_mount], &["/usr/sbin/init"]);
        } else {
            lab.start("proxy", &name, PROXY, &["--init", "-e", "FAKE_AWS_SSM_DIR=/ssm", "-v", &ssm_mount, "-v", &script], &["sleep", "infinity"]);
        }
        docker_ok(&["network", "connect", "--ip", &lab.echo_ip(PROXY_ON_ECHO), &format!("{name}-echo"), &lab.container("proxy")], 60);
        lab.start("vm", &name, VM, &["--init"], &["sleep", "infinity"]);
        lab.put("squid.conf", &lab.squid_conf());
        lab.put("allow", &base_allow());
        lab.put("extras", NO_EXTRAS);
        lab.put("suspended", NO_SUSPENDED);
        if systemd {
            return Some(lab);
        }
        lab.sh("proxy", &format!("mkdir -p /etc/ai-env-proxy && printf 'PARAM_PREFIX=%s\\nREGION=eu-central-1\\nLOG_GROUP=%s\\n' {} {} > /etc/ai-env-proxy/env", egress::PARAMETER_PREFIX, egress::LOG_GROUP));
        assert!(lab.reload_ok(&[]).contains("applied (started)"));
        lab.wait_ready();
        Some(lab)
    }

    fn ip(&self, host: u8) -> String {
        format!("{}.{host}", self.prefix)
    }

    fn echo_ip(&self, host: u8) -> String {
        format!("{}.{host}", self.echo_prefix)
    }

    fn container(&self, role: &str) -> String {
        format!("{}-{role}", self.name)
    }

    fn start(&mut self, role: &str, net: &str, host: u8, extra: &[&str], cmd: &[&str]) {
        let (cname, image, labels) = (self.container(role), self.image.clone(), labels());
        let ip = if net.ends_with("-echo") { self.echo_ip(host) } else { self.ip(host) };
        self.cleanup.containers.push(cname.clone());
        let mut args = vec!["run", "-d", "--platform", "linux/arm64", "--name", &cname, "--hostname", role, "--network", net, "--ip", &ip];
        args.extend(labels.iter().map(String::as_str));
        args.extend_from_slice(extra);
        args.push(&image);
        args.extend_from_slice(cmd);
        docker_ok(&args, 120);
    }

    fn exec(&self, role: &str, env: &[&str], cmd: &[&str], secs: u64) -> Output {
        let cname = self.container(role);
        let mut args = vec!["exec"];
        for e in env {
            args.extend_from_slice(&["-e", *e]);
        }
        args.push(&cname);
        args.extend_from_slice(cmd);
        docker(&args, secs)
    }

    #[track_caller]
    fn sh(&self, role: &str, script: &str) -> String {
        let out = self.exec(role, &[], &["sh", "-c", script], 60);
        assert!(out.status.success(), "{role}: {script}: {}", text(&out.stderr));
        text(&out.stdout)
    }

    /// The parameter as the fake serves it (`<dir>/ai-env/proxy/<param>`), written by rename.
    fn put(&self, param: &str, value: &str) {
        let dir = self.ssm.path().join(egress::PARAMETER_PREFIX.trim_start_matches('/'));
        std::fs::create_dir_all(&dir).unwrap();
        let tmp = dir.join(format!(".{param}.new"));
        std::fs::write(&tmp, value).unwrap();
        std::fs::rename(&tmp, dir.join(param)).unwrap();
    }

    fn delete(&self, param: &str) {
        std::fs::remove_file(self.ssm.path().join(egress::PARAMETER_PREFIX.trim_start_matches('/')).join(param)).unwrap();
    }

    /// A file for the containers under /ssm (read-only there).
    fn share(&self, name: &str, body: &[u8]) {
        std::fs::write(self.ssm.path().join(name), body).unwrap();
    }

    /// squid.conf as the stack would render it here: `@VMS@` is the VM client's /32.
    fn squid_conf(&self) -> String {
        render_squid(&self.ip(PROXY), PORT, &format!("{}/32", self.ip(VM)), &self.ip(RESOLVER))
    }

    fn reload(&self, env: &[&str], args: &[&str]) -> Output {
        let mut cmd = vec!["ai-env-proxy-reload"];
        cmd.extend_from_slice(args);
        self.exec("proxy", env, &cmd, 180)
    }

    /// Exit 0; its stderr.
    #[track_caller]
    fn reload_ok(&self, args: &[&str]) -> String {
        let out = self.reload(&[], args);
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "ai-env-proxy-reload {args:?}: {err}");
        err
    }

    /// `--status`, exit 0 and one line: (the raw line, its pairs).
    #[track_caller]
    fn status(&self) -> (String, BTreeMap<String, String>) {
        let out = self.reload(&[], &["--status"]);
        assert_eq!(out.status.code(), Some(0), "--status: {}", text(&out.stderr));
        let line = text(&out.stdout);
        assert_eq!(line.lines().count(), 1, "one line: {line:?}");
        let pairs = parse_reload_status(line.trim()).unwrap_or_else(|e| panic!("{e}: {line:?}"));
        (line.trim().to_string(), pairs)
    }

    fn curl(&self, from: &str, url: &str) -> Reply {
        self.curl_with(from, &[], url)
    }

    fn curl_with(&self, from: &str, extra: &[&str], url: &str) -> Reply {
        let proxy = format!("http://{}:{PORT}", self.ip(PROXY));
        let mut args = vec!["curl", "-sS", "-o", "/dev/null", "--max-time", "20", "--connect-timeout", "5", "-x", &proxy, "-w", "%{http_code} %{http_connect}"];
        args.extend_from_slice(extra);
        args.push(url);
        let out = self.exec(from, &[], &args, 60);
        let s = text(&out.stdout);
        let mut f = s.split_whitespace();
        Reply { code: f.next().unwrap_or_default().to_string(), connect: f.next().unwrap_or_default().to_string(), err: text(&out.stderr) }
    }

    /// A tunnel to the echo server's `host`: `curl -p` sends CONNECT, then
    /// plain HTTP the server echoes (no TLS handshake to hang on).
    fn echo(&self, host: &str) -> Reply {
        self.curl_with("vm", &["-p"], &format!("http://{host}:443/"))
    }

    /// `probe` until `done` holds; the reply and how long it took. Fails after `secs`.
    #[track_caller]
    fn until(&self, what: &str, secs: u64, probe: impl Fn() -> Reply, done: impl Fn(&Reply) -> bool) -> (Reply, Duration) {
        let started = Instant::now();
        loop {
            let r = probe();
            if done(&r) {
                return (r, started.elapsed());
            }
            assert!(started.elapsed() < Duration::from_secs(secs), "{what}: not within {secs} s: {r:?}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[track_caller]
    fn curl_until(&self, url: &str, secs: u64, done: impl Fn(&Reply) -> bool) -> (Reply, Duration) {
        self.until(url, secs, || self.curl("vm", url), done)
    }

    #[track_caller]
    fn echo_until(&self, host: &str, secs: u64, done: impl Fn(&Reply) -> bool) -> (Reply, Duration) {
        self.until(host, secs, || self.echo(host), done)
    }

    /// squid answers (a refused CONNECT) after its start.
    fn wait_ready(&self) {
        let started = Instant::now();
        loop {
            let r = self.curl("vm", "https://ready.example.org/");
            if r.err.contains(DENIED) {
                return;
            }
            assert!(started.elapsed() < Duration::from_secs(30), "squid never answered: {r:?}\n{}", self.sh("proxy", "tail -n 30 /var/log/squid/cache.log 2>&1 || true"));
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Internet from Docker, which the upstream-401 case needs: fail (never skip) without it.
    fn require_internet(&self) {
        let out = self.exec("proxy", &[], &["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20", "https://api.anthropic.com/v1/models"], 60);
        assert!(out.status.success(), "this case needs internet from Docker: api.anthropic.com is unreachable from a container ({}). Fix the Docker network (or run where it is reachable); the other cases do not need it.", text(&out.stderr).trim());
    }

    /// A tunnel to `host`:443 held open by a client in the VM container; its state file once open.
    #[track_caller]
    fn open_tunnel(&self, host: &str, tag: &str) -> String {
        let state = format!("/tmp/tunnel-{tag}");
        docker_ok(&["exec", "-d", &self.container("vm"), "python3", "-c", TUNNEL_CLIENT, &self.ip(PROXY), PORT, host, &state], 30);
        self.tunnel_until(&state, 10, |s| s.starts_with("open"));
        state
    }

    fn tunnel(&self, state: &str) -> String {
        self.sh("vm", &format!("cat {state} 2>/dev/null || true")).trim().to_string()
    }

    /// The tunnel's state once `done` holds, and how long that took.
    #[track_caller]
    fn tunnel_until(&self, state: &str, secs: u64, done: impl Fn(&str) -> bool) -> Duration {
        let started = Instant::now();
        loop {
            let s = self.tunnel(state);
            if done(&s) {
                return started.elapsed();
            }
            assert!(started.elapsed() < Duration::from_secs(secs), "{state}: still {s:?} after {secs} s");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn access_log(&self) -> String {
        self.sh("proxy", "cat /var/log/squid/access.log 2>/dev/null || true")
    }

    /// Every access-log line, each of which must parse.
    #[track_caller]
    fn lines(&self) -> Vec<SquidLine> {
        let log = self.access_log();
        log.lines().map(|l| parse_squid_line(l).unwrap_or_else(|| panic!("not an aienv line: {l:?}\n{log}"))).collect()
    }

    fn dns_log(&self) -> String {
        let out = docker(&["logs", &self.container("dns")], 60);
        format!("{}{}", text(&out.stdout), text(&out.stderr))
    }

    /// SHA-256 of every installed file: squid.conf and the list directories.
    fn installed(&self) -> String {
        self.sh("proxy", "cd /etc/squid && ls -1A ai-env && sha256sum squid.conf ai-env/*/*")
    }

    fn reconfigures(&self) -> usize {
        self.sh("proxy", "cat /var/log/squid/cache.log 2>/dev/null || true").matches("Reconfiguring Squid Cache").count()
    }

    /// systemd in the proxy container is up (running or degraded).
    #[track_caller]
    fn wait_systemd(&self) {
        let started = Instant::now();
        loop {
            let out = self.exec("proxy", &[], &["systemctl", "is-system-running"], 30);
            let state = text(&out.stdout).trim().to_string();
            if state == "running" || state == "degraded" {
                return;
            }
            assert!(started.elapsed() < Duration::from_secs(60), "systemd in the proxy container: {state:?} {}", text(&out.stderr));
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn unit_u64(&self, unit: &str, prop: &str) -> u64 {
        self.sh("proxy", &format!("systemctl show -p {prop} --value {unit}")).trim().parse().unwrap_or(0)
    }

    /// After a boot: squid active, started only after the reload unit had
    /// finished, the set recorded applied (squid's ExecStartPost) and served.
    #[track_caller]
    fn boot_checks(&self, what: &str) {
        let started = Instant::now();
        while self.exec("proxy", &[], &["systemctl", "is-active", "--quiet", "squid.service"], 30).status.code() != Some(0) {
            assert!(started.elapsed() < Duration::from_secs(60), "{what}: squid never became active:\n{}", self.sh("proxy", "systemctl status --no-pager ai-env-proxy-reload.service squid.service 2>&1; journalctl --no-pager -n 40 -u ai-env-proxy-reload -u squid 2>&1; true"));
            std::thread::sleep(Duration::from_millis(500));
        }
        let (reload_done, squid_start) = (self.unit_u64("ai-env-proxy-reload.service", "ExecMainExitTimestampMonotonic"), self.unit_u64("squid.service", "ExecMainStartTimestampMonotonic"));
        assert!(reload_done > 0 && reload_done <= squid_start, "{what}: the reload must finish ({reload_done}) before squid starts ({squid_start})");
        let started = Instant::now();
        while self.status().1["applied"] != "yes" {
            assert!(started.elapsed() < Duration::from_secs(10), "{what}: never applied=yes: {}", self.status().0);
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(self.sh("proxy", "ls /var/lib/ai-env-proxy").trim() == "applied", "{what}: pending promoted");
        self.echo_until(ECHO_HOST, 10, |r| r.connect == "200");
        assert_denied(&self.curl("vm", "https://example.com/"), what);
    }

    /// The squid wrapper on the script's PATH; `mode` `once` or `always`.
    fn fail_reconfigure(&self, mode: &str) {
        self.share("squid-wrapper", SQUID_WRAPPER.as_bytes());
        self.sh("proxy", &format!("install -m 0755 /ssm/squid-wrapper /usr/local/sbin/squid && echo {mode} > /tmp/fail-reconfigure"));
    }
}

// ---- the allowlist and its deny order ---------------------------------------------------

#[test]
#[ignore = "Docker: make test-proxy"]
fn allowed_host_tunnels_and_the_upstream_answers_401() {
    let Some(lab) = Lab::up() else { return };
    lab.require_internet();
    let r = lab.curl("vm", "https://api.anthropic.com/v1/models");
    assert_eq!((r.connect.as_str(), r.code.as_str()), ("200", "401"), "a tunnel, then the API's own 401: {r:?}");
    let lines = lab.lines();
    let l = lines.iter().find(|l| l.host == "api.anthropic.com").unwrap_or_else(|| panic!("{lines:?}"));
    assert_eq!((l.method.as_str(), l.code.as_str(), l.status, l.port, l.client.clone()), ("CONNECT", "TCP_TUNNEL", 200, Some(443), lab.ip(VM)), "{l:?}");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn a_denied_host_is_403() {
    let Some(lab) = Lab::up() else { return };
    assert_denied(&lab.curl("vm", "https://example.com/"), "example.com");
    assert_denied(&lab.curl("vm", "https://api.anthropic.com.evil.example/"), "an allowed name as a prefix");
    assert_denied(&lab.curl("vm", "https://sub.api.anthropic.com/"), "a subdomain of an allowed name");
    let lines = lab.lines();
    assert!(lines.iter().any(|l| l.host == "example.com" && l.method == "CONNECT" && l.code == "TCP_DENIED" && l.status == 403), "{lines:?}");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn an_ip_literal_is_403_without_a_reverse_lookup() {
    let Some(lab) = Lab::up() else { return };
    assert_denied(&lab.curl("vm", "https://1.1.1.1/"), "IPv4 literal");
    assert_denied(&lab.curl("vm", "https://[2606:4700:4700::1111]/"), "IPv6 literal");
    assert_denied(&lab.curl("vm", &format!("https://{}/", lab.echo_ip(ECHO))), "the echo server by address");
    let dns = lab.dns_log();
    assert!(!dns.contains("in-addr.arpa") && !dns.contains("ip6.arpa"), "dstdomain -n: no PTR query:\n{dns}");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn plain_http_get_is_403_and_the_error_page_has_no_version() {
    let Some(lab) = Lab::up() else { return };
    let r = lab.curl("vm", "http://example.com:8080/");
    assert_eq!(r.code, "403", "{r:?}");
    let proxy = format!("http://{}:{PORT}", lab.ip(PROXY));
    let out = lab.exec("vm", &[], &["curl", "-sS", "-i", "--max-time", "20", "-x", &proxy, "http://api.anthropic.com/"], 60);
    let page = text(&out.stdout);
    assert!(page.starts_with("HTTP/1.1 403 "), "even an allowed name: only CONNECT passes:\n{page}");
    assert!(page.contains("\r\nServer: squid\r\n"), "no version in Server:\n{page}");
    assert!(!page.contains("6.13") && !page.to_ascii_lowercase().contains("squid/6"), "no version anywhere:\n{page}");
    assert!(page.contains("ai-env-proxy"), "visible_hostname:\n{page}");
    assert!(!page.contains("body=") && !page.contains("ClientIP"), "email_err_data off: no request details in a mailto:\n{page}");
    assert!(page.contains("\r\nConnection: close\r\n") || page.contains("\r\nProxy-Connection: close\r\n"), "client_persistent_connections off:\n{page}");
    let lines = lab.lines();
    assert!(lines.iter().any(|l| l.method == "GET" && l.host == "example.com" && l.port == Some(8080) && l.status == 403), "{lines:?}");
}

/// The only rule that stops a plain GET to an allowed host on 443 is `deny !CONNECT`.
#[test]
#[ignore = "Docker: make test-proxy"]
fn only_connect_passes_even_to_an_allowed_host_on_443() {
    let Some(lab) = Lab::up() else { return };
    let r = lab.curl("vm", &format!("http://{ECHO_HOST}:443/"));
    assert_eq!(r.code, "403", "a GET to an allowed name on 443: {r:?}");
    assert_eq!(lab.echo(ECHO_HOST).connect, "200", "the control: CONNECT to it tunnels");
    let lines = lab.lines();
    assert!(lines.iter().any(|l| l.method == "GET" && l.host == ECHO_HOST && l.port == Some(443) && l.code == "TCP_DENIED"), "{lines:?}");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn connect_to_another_port_is_403() {
    let Some(lab) = Lab::up() else { return };
    assert_denied(&lab.curl("vm", "https://example.com:8443/"), "example.com:8443");
    assert_denied(&lab.curl("vm", &format!("https://{ECHO_HOST}:8443/")), "an allowed host on 8443");
    assert_denied(&lab.curl("vm", &format!("https://{}:{PORT}/", lab.ip(PROXY))), "the proxy itself");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn an_extra_tunnels_after_reload_and_its_removal_is_403_within_5s() {
    let Some(lab) = Lab::up() else { return };
    assert_denied(&lab.echo(EXTRA_HOST), "not listed yet");
    lab.put("extras", &format!("{EXTRA_HOST}\tws-a\n"));
    let started = Instant::now();
    assert!(lab.reload_ok(&[]).contains("applied (reconfigured)"), "an addition reconfigures");
    lab.echo_until(EXTRA_HOST, 5, |r| r.connect == "200");
    eprintln!("extra tunnels {:?} after the reload began", started.elapsed());
    lab.put("extras", NO_EXTRAS);
    let started = Instant::now();
    assert!(lab.reload_ok(&[]).contains("applied (restarted)"), "a removal restarts");
    lab.echo_until(EXTRA_HOST, 5, |r| r.err.contains(DENIED));
    let took = started.elapsed();
    assert!(took <= Duration::from_secs(5), "{took:?}");
    eprintln!("removal: 403 {took:?} after the reload began");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn suspended_wins_over_allowed_without_dns() {
    let Some(lab) = Lab::up() else { return };
    let url = "https://api.anthropic.com/v1/models";
    lab.put("suspended", "api.anthropic.com\n");
    lab.reload_ok(&[]);
    let (r, _) = lab.curl_until(url, 5, |r| r.err.contains(DENIED));
    assert_denied(&r, "suspended");
    lab.put("extras", "api.anthropic.com\tws-a\n");
    lab.reload_ok(&[]);
    let (r, _) = lab.curl_until(url, 5, |r| r.err.contains(DENIED));
    assert_denied(&r, "suspended, though also an extra");
    let dns = lab.dns_log();
    assert!(!dns.contains("api.anthropic.com"), "a suspended name is never resolved:\n{dns}");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn dns_rebinding_to_metadata_loopback_or_private_addresses_is_403() {
    let Some(lab) = Lab::up() else { return };
    for (host, addrs) in REBIND {
        assert_denied(&lab.curl("vm", &format!("https://{host}/")), &format!("{host} -> {addrs}"));
    }
    // The stub saw each name: the name rules let it through and an address
    // rule refused it (a resolved name squid lets through answers 503, not 403).
    let dns = lab.dns_log();
    for (host, _) in REBIND {
        assert!(dns.contains(&format!("query[A] {host}")) || dns.contains(&format!("query[AAAA] {host}")), "{host} was resolved:\n{dns}");
    }
    let lines = lab.lines();
    for (host, _) in REBIND {
        assert!(lines.iter().any(|l| l.host == host && l.code == "TCP_DENIED" && l.status == 403), "{host}: {lines:?}");
    }
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn a_client_outside_the_vm_subnet_is_403_without_dns() {
    let Some(mut lab) = Lab::up() else { return };
    let net = lab.name.clone();
    lab.start("outsider", &net, OUTSIDER, &["--init"], &["sleep", "infinity"]);
    assert_denied(&lab.curl("outsider", "https://api.anthropic.com/v1/models"), "a client outside @VMS@");
    assert_denied(&lab.curl("outsider", &format!("https://{ECHO_HOST}/")), "an outsider, an allowed name");
    let lines = lab.lines();
    assert!(lines.iter().any(|l| l.client == lab.ip(OUTSIDER) && l.host == "api.anthropic.com" && l.code == "TCP_DENIED"), "{lines:?}");
    let dns = lab.dns_log();
    assert!(!dns.contains("api.anthropic.com") && !dns.contains(ECHO_HOST), "deny !vms comes before any lookup:\n{dns}");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn a_denied_name_is_never_resolved() {
    let Some(lab) = Lab::up() else { return };
    let denied = format!("denied-{}.example.org", std::process::id());
    assert_denied(&lab.curl("vm", &format!("https://{denied}/")), &denied);
    assert_eq!(lab.curl("vm", &format!("http://{denied}:443/")).code, "403", "a GET, not CONNECT");
    // The control: an allowed name is resolved, and the stub logs it.
    assert_denied(&lab.curl("vm", "https://meta.rebind.test/"), "meta.rebind.test");
    let started = Instant::now();
    while !lab.dns_log().contains("query[A] meta.rebind.test") {
        assert!(started.elapsed() < Duration::from_secs(5), "the stub logs queries:\n{}", lab.dns_log());
        std::thread::sleep(Duration::from_millis(100));
    }
    let dns = lab.dns_log();
    assert!(!dns.contains(&denied) && !dns.contains("example.org"), "zero queries for a denied name:\n{dns}");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn the_access_log_has_hosts_and_ports_only() {
    let Some(lab) = Lab::up() else { return };
    let path = "/very-private/path?token=abc123";
    lab.curl("vm", &format!("http://example.com:8080{path}"));
    lab.curl("vm", &format!("https://example.com{path}"));
    lab.curl("vm", &format!("https://meta.rebind.test{path}"));
    lab.curl_with("vm", &["-p"], &format!("http://{ECHO_HOST}:443{path}"));
    let log = lab.access_log();
    assert!(!log.contains("very-private") && !log.contains("token") && !log.contains('?'), "no path or query:\n{log}");
    let lines = lab.lines();
    assert!(lines.len() >= 4, "{log}");
    for l in &lines {
        assert_eq!(l.client, lab.ip(VM), "{l:?}");
        assert!(!l.host.contains('/') && l.port.is_some(), "{l:?}");
    }
    assert!(lines.iter().any(|l| l.method == "GET" && l.host == "example.com" && l.port == Some(8080) && l.code == "TCP_DENIED"), "{log}");
    assert!(lines.iter().any(|l| l.method == "CONNECT" && l.host == ECHO_HOST && l.code == "TCP_TUNNEL"), "{log}");
    assert!(log.lines().all(|l| l.starts_with("aienv ")), "{log}");
}

// ---- open tunnels, rollback ---------------------------------------------------------------

#[test]
#[ignore = "Docker: make test-proxy"]
fn tunnels_close_when_their_host_is_suspended_or_removed_and_survive_an_addition() {
    let Some(lab) = Lab::up() else { return };
    // An addition only reconfigures: a tunnel already open lives on.
    let echo = lab.open_tunnel(ECHO_HOST, "echo");
    lab.put("extras", &format!("{EXTRA_HOST}\tws-a\n"));
    assert!(lab.reload_ok(&[]).contains("applied (reconfigured)"));
    let extra = lab.open_tunnel(EXTRA_HOST, "extra");
    let before = lab.tunnel(&echo);
    std::thread::sleep(Duration::from_secs(2));
    let after = lab.tunnel(&echo);
    assert!(after.starts_with("open") && after != before, "still pinging after a reconfigure: {before:?} -> {after:?}");
    // Suspending an allowed host restarts squid: its open tunnel dies.
    lab.put("suspended", &format!("{ECHO_HOST}\n"));
    let started = Instant::now();
    assert!(lab.reload_ok(&[]).contains("applied (restarted)"), "a suspension restarts");
    lab.tunnel_until(&echo, 8, |s| s == "closed");
    eprintln!("suspended: the open tunnel closed {:?} after the reload began", started.elapsed());
    assert_eq!(lab.tunnel(&extra), "closed", "a restart closes every tunnel");
    assert_denied(&lab.curl_until(&format!("https://{ECHO_HOST}/"), 5, |r| r.err.contains(DENIED)).0, "a new CONNECT to the suspended host");
    // Removing an extra: the same.
    lab.put("suspended", NO_SUSPENDED);
    assert!(lab.reload_ok(&[]).contains("applied (reconfigured)"), "lifting a suspension adds");
    let extra = lab.open_tunnel(EXTRA_HOST, "extra2");
    lab.put("extras", NO_EXTRAS);
    let started = Instant::now();
    assert!(lab.reload_ok(&[]).contains("applied (restarted)"), "a removal restarts");
    lab.tunnel_until(&extra, 8, |s| s == "closed");
    eprintln!("extra removed: the open tunnel closed {:?} after the reload began", started.elapsed());
    assert_denied(&lab.curl_until(&format!("https://{EXTRA_HOST}/"), 5, |r| r.err.contains(DENIED)).0, "a new CONNECT to the removed extra");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn a_failed_reconfigure_rolls_back_byte_for_byte() {
    let Some(lab) = Lab::up() else { return };
    let before = lab.installed();
    assert_eq!(lab.status().1["applied"], "yes");
    lab.fail_reconfigure("once");
    lab.put("extras", &format!("{EXTRA_HOST}\tws-a\n"));
    let out = lab.reload(&[], &[]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("squid did not confirm the new set (reconfigure); restoring the previous one") && err.contains("refused; the previous set is in place"), "{err}");
    assert_eq!(lab.installed(), before, "the previous set, byte for byte (the new list directory is gone)");
    let (line, st) = lab.status();
    assert_eq!((st["applied"].as_str(), st["squid"].as_str(), st["parse"].as_str()), ("no", "active", "ok"), "{line}");
    assert_denied(&lab.curl("vm", &format!("https://{EXTRA_HOST}/")), "the new extra is not served");
    assert_eq!(lab.echo(ECHO_HOST).connect, "200", "the old set serves");
    // The record was dropped, so --if-changed applies the set later.
    assert!(lab.reload_ok(&["--if-changed"]).contains("applied (reconfigured)"));
    assert_eq!(lab.status().1["applied"], "yes");
    lab.echo_until(EXTRA_HOST, 5, |r| r.connect == "200");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn a_failed_rollback_exits_3() {
    let Some(lab) = Lab::up() else { return };
    lab.fail_reconfigure("always");
    lab.put("extras", &format!("{EXTRA_HOST}\tws-a\n"));
    let out = lab.reload(&[], &[]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{err}");
    assert!(err.contains("the install and its rollback failed: state unknown (make proxy-stop to fail closed)"), "{err}");
    assert_eq!(lab.status().1["applied"], "no");
    lab.sh("proxy", "rm -f /tmp/fail-reconfigure");
    assert!(lab.reload_ok(&[]).contains("applied (reconfigured)"));
    assert_eq!(lab.status().1["applied"], "yes");
}

// ---- the reload script ------------------------------------------------------------------

#[test]
#[ignore = "Docker: make test-proxy"]
fn golden_hashes_and_the_status_line() {
    let Some(lab) = Lab::up() else { return };
    let conf = lab.squid_conf();
    lab.put("allow", GOLDEN[0].0);
    lab.put("extras", GOLDEN[1].0);
    lab.put("suspended", NO_SUSPENDED);
    lab.reload_ok(&[]);
    let (line, st) = lab.status();
    let keys: Vec<&str> = line.split(' ').map(|t| t.split_once('=').map_or(t, |(k, _)| k)).collect();
    assert_eq!(keys, STATUS_KEYS, "{line}");
    assert_eq!(st["sha256_allow"], GOLDEN[0].1, "the golden vector (plain)");
    assert_eq!(st["sha256_extras"], GOLDEN[1].1, "the golden vector (with a TAB)");
    assert_eq!(st["sha256_squid.conf"], value_sha256(&conf));
    assert_eq!(st["sha256_suspended"], value_sha256(NO_SUSPENDED));
    for (k, v) in [("squid", "active"), ("allowed", "2"), ("extras", "1"), ("suspended", "0"), ("parse", "ok"), ("applied", "yes")] {
        assert_eq!(st[k], v, "{line}");
    }
    // Exact bytes: the same hosts without the final newline hash differently,
    // and a value not yet reloaded is not applied.
    let trimmed = GOLDEN[0].0.trim_end();
    lab.put("allow", trimmed);
    let (_, st) = lab.status();
    assert_eq!(st["sha256_allow"], value_sha256(trimmed));
    assert_ne!(st["sha256_allow"], GOLDEN[0].1);
    assert_eq!((st["allowed"].as_str(), st["applied"].as_str()), ("2", "no"));
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn malformed_values_are_refused_and_the_old_allowlist_keeps_serving() {
    let Some(lab) = Lab::up() else { return };
    let good_extras = format!("{EXTRA_HOST}\tws-a\n");
    lab.put("extras", &good_extras);
    lab.reload_ok(&[]);
    let before = lab.installed();
    let conf = lab.squid_conf();
    let unrendered = read("infra/proxy/squid.conf").replace("@PROXY_IP@", &lab.ip(PROXY)).replace("@PORT@", PORT).replace("@RESOLVERS@", &lab.ip(RESOLVER));
    let cases: Vec<(&str, String, &str, &str)> = vec![
        ("extras", "example.com\tws-a\n1.2.3.4\tws\n".into(), "extras line 2 is not a valid host", "1.2.3.4"),
        ("extras", "# c\nexample.com\n".into(), "extras line 2 is not host<TAB>slug[,slug]", "example.com"),
        ("extras", "example.com\tbad/slug\n".into(), "extras line 1 has an invalid workspace slug", "bad/slug"),
        ("extras", "example.com\tws-a,\n".into(), "extras line 1 has an invalid workspace slug", "ws-a"),
        ("extras", "example.com\tws-a\nexample.com\tws-b\n".into(), "extras line 2 repeats a host", "ws-b"),
        ("extras", "Example.com\tws-a\n".into(), "extras line 1 is not a valid host", "Example"),
        ("allow", "api.anthropic.com\nhttps://evil.example\n".into(), "allow line 2 is not a valid host", "evil"),
        // bash `read` drops a NUL: without the byte rule this became nul.rebind.test.
        ("allow", "nul\0.rebind.test\n".into(), "allow holds a byte outside printable ASCII, TAB, CR and LF", "nul"),
        ("allow", "api.anthropic.com\u{a0}\n".into(), "allow holds a byte outside printable ASCII, TAB, CR and LF", "anthropic"),
        ("suspended", "*.example.com\n".into(), "suspended line 1 is not a valid host", "*.example"),
        ("squid.conf", format!("{conf}bogus_directive on\n"), "squid -k parse failed", "bogus"),
        // squid 6 exits 0 on this ERROR (a directive the build lacks): the output counts.
        ("squid.conf", format!("{conf}pinger_enable off\n"), "squid -k parse failed", "pinger"),
        // ... and on these WARNINGs (a duplicate entry): only the expected ones pass.
        ("squid.conf", format!("{conf}acl dupe src 10.9.0.1 10.9.0.1\n"), "squid -k parse failed", "dupe"),
        ("squid.conf", unrendered, "squid.conf still has an unrendered placeholder", "VMS"),
        ("squid.conf", conf.replace(&format!("dns_nameservers {}", lab.ip(RESOLVER)), "dns_nameservers resolver.example"), "one dns_nameservers line of IPs", "resolver.example"),
        ("squid.conf", conf.replace(&format!("acl vms src {}/32", lab.ip(VM)), "acl vms src all"), "a non-empty acl vms src", ""),
    ];
    let good = |param: &str| match param {
        "extras" => good_extras.clone(),
        "allow" => base_allow(),
        "suspended" => NO_SUSPENDED.to_string(),
        _ => conf.clone(),
    };
    for (param, value, want, secret) in cases {
        lab.put(param, &value);
        let out = lab.reload(&[], &[]);
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{param} {value:?}: {err}");
        assert!(err.contains(want) && err.contains("refused; the running config is unchanged"), "{param} {value:?}: {err}");
        assert!(secret.is_empty() || !err.contains(secret), "no parameter value in a log line: {err}");
        assert_eq!(lab.installed(), before, "{param}: the installed set is untouched");
        let (_, st) = lab.status();
        assert_eq!((st["parse"].as_str(), st["squid"].as_str(), st["applied"].as_str()), ("failed", "active", "no"), "{param} {value:?}");
        lab.put(param, &good(param));
    }
    assert_eq!(lab.echo(ECHO_HOST).connect, "200", "the old allowlist still serves");
    assert_eq!(lab.echo(EXTRA_HOST).connect, "200", "and the old extras");
    let (_, st) = lab.status();
    assert_eq!((st["parse"].as_str(), st["applied"].as_str()), ("ok", "yes"));
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn fetch_failures_exit_2_and_change_nothing() {
    let Some(lab) = Lab::up() else { return };
    let before = lab.installed();
    lab.delete("suspended");
    let out = lab.reload(&[], &[]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("no value for /ai-env/proxy/suspended") && err.contains("fetch failed; nothing changed"), "{err}");
    let out = lab.reload(&[], &["--status"]);
    assert_eq!((out.status.code(), text(&out.stdout)), (Some(2), String::new()), "--status prints nothing when it cannot fetch");
    lab.put("suspended", NO_SUSPENDED);
    // The fake refuses a call without the pinned --endpoint-url (exit 252), so every
    // fetch that worked carried it; here every call fails like an expired session.
    let started = Instant::now();
    let out = lab.reload(&["FAKE_AWS_FAIL=1"], &[]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("(try 5 of 5)") && started.elapsed() >= Duration::from_secs(10), "five tries, 1+2+3+4 s apart ({:?}): {err}", started.elapsed());
    lab.sh("proxy", "mv /etc/ai-env-proxy/env /etc/ai-env-proxy/env.off");
    let out = lab.reload(&[], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("cannot read /etc/ai-env-proxy/env"));
    lab.sh("proxy", "mv /etc/ai-env-proxy/env.off /etc/ai-env-proxy/env");
    let out = lab.reload(&[], &["--bogus"]);
    assert_eq!(out.status.code(), Some(1), "usage");
    assert_eq!(lab.installed(), before);
    let (_, st) = lab.status();
    assert_eq!((st["squid"].as_str(), st["applied"].as_str()), ("active", "yes"), "a failed fetch keeps the record");
    assert_denied(&lab.curl("vm", "https://example.com/"), "still serving");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn log_lines_reach_the_journal_once_and_carry_no_value() {
    let Some(lab) = Lab::up() else { return };
    // A logger stand-in: /usr/local/bin comes first on the script's PATH.
    lab.share("logger", b"#!/bin/sh\nprintf '%s\\n' \"$*\" >> /tmp/journal\n");
    lab.sh("proxy", "install -m 0755 /ssm/logger /usr/local/bin/logger && : > /tmp/journal");
    lab.put("extras", "1.2.3.4\tsecret-slug\n");
    let out = lab.reload(&[], &[]);
    assert_eq!(out.status.code(), Some(1));
    lab.put("extras", NO_EXTRAS);
    let err = text(&out.stderr);
    let journal = lab.sh("proxy", "cat /tmp/journal");
    let from_stderr: Vec<String> = err.lines().map(|l| format!("-t ai-env-proxy-reload -- {}", l.strip_prefix("ai-env-proxy-reload: ").unwrap_or_else(|| panic!("{l:?}")))).collect();
    assert_eq!(journal.lines().collect::<Vec<_>>(), from_stderr, "each stderr line once in the journal");
    assert!(journal.contains("extras line 1 is not a valid host"), "{journal}");
    lab.reload_ok(&[]);
    let journal = lab.sh("proxy", "cat /tmp/journal");
    let allowed = parse_hosts(&base_allow()).unwrap().len();
    assert!(journal.contains(&format!("applied (reconfigured): allowed={allowed} extras=0 suspended=0")), "{journal}");
    for value in ["secret-slug", "1.2.3.4", "anthropic", "crates", "rebind", "tunnel"] {
        assert!(!journal.contains(value), "a parameter value in the journal: {value}\n{journal}");
    }
    // Run by the boot unit, stderr is the journal (JOURNAL_STREAM): no second copy.
    lab.sh("proxy", ": > /tmp/journal && exec 2> /tmp/err && JOURNAL_STREAM=$(stat -L -c %d:%i /tmp/err) ai-env-proxy-reload");
    assert_eq!(lab.sh("proxy", "cat /tmp/journal"), "");
    assert!(lab.sh("proxy", "cat /tmp/err").contains("applied (reconfigured)"));
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn if_changed_applies_only_a_new_or_tampered_set() {
    let Some(lab) = Lab::up() else { return };
    let r0 = lab.reconfigures();
    let err = lab.reload_ok(&["--if-changed"]);
    assert!(err.contains("unchanged since the last apply"), "{err}");
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(lab.reconfigures(), r0, "no reconfigure");
    lab.put("extras", &format!("{EXTRA_HOST}\tws-a\n"));
    let err = lab.reload_ok(&["--if-changed"]);
    assert!(err.contains("applied (reconfigured): allowed=") && err.contains("extras=1"), "{err}");
    assert_eq!(lab.reconfigures(), r0 + 1, "the reload waited for squid's reconfigure");
    lab.echo_until(EXTRA_HOST, 5, |r| r.connect == "200");
    assert!(lab.reload_ok(&["--if-changed"]).contains("unchanged"));
    // An installed file edited on disk: the hashes still match, the bytes do not.
    lab.sh("proxy", "echo tampered.example >> \"$(ls -d /etc/squid/ai-env/*/ | head -n 1)allow.txt\"");
    assert_eq!(lab.status().1["applied"], "no", "staged != installed");
    assert!(lab.reload_ok(&["--if-changed"]).contains("applied ("), "re-applied");
    assert_eq!(lab.status().1["applied"], "yes");
    assert!(!lab.sh("proxy", "cat /etc/squid/ai-env/*/allow.txt").contains("tampered"));
    assert!(lab.reload_ok(&[]).contains("applied (reconfigured)"), "a plain reload always applies");
}

#[test]
#[ignore = "Docker: make test-proxy"]
fn the_reload_grammar_agrees_with_the_rust_one() {
    let Some(lab) = Lab::up() else { return };
    let long = |n: usize| "a".repeat(n);
    let hosts: Vec<String> = [
        "api.anthropic.com",
        "static.crates.io",
        "a.b",
        "0.a",
        "1.2.3.4.nip.io",
        "xn--bcher-kva.example",
        "a-b.c1.io",
        "a.b.c.d.e.f",
        "",
        "localhost",
        "1.2.3.4",
        "10.42.0.10",
        "0x7f.1",
        "example.123",
        "a.1b",
        "*.example.com",
        ".example.com",
        "example.com.",
        "example.com:443",
        "https://example.com",
        "example.com/x",
        "a_b.example.com",
        "-a.example.com",
        "a-.example.com",
        "a.-b",
        "a.b-",
        "Example.com",
        "a..b",
        "[::1]",
        "::1",
        "bücher.example",
        "exa mple.com",
        " example.com",
        "example.com\t",
        "a.b\r",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([format!("{}.com", long(63)), format!("{}.com", long(64)), format!("{}com", "a.".repeat(126)), format!("{}.{}.{}.{}", long(63), long(63), long(63), long(61)), format!("{}.{}.{}.{}", long(63), long(63), long(63), long(62))])
    .collect();
    assert!(hosts.iter().any(|h| h.len() == 253 && is_valid_host(h)) && hosts.iter().any(|h| h.len() == 254), "both sides of the length bound");
    lab.share("hosts", hosts.iter().map(|h| format!("{h}\n")).collect::<String>().as_bytes());
    let out = lab.exec("proxy", &[], &["bash", "-c", r#"source /usr/local/sbin/ai-env-proxy-reload; while IFS= read -r h; do if valid_host "$h"; then echo 1; else echo 0; fi; done < /ssm/hosts"#], 60);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let got: Vec<bool> = text(&out.stdout).lines().map(|l| l == "1").collect();
    assert_eq!(got.len(), hosts.len());
    for (h, ok) in hosts.iter().zip(&got) {
        assert_eq!(*ok, is_valid_host(h), "reload.sh and egress::is_valid_host disagree on {h:?}");
    }
    assert!(got.iter().filter(|g| **g).count() >= 8 && got.iter().filter(|g| !**g).count() >= 25, "both kinds: {got:?}");
    // Whole values: the byte rule plus hosts_of against parse_hosts / parse_extras
    // (accept or refuse, and the hosts in order).
    let values: Vec<(&str, String)> = [
        ("allow", "api.anthropic.com\n"),
        ("allow", "# base\napi.anthropic.com\n\n  static.crates.io  \n"),
        ("allow", "a.b\r\nc.d\r\n"),
        ("allow", "a.b"),
        ("allow", ""),
        ("allow", "\n\n# only comments\n"),
        ("allow", "a.b\n1.2.3.4\n"),
        ("allow", "a.b c.d\n"),
        ("allow", "a.b\rc.d\n"),
        ("allow", " api.anthropic.com\t\r\n"),
        ("allow", "nul\0.rebind.test\n"),
        ("allow", "api.anthrop\0ic.com\n"),
        ("allow", "api.anthropic.com\u{a0}\n"),
        ("allow", "api.anthropic.com\u{85}\n"),
        ("allow", "\u{2003}api.anthropic.com\n"),
        ("allow", "a.b\u{b}\n"),
        ("suspended", "\t-a.b\n"),
        ("extras", "github.com\tai-env,other-ws\n"),
        ("extras", "github.com\tai-env\n# c\nobjects.githubusercontent.com\tai-env\n"),
        ("extras", "  github.com\tws  \n"),
        ("extras", "github.com\n"),
        ("extras", "github.com\t\n"),
        ("extras", "github.com\tbad/slug\n"),
        ("extras", "x\tai-env\n"),
        ("extras", "github.com\ta\ngithub.com\tb\n"),
        ("extras", "github.com\ta,,b\n"),
        ("extras", "github.com\ta,\n"),
        ("extras", "github.com\t,a\n"),
        ("extras", "github.com\t.\n"),
        ("extras", "github.com\t..\n"),
        ("extras", "github.com\t...\n"),
        ("extras", "github.com\tws\tmore\n"),
        ("extras", "github.com \tws\n"),
        ("extras", "github.com\t ws\n"),
        ("extras", "github.com,x.io\tws\n"),
        ("extras", "github.com\tws\u{a0}\n"),
        ("extras", "github.com\tw\0s\n"),
    ]
    .iter()
    .map(|(k, v)| (*k, v.to_string()))
    .chain([("extras", format!("github.com\t{}\n", "x".repeat(64))), ("extras", format!("github.com\t{}\n", "x".repeat(65)))])
    .collect();
    let script = |values: &[(&str, String)], prefix: &str| -> Vec<String> {
        let mut body = String::from("source /usr/local/sbin/ai-env-proxy-reload\n");
        for (i, (kind, v)) in values.iter().enumerate() {
            lab.share(&format!("{prefix}{i}"), v.as_bytes());
            body.push_str(&format!("if clean {kind} /ssm/{prefix}{i} 2> /dev/null && hosts_of {kind} /ssm/{prefix}{i} > /tmp/h 2> /dev/null; then printf 'ok'; while IFS= read -r h; do printf ' %s' \"$h\"; done < /tmp/h; echo; else echo bad; fi\n"));
        }
        let out = lab.exec("proxy", &[], &["bash", "-c", &body], 60);
        assert!(out.status.success(), "{}", text(&out.stderr));
        text(&out.stdout).lines().map(str::to_string).collect()
    };
    let got = script(&values, "v");
    assert_eq!(got.len(), values.len(), "{got:?}");
    for ((kind, v), g) in values.iter().zip(&got) {
        let rust = if *kind == "extras" { parse_extras(v).map(|e| e.into_iter().map(|x| x.host).collect::<Vec<_>>()) } else { parse_hosts(v) };
        let want = match rust {
            Ok(h) => std::iter::once("ok".to_string()).chain(h).collect::<Vec<_>>().join(" "),
            Err(_) => "bad".to_string(),
        };
        assert_eq!(g, &want, "{kind} {v:?}");
    }
    // Stricter than the Rust parsers (fail closed): a non-ASCII byte in a comment, a form feed.
    let stricter: Vec<(&str, String)> = vec![("allow", "# café\napi.anthropic.com\n".into()), ("allow", "api.anthropic.com\u{c}\n".into())];
    assert_eq!(script(&stricter, "s"), ["bad", "bad"]);
}

// ---- the bootstrap ----------------------------------------------------------------------

/// Every `@[A-Z_]+@` placeholder (the pattern infra/egress.ts checks).
fn tokens(text: &str) -> BTreeSet<String> {
    let b = text.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'@' {
            let mut j = i + 1;
            while j < b.len() && (b[j].is_ascii_uppercase() || b[j] == b'_') {
                j += 1;
            }
            if j > i + 1 && j < b.len() && b[j] == b'@' {
                out.insert(text[i..=j].to_string());
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn set(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The CloudWatch agent config with the production log group.
fn render_cw() -> String {
    read("infra/proxy/cloudwatch-agent.json").replace("@LOG_GROUP@", egress::LOG_GROUP)
}

/// user-data with the production values; each embedded file replaces its
/// token without its final newline (the heredoc's own line end restores it),
/// as infra/egress.ts does.
fn render_user_data() -> String {
    let reload = read("infra/proxy/reload.sh");
    let cw = render_cw();
    read("infra/proxy/user-data.sh")
        .replace("@PARAM_PREFIX@", egress::PARAMETER_PREFIX)
        .replace("@REGION@", "eu-central-1")
        .replace("@LOG_GROUP@", egress::LOG_GROUP)
        .replace("@RELOAD_SH@", reload.strip_suffix('\n').unwrap_or(&reload))
        .replace("@CW_AGENT_JSON@", cw.strip_suffix('\n').unwrap_or(&cw))
}

/// The body of the quoted heredoc ending at `delim` in `text`.
fn heredoc<'a>(text: &'a str, delim: &str) -> Vec<&'a str> {
    let lines: Vec<&str> = text.lines().collect();
    let open = lines.iter().position(|l| l.ends_with(&format!("<<'{delim}'"))).unwrap_or_else(|| panic!("no <<'{delim}'"));
    let close = lines.iter().position(|l| *l == delim).unwrap_or_else(|| panic!("no {delim} line"));
    assert!(close > open, "{delim}");
    lines[open + 1..close].to_vec()
}

/// Reads files only: part of every `cargo test`.
#[test]
fn templates_and_user_data_static_checks() {
    let (squid, reload, ud, cw, allow) = (read("infra/proxy/squid.conf"), read("infra/proxy/reload.sh"), read("infra/proxy/user-data.sh"), read("infra/proxy/cloudwatch-agent.json"), read("infra/proxy/allow.txt"));
    // The token set of each file (contract 3 + phase 0); nothing else carries one.
    assert_eq!(tokens(&squid), set(&["@DIR@", "@PORT@", "@PROXY_IP@", "@RESOLVERS@", "@VMS@"]));
    assert_eq!(tokens(&ud), set(&["@CW_AGENT_JSON@", "@LOG_GROUP@", "@PARAM_PREFIX@", "@REGION@", "@RELOAD_SH@"]));
    assert_eq!(tokens(&reload), set(&["@DIR@"]), "reload.sh fills @DIR@ and carries no other token");
    assert_eq!(tokens(&cw), set(&["@LOG_GROUP@"]));
    assert!(tokens(&allow).is_empty());
    // Rendered by plain replacement: a token in a comment would be filled there too (a
    // multi-line value would escape the comment), so each occurs once, on a code line.
    for t in tokens(&ud) {
        assert_eq!(ud.matches(&t).count(), 1, "{t} once in user-data.sh");
    }
    for (name, body) in [("squid.conf", &squid), ("user-data.sh", &ud), ("cloudwatch-agent.json", &cw)] {
        for l in body.lines().filter(|l| l.trim_start().starts_with('#')) {
            assert!(tokens(l).is_empty(), "{name}: a token in a comment: {l}");
        }
    }
    // The embedded files: quoted heredocs that never meet their delimiter, and no `$$`,
    // `$&`, `` $` `` or `$'`, which a JS String.replace replacement string would expand.
    let lines: Vec<&str> = ud.lines().collect();
    for (open, token, close) in [("cat > /usr/local/sbin/ai-env-proxy-reload <<'AIENV_RELOAD_EOF'", "@RELOAD_SH@", "AIENV_RELOAD_EOF"), ("cat > /etc/ai-env-proxy/cloudwatch-agent.json <<'AIENV_CW_EOF'", "@CW_AGENT_JSON@", "AIENV_CW_EOF")] {
        let at = lines.iter().position(|l| *l == open).unwrap_or_else(|| panic!("{open}"));
        assert_eq!((lines[at + 1], lines[at + 2]), (token, close));
    }
    for l in lines.iter().filter(|l| l.contains("<<")) {
        assert!(l.contains("<<'AIENV_") && l.ends_with("_EOF'"), "every heredoc is quoted: {l}");
    }
    for (name, body) in [("reload.sh", &reload), ("cloudwatch-agent.json", &cw)] {
        assert!(!body.contains("AIENV_"), "{name} must not contain a heredoc delimiter");
        for special in ["$$", "$&", "$`", "$'"] {
            assert!(!body.contains(special), "{name} contains {special}");
        }
    }
    // Order: swap before dnf (OOM); the deny-all squid.conf, the units and daemon-reload
    // before the RPM; squid's start queued (--no-block) before the CloudWatch agent.
    let pos = |needle: &str| lines.iter().position(|l| l.starts_with(needle)).unwrap_or_else(|| panic!("{needle}"));
    let order = [
        pos("  dd if=/dev/zero of=/swapfile.new bs=1M count=512"),
        pos("swapon --show=NAME --noheadings | grep -qx /swapfile || swapon /swapfile"),
        pos("if ! grep -qs '^# ai-env egress proxy' /etc/squid/squid.conf"),
        pos("cat > /etc/systemd/system/ai-env-proxy-reload.service <<"),
        pos("cat > /etc/systemd/system/squid.service.d/ai-env.conf <<"),
        pos("systemctl daemon-reload"),
        pos("  dnf -y install squid amazon-cloudwatch-agent jq logrotate && break"),
        pos("systemctl enable logrotate.timer ai-env-proxy-reload.service squid.service"),
        pos("systemctl start --no-block logrotate.timer squid.service"),
        pos("/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl "),
    ];
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
    // The script itself: no comment and no heredoc body (a unit, the logrotate rule).
    let mut code: Vec<&str> = Vec::new();
    let mut inside: Option<String> = None;
    for l in &lines {
        match &inside {
            Some(delim) if l == delim => inside = None,
            Some(_) => {}
            None if l.trim_start().starts_with('#') => {}
            None => {
                inside = l.split_once("<<'").map(|(_, d)| d.trim_end_matches('\'').to_string());
                code.push(l);
            }
        }
    }
    let systemctl: Vec<&str> = code.iter().copied().filter(|l| l.contains("systemctl")).collect();
    assert_eq!(systemctl, ["systemctl daemon-reload", "systemctl enable logrotate.timer ai-env-proxy-reload.service squid.service", "systemctl start --no-block logrotate.timer squid.service"]);
    assert!(!code.iter().any(|l| l.trim_start().starts_with("squid ") || l.trim_start().starts_with("/usr/sbin/squid ")), "user-data never runs squid itself");
    assert!(lines[order[9]].ends_with("|| logger -s -t ai-env-user-data 'the CloudWatch agent did not start; squid serves without log shipping' || true"), "the agent never fails the bootstrap");
    assert!(squid.starts_with("# ai-env egress proxy"), "the marker user-data looks for");
    let unit = heredoc(&ud, "AIENV_UNIT_EOF");
    for want in ["Wants=network-online.target", "After=network-online.target", "Before=squid.service", "Type=oneshot", "RemainAfterExit=yes", "Environment=AI_ENV_PROXY_BOOT=1", "ExecStart=/usr/local/sbin/ai-env-proxy-reload", "Restart=on-failure", "RestartPreventExitStatus=1", "WantedBy=multi-user.target"] {
        assert!(unit.contains(&want), "the reload unit: {want}");
    }
    let timeout: u32 = unit.iter().find_map(|l| l.strip_prefix("TimeoutStartSec=")).and_then(|v| v.parse().ok()).unwrap();
    assert!(timeout >= 600, "TimeoutStartSec={timeout}: five fetches of up to 60 s, their pauses and the lock wait");
    let dropin = heredoc(&ud, "AIENV_DROPIN_EOF");
    for want in ["[Unit]", "Requires=ai-env-proxy-reload.service", "After=ai-env-proxy-reload.service", "ExecStartPost=-+/usr/bin/mv -f /var/lib/ai-env-proxy/pending /var/lib/ai-env-proxy/applied"] {
        assert!(dropin.contains(&want), "the squid drop-in: {want}");
    }
    assert!(reload.contains("STATE=/var/lib/ai-env-proxy\nAPPLIED=$STATE/applied\nPENDING=$STATE/pending\n"), "the drop-in's paths are the script's");
    let rotate = heredoc(&ud, "AIENV_LOGROTATE_EOF");
    assert!(rotate.contains(&"/var/log/squid/*.log {") && rotate.contains(&"    maxsize 100M"), "{rotate:?}");
    assert!(ud.contains("printf '%s\\n' '[Timer]' 'OnCalendar=' 'OnCalendar=hourly' > /etc/systemd/system/logrotate.timer.d/ai-env.conf"), "logrotate hourly");
    assert!(ud.starts_with("#!/bin/bash\n") && code.contains(&"set -euo pipefail"));
    for (name, body) in [("squid.conf", &squid), ("reload.sh", &reload), ("user-data.sh", &ud), ("cloudwatch-agent.json", &cw), ("allow.txt", &allow)] {
        let lower = body.to_ascii_lowercase();
        for bad in ["sshd", "authorized_keys", "akia", "sk-ant-", "secretaccesskey", "aws_secret", "begin "] {
            assert!(!lower.contains(bad), "{name}: {bad}");
        }
    }
    // The bounds infra/egress.ts enforces (16 KB), with a margin, and the production values.
    let ud_rendered = render_user_data();
    assert!(ud_rendered.len() <= 15_500, "user-data is {} bytes: keep under 15.5 KB (infra/egress.ts and EC2 stop at 16 KB)", ud_rendered.len());
    assert_eq!(tokens(&ud_rendered), BTreeSet::from(["@DIR@".to_string()]), "only @DIR@ (inside the reload script) is left");
    let prod = render_squid(egress::PROXY_IP, &egress::PROXY_PORT.to_string(), egress::VM_SUBNET_CIDR, &egress::RESOLVERS.join(" "));
    assert!(egress::fits_parameter(&prod) && egress::fits_parameter(&prod.replace("@DIR@", "/etc/squid/ai-env/0123456789abcdef-1790000000000000000")), "squid.conf is {} bytes", prod.len());
    eprintln!("rendered sizes: user-data {} bytes, squid.conf {} bytes", ud_rendered.len(), prod.len());
    // squid.conf: the deny order, the ACLs, the log format, the hardening lines.
    let directives: Vec<&str> = squid.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).collect();
    let access: Vec<&str> = directives.iter().copied().filter(|l| l.starts_with("http_access ")).collect();
    assert_eq!(
        access,
        [
            "http_access deny !vms",
            "http_access deny !CONNECT",
            "http_access deny !SSL_ports",
            "http_access deny suspended",
            "http_access deny !allowed !extras",
            "http_access deny to_localhost",
            "http_access deny to_linklocal",
            "http_access deny to_private",
            "http_access allow allowed",
            "http_access allow extras",
            "http_access deny all"
        ]
    );
    for want in [
        "http_port @PROXY_IP@:@PORT@",
        "visible_hostname ai-env-proxy",
        "httpd_suppress_version_string on",
        "dns_nameservers @RESOLVERS@",
        "cache deny all",
        "via off",
        "forwarded_for delete",
        "icp_port 0",
        "htcp_port 0",
        "snmp_port 0",
        "hosts_file none",
        "cachemgr_passwd disable all",
        "client_persistent_connections off",
        "email_err_data off",
        "acl vms src @VMS@",
        "acl SSL_ports port 443",
        "acl allowed dstdomain -n \"@DIR@/allow.txt\"",
        "acl extras dstdomain -n \"@DIR@/extras.txt\"",
        "acl suspended dstdomain -n \"@DIR@/suspended.txt\"",
        "acl to_private dst 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16 fc00::/7",
        "logformat aienv aienv %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %>rd:%>rP",
        "access_log stdio:/var/log/squid/access.log aienv",
    ] {
        assert!(directives.contains(&want), "squid.conf: {want}");
    }
    assert!(!directives.iter().any(|l| l.starts_with("cache_peer") || l.starts_with("cache_dir") || l.starts_with("ssl_bump") || l.starts_with("https_port")), "{directives:?}");
    // The base allowlist, exactly.
    assert_eq!(parse_hosts(&allow).unwrap(), ["api.anthropic.com", "platform.claude.com", "index.crates.io", "static.crates.io"]);
    // The CloudWatch agent: access.log to the egress group, one stream per instance, nothing else.
    let doc: serde_json::Value = serde_json::from_str(&render_cw()).unwrap();
    assert_eq!(doc.as_object().unwrap().keys().collect::<Vec<_>>(), ["agent", "logs"], "no metrics");
    assert_eq!(doc["agent"]["run_as_user"], "root", "access.log is 0640 squid:squid");
    let files = doc["logs"]["logs_collected"]["files"]["collect_list"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!((files[0]["file_path"].as_str(), files[0]["log_group_name"].as_str(), files[0]["log_stream_name"].as_str()), (Some("/var/log/squid/access.log"), Some(egress::LOG_GROUP), Some("{instance_id}")));
    assert_eq!(doc["logs"]["logs_collected"].as_object().unwrap().len(), 1, "files only");
    // The reload script's status keys: egress::PARAMS, then parse and applied.
    assert!(reload.contains(&format!("PARAMS=({})", egress::PARAMS.join(" "))));
    assert!(reload.contains("printf 'squid=%s allowed=%s extras=%s suspended=%s %s parse=%s applied=%s\\n'"));
    assert_eq!(STATUS_KEYS[4..8], egress::PARAMS.map(|p| format!("sha256_{p}")));
}

/// The stubs of the user-data dry run: each records its argv in /tmp/calls.
/// dnf notes what was in place when it ran and installs squid's RPM (kept in
/// the image) over whatever squid.conf is there.
const STUBS: [(&str, &str); 8] = [
    (
        "dnf",
        "echo \"dnf $*\" >> /tmp/calls\n\
         echo \"dnf saw: swap=$(grep -qx /swapfile /tmp/swaps && echo on) placeholder=$(grep -qs '^http_access deny all$' /etc/squid/squid.conf && echo yes) unit=$(test -f /etc/systemd/system/ai-env-proxy-reload.service && echo yes) dropin=$(test -f /etc/systemd/system/squid.service.d/ai-env.conf && echo yes)\" >> /tmp/calls\n\
         case \" $* \" in *' squid '*) /usr/bin/rpm -q squid > /dev/null 2>&1 || env PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/rpm -i --nodeps /opt/rpms/squid-[0-9]*.rpm >> /tmp/rpm.log 2>&1 ;; esac\n\
         exit 0\n",
    ),
    ("rpm", "echo \"rpm $*\" >> /tmp/calls\n"),
    ("mkswap", "echo \"mkswap $*\" >> /tmp/calls\n"),
    ("dd", "echo \"dd $*\" >> /tmp/calls\nfor a in \"$@\"; do case $a in of=*) : > \"${a#of=}\" ;; esac; done\n"),
    ("swapon", "echo \"swapon $*\" >> /tmp/calls\ncase $1 in --show*) cat /tmp/swaps 2> /dev/null; exit 0 ;; esac\nif grep -qx \"$1\" /tmp/swaps 2> /dev/null; then echo \"swapon: $1: busy\" >&2; exit 1; fi\necho \"$1\" >> /tmp/swaps\n"),
    ("systemctl", "echo \"systemctl $*\" >> /tmp/calls\ncase $* in *start*squid*) [ -f /etc/systemd/system/squid.service.d/ai-env.conf ] && echo 'drop-in present at start' >> /tmp/calls ;; esac\n"),
    ("logger", "echo \"logger $*\" >> /tmp/calls\n"),
    ("amazon-cloudwatch-agent-ctl", "echo \"amazon-cloudwatch-agent-ctl $*\" >> /tmp/calls\njq -e '.logs.logs_collected.files.collect_list[0].file_path' /etc/ai-env-proxy/cloudwatch-agent.json > /dev/null\n[ ! -e /tmp/cw-fail ]\n"),
];

#[test]
#[ignore = "Docker: make test-proxy"]
fn user_data_dry_run_with_stubbed_dnf_and_systemctl() {
    if !enabled() {
        return;
    }
    let _serial = serial();
    sweep_leftovers();
    let image = image();
    let w = tempfile::tempdir().unwrap();
    let wp = w.path().canonicalize().unwrap();
    std::fs::write(wp.join("user-data.sh"), render_user_data()).unwrap();
    std::fs::copy(repo("infra/proxy/reload.sh"), wp.join("reload.sh")).unwrap();
    std::fs::write(wp.join("squid.conf"), render_squid(egress::PROXY_IP, &egress::PROXY_PORT.to_string(), egress::VM_SUBNET_CIDR, &egress::RESOLVERS.join(" ")).replace("@DIR@", "/etc/squid/ai-env/0123456789abcdef")).unwrap();
    std::fs::create_dir(wp.join("stub")).unwrap();
    for (name, body) in STUBS {
        use std::os::unix::fs::PermissionsExt;
        let p = wp.join("stub").join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut cleanup = Cleanup::default();
    let name = unique();
    cleanup.containers.push(name.clone());
    let (mount, labels) = (format!("{}:/w:ro", wp.display()), labels());
    let mut args = vec!["run", "-d", "--init", "--platform", "linux/arm64", "--network", "none", "--name", &name, "-v", &mount];
    args.extend(labels.iter().map(String::as_str));
    args.extend_from_slice(&[&image, "sleep", "infinity"]);
    docker_ok(&args, 120);
    let sh = |script: &str| -> Output { docker(&["exec", &name, "bash", "-c", script], 120) };
    let ok = |script: &str| -> String {
        let out = sh(script);
        assert!(out.status.success(), "{script}: {}{}", text(&out.stdout), text(&out.stderr));
        text(&out.stdout)
    };
    ok("bash -n /w/user-data.sh && bash -n /w/reload.sh");
    // A fresh AMI: no squid yet.
    ok("rpm -e --nodeps squid > /dev/null 2>&1; rm -rf /etc/squid /etc/logrotate.d/squid; ! rpm -q squid > /dev/null");
    ok("mkdir -p /opt/aws/amazon-cloudwatch-agent/bin && cp /w/stub/amazon-cloudwatch-agent-ctl /opt/aws/amazon-cloudwatch-agent/bin/");
    let files = "/etc/ai-env-proxy/env /usr/local/sbin/ai-env-proxy-reload /etc/ai-env-proxy/cloudwatch-agent.json /etc/systemd/system/ai-env-proxy-reload.service /etc/systemd/system/squid.service.d/ai-env.conf /etc/systemd/system/logrotate.timer.d/ai-env.conf /etc/logrotate.d/squid /etc/squid/squid.conf /etc/fstab";
    let run = || -> (String, String) {
        ok("rm -f /tmp/calls && PATH=/w/stub:$PATH bash /w/user-data.sh");
        (ok("cat /tmp/calls"), ok(&format!("sha256sum {files}")))
    };
    let (calls1, sums1) = run();
    assert_eq!(
        calls1.lines().collect::<Vec<_>>(),
        [
            "dd if=/dev/zero of=/swapfile.new bs=1M count=512 status=none",
            "mkswap /swapfile.new",
            "swapon --show=NAME --noheadings",
            "swapon /swapfile",
            "systemctl daemon-reload",
            "dnf -y install squid amazon-cloudwatch-agent jq logrotate",
            "dnf saw: swap=on placeholder=yes unit=yes dropin=yes",
            "rpm -q squid amazon-cloudwatch-agent jq logrotate",
            "systemctl enable logrotate.timer ai-env-proxy-reload.service squid.service",
            "systemctl start --no-block logrotate.timer squid.service",
            "drop-in present at start",
            "amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/etc/ai-env-proxy/cloudwatch-agent.json",
        ]
    );
    // The RPM went in over the placeholder and kept it (config noreplace).
    ok("rpm -q squid > /dev/null || cat /tmp/rpm.log");
    ok("rpm -q squid > /dev/null");
    let placeholder = ok("cat /etc/squid/squid.conf");
    assert!(placeholder.contains("http_access deny all") && placeholder.contains("http_port 127.0.0.1:3128") && !placeholder.contains("http_access allow"), "the deny-all placeholder:\n{placeholder}");
    assert!(ok("cat /etc/squid/squid.conf.rpmnew").contains("http_access allow localhost"), "the package default went to .rpmnew");
    assert_eq!(ok("cat /usr/local/sbin/ai-env-proxy-reload"), read("infra/proxy/reload.sh"), "the reload script, byte for byte");
    assert_eq!(ok("stat -c '%a %U' /usr/local/sbin/ai-env-proxy-reload /etc/ai-env-proxy/env /swapfile"), "755 root\n644 root\n600 root\n");
    assert_eq!(ok("cat /etc/ai-env-proxy/env"), format!("PARAM_PREFIX={}\nREGION=eu-central-1\nLOG_GROUP={}\n", egress::PARAMETER_PREFIX, egress::LOG_GROUP));
    assert_eq!(ok("cat /etc/ai-env-proxy/cloudwatch-agent.json"), render_cw());
    assert!(ok("cat /etc/logrotate.d/squid").contains("maxsize 100M"), "ours replaced the RPM's rule");
    ok("logrotate -d /etc/logrotate.d/squid > /dev/null 2>&1");
    // systemd itself checks the units and the drop-ins (no output: no warning either).
    let verify = sh("systemd-analyze verify --man=no ai-env-proxy-reload.service squid.service logrotate.timer 2>&1");
    assert!(verify.status.success() && text(&verify.stdout).trim().is_empty(), "systemd-analyze verify: {}", text(&verify.stdout));
    // A second run changes nothing (one fstab line, no second dd, mkswap or swapon).
    let (calls2, sums2) = run();
    assert_eq!(sums2, sums1, "idempotent");
    assert!(!calls2.contains("mkswap") && !calls2.contains("swapon /swapfile") && !calls2.contains("dd "), "{calls2}");
    assert_eq!(ok("grep -c '^/swapfile ' /etc/fstab"), "1\n");
    // Once the reload installed the real config, a rerun keeps it.
    ok("cp /w/squid.conf /etc/squid/squid.conf");
    let ours = ok("sha256sum /etc/squid/squid.conf");
    run();
    assert_eq!(ok("sha256sum /etc/squid/squid.conf"), ours, "the installed config survives a rerun");
    // A CloudWatch agent that fails: logged, the bootstrap still succeeds, squid was queued first.
    ok("touch /tmp/cw-fail");
    let (calls4, _) = run();
    let at = |needle: &str| calls4.lines().position(|l| l.starts_with(needle)).unwrap_or_else(|| panic!("{needle}: {calls4}"));
    assert!(at("systemctl start --no-block") < at("amazon-cloudwatch-agent-ctl") && at("amazon-cloudwatch-agent-ctl") < at("logger -s -t ai-env-user-data"), "{calls4}");
    drop(cleanup);
}

/// The bootstrap and the reload under a real systemd (PID 1 in a privileged
/// container; dnf, rpm, swap and the CloudWatch agent stubbed): the boot
/// unit applies the set before squid starts and squid's ExecStartPost
/// records it; a removal restarts squid; a refused reload at boot leaves
/// squid stopped until a good set is reloaded; a reboot applies again first.
#[test]
#[ignore = "Docker: make test-proxy (privileged: AI_ENV_PROXY_SYSTEMD=1)"]
fn under_systemd_the_reload_runs_before_squid_and_records_it() {
    let Some(lab) = Lab::up_systemd() else { return };
    lab.wait_systemd();
    for (name, body) in STUBS.iter().filter(|(n, _)| !matches!(*n, "systemctl" | "logger")) {
        lab.share(&format!("stub-{name}"), format!("#!/bin/sh\n{body}").as_bytes());
    }
    lab.share("user-data.sh", render_user_data().as_bytes());
    // The boot unit gets the fake's parameter directory (PID 1 has no such environment).
    lab.sh(
        "proxy",
        "mkdir -p /tmp/stub /opt/aws/amazon-cloudwatch-agent/bin /etc/systemd/system/ai-env-proxy-reload.service.d \
         && for f in /ssm/stub-*; do install -m 0755 \"$f\" \"/tmp/stub/${f#/ssm/stub-}\"; done \
         && cp /tmp/stub/amazon-cloudwatch-agent-ctl /opt/aws/amazon-cloudwatch-agent/bin/ \
         && printf '[Service]\\nEnvironment=FAKE_AWS_SSM_DIR=/ssm\\n' > /etc/systemd/system/ai-env-proxy-reload.service.d/test.conf",
    );
    lab.sh("proxy", "PATH=/tmp/stub:$PATH bash /ssm/user-data.sh");
    lab.boot_checks("first boot");
    assert!(lab.sh("proxy", "journalctl --no-pager -u ai-env-proxy-reload -o cat").contains("applied (start queued)"));
    assert_eq!(lab.sh("proxy", "systemctl is-active logrotate.timer").trim(), "active");
    assert!(lab.sh("proxy", "systemctl cat logrotate.timer").contains("OnCalendar=hourly"));
    // An addition reconfigures, a removal restarts (a new main PID).
    lab.put("extras", &format!("{EXTRA_HOST}\tws-a\n"));
    assert!(lab.reload_ok(&[]).contains("applied (reconfigured)"));
    let pid = lab.unit_u64("squid.service", "MainPID");
    lab.put("extras", NO_EXTRAS);
    assert!(lab.reload_ok(&[]).contains("applied (restarted)"));
    assert_ne!(lab.unit_u64("squid.service", "MainPID"), pid);
    assert_eq!(lab.status().1["applied"], "yes");
    // A refused reload at boot: the unit fails and squid stays down (fail closed) ...
    lab.put("extras", "1.2.3.4\tws-a\n");
    let out = lab.exec("proxy", &[], &["systemctl", "restart", "ai-env-proxy-reload.service"], 120);
    assert!(!out.status.success(), "the boot unit refused");
    let started = Instant::now();
    while lab.exec("proxy", &[], &["systemctl", "is-active", "--quiet", "squid.service"], 30).status.success() {
        assert!(started.elapsed() < Duration::from_secs(20), "squid must not run after a refused boot reload");
        std::thread::sleep(Duration::from_millis(250));
    }
    let (line, st) = lab.status();
    assert_eq!((st["squid"].as_str(), st["parse"].as_str(), st["applied"].as_str()), ("inactive", "failed", "no"), "{line}");
    // ... until a good set is reloaded by hand: squid starts after the (re-run) boot unit.
    lab.put("extras", NO_EXTRAS);
    assert!(lab.reload_ok(&[]).contains("applied (started)"));
    lab.boot_checks("after a refused boot");
    // A reboot applies the set before squid again.
    docker_ok(&["restart", "-t", "20", &lab.container("proxy")], 120);
    lab.wait_systemd();
    lab.boot_checks("after a reboot");
}
