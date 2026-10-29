//! The relay's units and config on the instance (§R-relay.3, `deploy/`): I's user data embeds these files
//! verbatim (Q-R5), so their text is pinned here, line for line.

use std::path::{Path, PathBuf};

use ai_env_relay::config::{Config, DEFAULT_ENV_FILE, LIVE_DIR, REQUEST_LOG};

fn deploy(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A unit as (section, key, value) lines, in order; comments and blanks dropped.
fn unit(text: &str) -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';')) {
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.to_string();
            continue;
        }
        let (k, v) = line.split_once('=').unwrap_or_else(|| panic!("not KEY=VALUE: {line}"));
        out.push((section.clone(), k.to_string(), v.to_string()));
    }
    out
}

fn lines(spec: &[(&str, &str)]) -> Vec<(String, String, String)> {
    let mut section = "";
    let mut out = Vec::new();
    for (k, v) in spec {
        if k.starts_with('[') {
            section = v;
            continue;
        }
        out.push((section.to_string(), k.to_string(), v.to_string()));
    }
    out
}

fn value<'a>(u: &'a [(String, String, String)], section: &str, key: &str) -> Vec<&'a str> {
    u.iter().filter(|(s, k, _)| s == section && k == key).map(|(_, _, v)| v.as_str()).collect()
}

/// Deploy test 1.
#[test]
fn the_relay_unit_is_notify_with_watchdog_and_hardening() {
    let text = deploy("ai-env-relay.service");
    let got = unit(&text);
    let want = lines(&[
        ("[", "Unit"),
        ("Description", "ai-env relay: the worker tunnel (443) and the VMs' private face (@RELAY_IP@:@RELAY_PORT@)"),
        ("Wants", "network-online.target"),
        ("After", "network-online.target ai-env-relay-guard.service"),
        ("Requires", "ai-env-relay-guard.service"),
        ("ConditionPathExists", "/usr/local/libexec/ai-env-relay/current"),
        ("ConditionPathExists", "/var/lib/ai-env-relay/live/tls.pem"),
        ("StartLimitIntervalSec", "300"),
        ("StartLimitBurst", "10"),
        ("[", "Service"),
        ("Type", "notify"),
        ("NotifyAccess", "main"),
        ("WatchdogSec", "30"),
        ("ExecStart", "/usr/local/libexec/ai-env-relay/current"),
        ("ExecReload", "/bin/kill -HUP $MAINPID"),
        ("EnvironmentFile", "/etc/ai-env-relay/relay.env"),
        ("Environment", "RUST_LOG=info"),
        ("User", "ai-env-relay"),
        ("Group", "ai-env-relay"),
        ("AmbientCapabilities", "CAP_NET_BIND_SERVICE"),
        ("CapabilityBoundingSet", "CAP_NET_BIND_SERVICE"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateDevices", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelLogs", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectHostname", "yes"),
        ("ProtectProc", "invisible"),
        ("ProcSubset", "pid"),
        ("RestrictNamespaces", "yes"),
        ("RestrictRealtime", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("LockPersonality", "yes"),
        ("MemoryDenyWriteExecute", "yes"),
        ("RemoveIPC", "yes"),
        ("SystemCallArchitectures", "native"),
        ("SystemCallFilter", "@system-service"),
        ("SystemCallFilter", "~@privileged @resources"),
        ("SystemCallErrorNumber", "EPERM"),
        ("RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX"),
        ("IPAddressDeny", "169.254.0.0/16 fd00:ec2::/32"),
        ("UMask", "0077"),
        ("LogsDirectory", "ai-env-relay/requests"),
        ("LogsDirectoryMode", "0750"),
        ("StandardOutput", "append:/var/log/ai-env-relay/relay.log"),
        ("StandardError", "append:/var/log/ai-env-relay/relay.log"),
        ("MemoryMax", "320M"),
        ("TasksMax", "256"),
        ("LimitNOFILE", "8192"),
        ("Restart", "always"),
        ("RestartSec", "5"),
        ("TimeoutStartSec", "60"),
        ("TimeoutStopSec", "10"),
        ("[", "Install"),
        ("WantedBy", "multi-user.target"),
    ]);
    assert_eq!(got, want, "§R-relay.3.3's set, exactly");
    for (key, v) in [
        ("Type", "notify"),
        ("WatchdogSec", "30"),
        ("User", "ai-env-relay"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("IPAddressDeny", "169.254.0.0/16 fd00:ec2::/32"),
        ("CapabilityBoundingSet", "CAP_NET_BIND_SERVICE"),
        ("ExecReload", "/bin/kill -HUP $MAINPID"),
    ] {
        assert_eq!(value(&got, "Service", key), vec![v], "{key}");
    }
    assert_eq!(value(&got, "Unit", "Requires"), vec!["ai-env-relay-guard.service"]);
    assert!(value(&got, "Service", "SystemCallFilter").contains(&"~@privileged @resources"));
    assert!(!got.iter().any(|(_, k, v)| (k == "User" && v == "root") || k == "DynamicUser" || k == "PrivateUsers"));
    for line in text.lines().filter(|l| l.contains('=')) {
        assert!(!line.contains(" #") && !line.contains(" ;"), "a trailing comment: {line}");
    }
}

/// Deploy test 2. The guard is stateless (§Q.8 F4): no rule reads conntrack, so nothing loads it host-wide. The
/// relay's user sends no SYN without ACK (a connect: reset) and no packet but TCP; the SYN-ACKs, ACKs, FINs and RSTs
/// of the connections it accepted pass.
#[test]
fn the_guard_blocks_the_relay_uid() {
    let nft = deploy("guard.nft");
    let rules: Vec<&str> = nft.lines().map(str::trim).filter(|l| l.starts_with("meta ")).collect();
    assert_eq!(
        rules,
        vec![
            "meta skuid \"ai-env-relay\" ip daddr 169.254.0.0/16 counter reject",
            "meta skuid \"ai-env-relay\" ip6 daddr fd00:ec2::/32 counter reject",
            "meta skuid \"ai-env-relay\" tcp flags & (syn | ack) == syn counter reject with tcp reset",
            "meta skuid \"ai-env-relay\" meta l4proto != tcp counter reject",
        ]
    );
    assert!(rules.iter().all(|r| r.starts_with("meta skuid \"ai-env-relay\" ")));
    assert!(nft.lines().any(|l| l.trim() == "table inet ai_env_relay_guard {"));
    assert!(nft.lines().any(|l| l.trim() == "delete table inet ai_env_relay_guard"), "replaced whole: idempotent");
    assert!(nft.lines().any(|l| l.trim() == "type filter hook output priority filter; policy accept;"));
    // Every statement, in order: no other rule (none for other uids) and no `ct` or `notrack`, which load conntrack.
    let statements: Vec<&str> = nft.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let mut want = vec![
        "table inet ai_env_relay_guard",
        "delete table inet ai_env_relay_guard",
        "table inet ai_env_relay_guard {",
        "chain output {",
        "type filter hook output priority filter; policy accept;",
    ];
    want.extend(&rules);
    want.extend(["}", "}"]);
    assert_eq!(statements, want);
    let words: Vec<&str> = statements.iter().flat_map(|l| l.split_whitespace()).collect();
    assert!(!words.contains(&"ct") && !words.contains(&"notrack"), "stateless: {statements:?}");

    let guard = unit(&deploy("ai-env-relay-guard.service"));
    assert_eq!(value(&guard, "Service", "Type"), vec!["oneshot"]);
    assert_eq!(value(&guard, "Service", "RemainAfterExit"), vec!["yes"]);
    assert_eq!(value(&guard, "Service", "ExecStart"), vec!["/usr/sbin/nft -f /etc/ai-env-relay/guard.nft"]);
    assert_eq!(value(&guard, "Service", "ExecStop"), vec!["/usr/sbin/nft delete table inet ai_env_relay_guard"]);
    assert_eq!(value(&guard, "Unit", "Before"), vec!["ai-env-relay.service"]);
    assert_eq!(value(&guard, "Install", "RequiredBy"), vec!["ai-env-relay.service"]);
    // Q-R18 (phase 0): a later nftables or firewalld start cannot flush the table under a running relay.
    assert_eq!(value(&guard, "Unit", "After"), vec!["nftables.service firewalld.service"]);
    assert_eq!(value(&guard, "Unit", "Conflicts"), vec!["firewalld.service"]);
}

/// Deploy test 3.
#[test]
fn the_env_example_is_the_unit_s_config() {
    let service = unit(&deploy("ai-env-relay.service"));
    assert_eq!(value(&service, "Service", "EnvironmentFile"), vec![DEFAULT_ENV_FILE], "the default of `check --env-file`");
    let exec = value(&service, "Service", "ExecStart");
    assert_eq!(exec.len(), 1);
    assert!(!exec[0].contains(' '), "ExecStart has no argument: {}", exec[0]);

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/relay.env.example");
    let vars = Config::read_env_file(&path).expect("the example reads");
    let get = |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| PathBuf::from(v)).unwrap_or_else(|| panic!("{k}"));
    let tls = get(LIVE_DIR).join("tls.pem");
    assert!(value(&service, "Unit", "ConditionPathExists").contains(&tls.to_str().unwrap()), "{}", tls.display());
    let logs = Path::new("/var/log").join(value(&service, "Service", "LogsDirectory")[0]);
    assert_eq!(get(REQUEST_LOG).parent(), Some(logs.as_path()));
    let (cfg, warnings) = Config::from_vars(vars.clone()).expect("the example loads");
    assert!(warnings.is_empty());
    assert_eq!(cfg.request_log, get(REQUEST_LOG));
}
