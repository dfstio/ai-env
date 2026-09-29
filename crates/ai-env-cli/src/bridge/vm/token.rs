//! Endpoint tokens: the port allowlist and minting with the expiry recorded (plan S4 D5, step 5).
//!
//! One port per token (`Port(p)`, never `AllPorts`), `p` from
//! [`ALLOWED_PORTS`] (plan §2.8(2)), 1–60 minutes. The value is a `Secret`
//! registered with the scrubber; the VM row keeps only its expiry
//! (`token_expiries["<port>"]`), never the value. Internal mints (`/health`,
//! gc, smoke) are [`INTERNAL_MINUTES`]-minute `Port(8080)` tokens.
use crate::bridge::api::{AuthToken, MicrovmApi, APP_PORT};
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::registry::{is_vm_id, update_row};
use crate::wire::redact::register_secret;

/// The ports a token may open: the shim's app port, the reserved second app
/// port and git (plan §2.8(2)). Anything else is exit 9.
pub const ALLOWED_PORTS: [u16; 3] = [8080, 8082, 9418];

/// Lifetime of the tokens the bridge mints for itself (`/health`, gc, smoke).
pub const INTERNAL_MINUTES: u16 = 5;

/// The service's token lifetime range, in minutes.
pub const MINUTES_RANGE: std::ops::RangeInclusive<u16> = 1..=60;

fn allowlist() -> String {
    ALLOWED_PORTS.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
}

/// `port` must be one of [`ALLOWED_PORTS`]; anything else is `Policy` (exit 9)
/// naming the allowlist.
pub fn check_port(port: u16) -> Result<(), BridgeError> {
    if ALLOWED_PORTS.contains(&port) {
        Ok(())
    } else {
        Err(BridgeError::Policy(format!("token port {port} is not allowed (allowed: {})", allowlist())))
    }
}

/// `minutes` must be 1..=60 (the service's range); anything else is `Policy` (exit 9).
pub fn check_minutes(minutes: u16) -> Result<(), BridgeError> {
    if MINUTES_RANGE.contains(&minutes) {
        Ok(())
    } else {
        Err(BridgeError::Policy(format!("token lifetime of {minutes} minutes is outside {}..={}", MINUTES_RANGE.start(), MINUTES_RANGE.end())))
    }
}

/// Mint a `Port(port)` token for `minutes`: both are checked before any call;
/// every header value is registered with the scrubber; when `state/vms/<id>.toml`
/// exists its `token_expiries["<port>"]` is set to the expiry (a row that
/// cannot be read or written costs a `warn!` in the log, never the token).
pub async fn mint<A: MicrovmApi>(api: &A, paths: &Paths, id: &str, port: u16, minutes: u16) -> Result<AuthToken, BridgeError> {
    check_port(port)?;
    check_minutes(minutes)?;
    let token = api.create_auth_token(id, minutes, port).await?;
    for value in token.headers.values() {
        register_secret(value.expose());
    }
    if let Err(e) = record_expiry(paths, id, port, token.expires_at_unix) {
        tracing::warn!("vm {id}: token minted for port {port}, but its expiry was not recorded in the row: {e}");
    }
    Ok(token)
}

/// The bridge's own token: [`INTERNAL_MINUTES`] minutes, `Port(8080)`.
pub async fn mint_internal<A: MicrovmApi>(api: &A, paths: &Paths, id: &str) -> Result<AuthToken, BridgeError> {
    mint(api, paths, id, APP_PORT, INTERNAL_MINUTES).await
}

/// `token_expiries["<port>"]` of the row, under the rows lock (`registry::update_row`).
fn record_expiry(paths: &Paths, id: &str, port: u16, expires_at_unix: u64) -> Result<(), BridgeError> {
    if !is_vm_id(id) {
        return Ok(());
    }
    update_row(paths, id, |row| {
        row.token_expiries.insert(port.to_string(), expires_at_unix);
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::{Call, FakeMicrovmApi, IdleSpec, RunSpec, FAKE_IMAGE_ARN, TOKEN_HEADER};
    use crate::bridge::vm::registry::{read_row, write_row, RowStatus, VmRow};
    use crate::errors::CliError;
    use crate::wire::time::unix_now;

    fn spec() -> RunSpec {
        RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: "01926f2e-0000-7000-8000-0000000000aa".into(),
        }
    }

    #[test]
    fn port_allowlist_is_exit_9() {
        for p in ALLOWED_PORTS {
            check_port(p).unwrap();
        }
        for p in [0, 22, 8022, 8081, 9000, 65535] {
            let e = check_port(p).unwrap_err();
            let text = e.to_string();
            assert!(text.contains(&format!("port {p}")) && text.contains("8080, 8082, 9418"), "{text}");
            assert_eq!(CliError::from(e).exit_code(), 9);
        }
    }

    #[test]
    fn minutes_are_1_to_60() {
        check_minutes(1).unwrap();
        check_minutes(60).unwrap();
        for m in [0, 61, 1440] {
            assert_eq!(CliError::from(check_minutes(m).unwrap_err()).exit_code(), 9, "{m}");
        }
    }

    #[tokio::test]
    async fn mint_checks_before_calling_and_records_the_expiry_only() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let api = FakeMicrovmApi::new();
        api.set_auto_advance(true);
        let vm = api.run(&spec()).await.unwrap();
        assert!(mint(&api, &paths, &vm.id, 9000, 5).await.is_err());
        assert!(mint(&api, &paths, &vm.id, 8080, 0).await.is_err());
        assert!(!api.calls().iter().any(|c| matches!(c, Call::Token { .. })), "refused before any call");

        // No row: minted, nothing written.
        let t = mint(&api, &paths, &vm.id, 8082, 30).await.unwrap();
        assert_eq!(t.port, 8082);
        assert!(!paths.vms().exists(), "no row is created by a mint");

        // With a row: the expiry lands in token_expiries, the value nowhere.
        let row = VmRow { id: vm.id.clone(), status: RowStatus::Running, client_token: spec().client_token, ..VmRow::default() };
        write_row(&paths, &row).unwrap();
        let before = unix_now();
        let t = mint_internal(&api, &paths, &vm.id).await.unwrap();
        assert_eq!(t.port, APP_PORT);
        assert!(t.expires_at_unix >= before + 300 && t.expires_at_unix <= unix_now() + 300);
        let back = read_row(&paths, &vm.id).unwrap().unwrap();
        assert_eq!(back.token_expiries.get("8080"), Some(&t.expires_at_unix));
        let text = std::fs::read_to_string(paths.vms().join(format!("{}.toml", vm.id))).unwrap();
        assert!(!text.contains(t.headers[TOKEN_HEADER].expose().as_str()), "the value is never stored");
        assert!(api.calls().contains(&Call::Token { id: vm.id.clone(), minutes: INTERNAL_MINUTES, port: 8080 }));
    }

    #[tokio::test]
    async fn an_unreadable_row_does_not_cost_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let api = FakeMicrovmApi::new();
        let vm = api.run(&spec()).await.unwrap();
        std::fs::create_dir_all(paths.vms()).unwrap();
        std::fs::write(paths.vms().join(format!("{}.toml", vm.id)), "status = [broken").unwrap();
        assert!(mint_internal(&api, &paths, &vm.id).await.is_ok());
    }
}
