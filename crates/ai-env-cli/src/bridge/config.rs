//! `~/.config/ai-env/bridge/bridge.toml` — the bridge's operator configuration
//! (§2.4 of the plan). The AWS region is pinned in code: a differing value in
//! the file is an error and the environment is never consulted.
use crate::bridge::errors::BridgeError;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The only region the MicroVM API is available in for this account (eu-west-3
/// answers 403). Pinned in code; `AWS_REGION` is ignored on purpose.
pub const REGION: &str = "eu-central-1";

/// State root and config file location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub root: PathBuf,
    pub config: PathBuf,
}

impl Paths {
    /// `AI_ENV_BRIDGE_DIR` | `$HOME/.config/ai-env/bridge`; config from
    /// `AI_ENV_BRIDGE_CONFIG` | `<root>/bridge.toml`.
    pub fn resolve() -> Result<Paths, BridgeError> {
        let root = match std::env::var_os("AI_ENV_BRIDGE_DIR") {
            Some(d) => PathBuf::from(d),
            None => {
                let home = std::env::var_os("HOME").ok_or_else(|| BridgeError::Config("HOME is not set".into()))?;
                PathBuf::from(home).join(".config").join("ai-env").join("bridge")
            }
        };
        Ok(Self::from_root_and_env(root, std::env::var_os("AI_ENV_BRIDGE_CONFIG").map(PathBuf::from)))
    }

    #[must_use]
    pub fn from_root_and_env(root: PathBuf, config_override: Option<PathBuf>) -> Paths {
        let config = config_override.unwrap_or_else(|| root.join("bridge.toml"));
        Paths { root, config }
    }

    #[must_use]
    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AwsCfg {
    pub region: Option<String>,
    pub credentials: String,
    pub image_arn: Option<String>,
    pub image_version: String,
    pub execution_role_arn: Option<String>,
    pub egress_connector_arn: Option<String>,
    pub proxy_private_ip: Option<String>,
    pub budget_name: Option<String>,
}

impl Default for AwsCfg {
    fn default() -> Self {
        AwsCfg {
            region: None,
            credentials: "container".into(),
            image_arn: None,
            image_version: "active".into(),
            execution_role_arn: None,
            egress_connector_arn: None,
            proxy_private_ip: None,
            budget_name: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct VmCfg {
    pub memory_mib: u32,
    pub max_duration_s: u32,
    pub max_idle_s: u32,
    pub suspended_s: Option<u32>,
    pub auto_resume: bool,
    pub reuse_per_workspace: bool,
    pub suspend_on_close: bool,
    pub max_concurrent: u32,
    pub migrate_before_wall_s: u32,
    pub prewarm_on_auth_status: String,
    pub auto_gc: bool,
}

impl Default for VmCfg {
    fn default() -> Self {
        VmCfg {
            memory_mib: 2048,
            max_duration_s: 28_800,
            max_idle_s: 300,
            suspended_s: None,
            auto_resume: true,
            reuse_per_workspace: true,
            suspend_on_close: true,
            max_concurrent: 3,
            migrate_before_wall_s: 1200,
            prewarm_on_auth_status: "auto".into(),
            auto_gc: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WrapperCfg {
    pub local_fallback: bool,
    pub strip_add_dir: bool,
    pub strip_debug: bool,
    pub env_forward: Vec<String>,
    pub env_extra: Vec<String>,
    pub initial_permission_mode: String,
}

impl Default for WrapperCfg {
    fn default() -> Self {
        WrapperCfg {
            local_fallback: true,
            strip_add_dir: true,
            strip_debug: true,
            env_forward: [
                "CLAUDE_CODE_ENTRYPOINT",
                "CLAUDE_AGENT_SDK_VERSION",
                "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING",
                "MCP_CONNECTION_NONBLOCKING",
                "CLAUDE_CODE_ENABLE_TASKS",
                "LANG",
                "TERM",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            env_extra: Vec::new(),
            initial_permission_mode: "default".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspacesCfg {
    pub roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspaceCfg {
    pub path: PathBuf,
    pub branch: Option<String>,
    pub memory_mib: Option<u32>,
    pub egress_allow: Vec<String>,
    pub seed_allow_dirty: bool,
    pub trust_repo_settings: bool,
}

impl Default for WorkspaceCfg {
    fn default() -> Self {
        WorkspaceCfg {
            path: PathBuf::new(),
            branch: None,
            memory_mib: None,
            egress_allow: Vec::new(),
            seed_allow_dirty: false,
            trust_repo_settings: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CredsCfg {
    pub mode: String,
    pub deliver: String,
    pub key: String,
}

impl Default for CredsCfg {
    fn default() -> Self {
        CredsCfg { mode: "setup-token".into(), deliver: "fd".into(), key: "ai-env-bridge".into() }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EgressCfg {
    pub require: bool,
    pub disable_nonessential: bool,
}

impl Default for EgressCfg {
    fn default() -> Self {
        EgressCfg { require: true, disable_nonessential: true }
    }
}

/// `[review] tripwires settings_policy` — the two scan lists `box review`,
/// seed and `make image-zip` read. Both default to files under the bridge
/// root, so an empty table is the documented setup.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ReviewCfg {
    pub tripwires: Option<PathBuf>,
    pub settings_policy: Option<PathBuf>,
}

impl ReviewCfg {
    /// `[review].tripwires` | `<root>/tripwires.txt`.
    #[must_use]
    pub fn tripwires_path(&self, paths: &Paths) -> PathBuf {
        self.tripwires.clone().unwrap_or_else(|| paths.root.join("tripwires.txt"))
    }

    /// `[review].settings_policy` | `<root>/settings-policy.txt`.
    #[must_use]
    pub fn settings_policy_path(&self, paths: &Paths) -> PathBuf {
        self.settings_policy.clone().unwrap_or_else(|| paths.root.join("settings-policy.txt"))
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PanelCfg {
    pub port: u16,
    pub enabled: bool,
}

impl Default for PanelCfg {
    fn default() -> Self {
        PanelCfg { port: 7391, enabled: false }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BridgeConfig {
    pub aws: AwsCfg,
    pub vm: VmCfg,
    pub wrapper: WrapperCfg,
    pub workspaces: WorkspacesCfg,
    #[serde(rename = "workspace")]
    pub workspace_overrides: Vec<WorkspaceCfg>,
    pub creds: CredsCfg,
    pub egress: EgressCfg,
    pub review: ReviewCfg,
    pub panel: PanelCfg,
}

impl BridgeConfig {
    pub fn parse(text: &str) -> Result<Self, BridgeError> {
        let cfg: BridgeConfig = toml::from_str(text).map_err(|e| BridgeError::Config(format!("bridge.toml: {e}")))?;
        if let Some(r) = &cfg.aws.region {
            if r != REGION {
                return Err(BridgeError::Config(format!(
                    "[aws].region = {r:?} but the MicroVM bridge is pinned to {REGION} (eu-west-3 is not supported)"
                )));
            }
        }
        Ok(cfg)
    }

    /// `Ok(None)` when the file does not exist.
    pub fn load(paths: &Paths) -> Result<Option<Self>, BridgeError> {
        match std::fs::read_to_string(&paths.config) {
            Ok(text) => Self::parse(&text).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BridgeError::Config(format!("cannot read {}: {e}", paths.config.display()))),
        }
    }

    /// Always the pinned region; the environment is never consulted.
    #[must_use]
    pub fn region(&self) -> aws_sdk_lambdamicrovms::config::Region {
        aws_sdk_lambdamicrovms::config::Region::new(REGION)
    }

    /// One budget covers running + suspended unless overridden.
    #[must_use]
    pub fn suspended_s(&self) -> u32 {
        self.vm.suspended_s.unwrap_or(self.vm.max_duration_s)
    }

    /// Is `path` under one of the approved workspace roots?
    #[must_use]
    pub fn under_roots(&self, path: &Path) -> bool {
        self.workspaces.roots.iter().any(|r| path.starts_with(r))
    }
}

/// A note when `AWS_REGION`/`AWS_DEFAULT_REGION` disagree with the pin.
#[must_use]
pub fn env_region_warning() -> Option<String> {
    for var in ["AWS_REGION", "AWS_DEFAULT_REGION"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() && v != REGION {
                return Some(format!("env {var}={v} ignored (region pinned to {REGION})"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_from_empty() {
        let c = BridgeConfig::parse("").unwrap();
        assert_eq!(c.vm.memory_mib, 2048);
        assert_eq!(c.vm.max_duration_s, 28_800);
        assert_eq!(c.suspended_s(), 28_800);
        assert_eq!(c.creds.key, "ai-env-bridge");
        assert!(c.egress.require);
        assert_eq!(c.region().as_ref(), "eu-central-1");
    }

    #[test]
    fn region_mismatch_is_error() {
        let e = BridgeConfig::parse("[aws]\nregion = \"eu-west-3\"\n").unwrap_err();
        assert!(e.to_string().contains("pinned to eu-central-1"), "{e}");
        assert!(BridgeConfig::parse("[aws]\nregion = \"eu-central-1\"\n").is_ok());
    }

    #[test]
    fn unknown_key_is_error() {
        assert!(BridgeConfig::parse("[vm]\nmemroy_mib = 4096\n").is_err());
    }

    #[test]
    fn suspended_override_and_workspaces() {
        let c = BridgeConfig::parse(
            "[vm]\nsuspended_s = 600\n[workspaces]\nroots = [\"/Users/mike/Documents/DeFi\"]\n[[workspace]]\npath = \"/Users/mike/Documents/DeFi/ai-env\"\negress_allow = [\"github.com\"]\n",
        )
        .unwrap();
        assert_eq!(c.suspended_s(), 600);
        assert!(c.under_roots(Path::new("/Users/mike/Documents/DeFi/ai-env")));
        assert!(!c.under_roots(Path::new("/tmp/x")));
        assert_eq!(c.workspace_overrides[0].egress_allow, vec!["github.com".to_string()]);
    }

    #[test]
    fn paths_default_and_override() {
        let p = Paths::from_root_and_env(PathBuf::from("/r"), None);
        assert_eq!(p.config, PathBuf::from("/r/bridge.toml"));
        let q = Paths::from_root_and_env(PathBuf::from("/r"), Some(PathBuf::from("/x/b.toml")));
        assert_eq!(q.config, PathBuf::from("/x/b.toml"));
        assert_eq!(q.logs(), PathBuf::from("/r/logs"));
    }

    #[test]
    fn review_paths_override_and_default() {
        let p = Paths::from_root_and_env(PathBuf::from("/r"), None);
        let c = BridgeConfig::parse("[review]\ntripwires = \"/x/t.txt\"\n").unwrap();
        assert_eq!(c.review.tripwires, Some(PathBuf::from("/x/t.txt")));
        assert_eq!(c.review.tripwires_path(&p), PathBuf::from("/x/t.txt"));
        assert_eq!(c.review.settings_policy, None);
        assert_eq!(c.review.settings_policy_path(&p), PathBuf::from("/r/settings-policy.txt"));
        let d = BridgeConfig::parse("").unwrap();
        assert_eq!(d.review, ReviewCfg::default());
        assert_eq!(d.review.tripwires_path(&p), PathBuf::from("/r/tripwires.txt"));
        assert_eq!(d.review.settings_policy_path(&p), PathBuf::from("/r/settings-policy.txt"));
        let e = BridgeConfig::parse("[review]\nsettings_policy = \"/x/p.toml\"\n").unwrap();
        assert_eq!(e.review.settings_policy_path(&p), PathBuf::from("/x/p.toml"));
    }

    #[test]
    fn review_pre_push_hook_is_unknown() {
        let e = BridgeConfig::parse("[review]\npre_push_hook = true\n").unwrap_err();
        assert!(e.to_string().contains("pre_push_hook"), "{e}");
    }

    #[test]
    fn load_missing_is_none() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::from_root_and_env(d.path().to_path_buf(), None);
        assert_eq!(BridgeConfig::load(&p).unwrap(), None);
        std::fs::write(&p.config, "[panel]\nport = 1\n").unwrap();
        assert_eq!(BridgeConfig::load(&p).unwrap().unwrap().panel.port, 1);
    }
}
