//! The hardening `/etc/claude-code/managed-settings.json` must carry (plan
//! D6), in one place: the Mac's image scan (`bridge::scan`) and the VM's
//! `/validate` V3 (`shim::validate`) both check a file against it, so the
//! two gates cannot drift apart. Managed settings are read by claude
//! regardless of `--setting-sources`; these four values are what keep a
//! `--permission-mode bypassPermissions` from the Mac, auto mode and the
//! self-updater out of every VM.

/// `(JSON path, required string value)`.
pub const MANAGED_HARDENING: [(&[&str], &str); 4] = [
    (&["permissions", "disableBypassPermissionsMode"], "disable"),
    (&["permissions", "disableAutoMode"], "disable"),
    (&["env", "DISABLE_AUTOUPDATER"], "1"),
    (&["env", "DISABLE_UPDATES"], "1"),
];

/// The dotted paths of every hardening value that is missing or different
/// in `doc` (empty = compliant). Never the values themselves.
#[must_use]
pub fn hardening_gaps(doc: &serde_json::Value) -> Vec<String> {
    MANAGED_HARDENING
        .iter()
        .filter(|(path, want)| path.iter().try_fold(doc, |v, k| v.get(k)).and_then(serde_json::Value::as_str) != Some(*want))
        .map(|(path, _)| path.join("."))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_file_is_compliant() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../image/managed-settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(hardening_gaps(&doc), Vec::<String>::new());
    }

    #[test]
    fn every_missing_or_weakened_value_is_named() {
        assert_eq!(hardening_gaps(&serde_json::json!({})).len(), 4);
        let weak = serde_json::json!({
            "permissions": {"disableBypassPermissionsMode": "enable", "disableAutoMode": "disable"},
            "env": {"DISABLE_AUTOUPDATER": 1, "DISABLE_UPDATES": "1"}
        });
        assert_eq!(hardening_gaps(&weak), vec!["permissions.disableBypassPermissionsMode".to_string(), "env.DISABLE_AUTOUPDATER".to_string()], "a number is not the string \"1\"");
        assert_eq!(hardening_gaps(&serde_json::json!({"permissions": "disable"})).len(), 4, "wrong shapes count as missing");
    }
}
