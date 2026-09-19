//! Clone of the Claude extension's transcript-mirror key (2.1.278): given the
//! projects root and the `filePath` of a `transcript_mirror` frame, decide
//! where the entries belong — or reject the path.
//!
//! Rules: `rel = path.relative(root, file)`; `..` first or absolute → none;
//! fewer than 2 segments → none; exactly 2 with a `.jsonl` second segment →
//! `{project_key, session_id}`; 3 segments → none; 4 or more →
//! `{project_key, session_id, subpath}` with `.jsonl` stripped from the last
//! segment only.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorKey {
    pub project_key: String,
    pub session_id: String,
    pub subpath: Option<String>,
}

/// Lexical clone of POSIX `path.resolve` for an absolute input: collapses
/// `//`, `.` and `..` without touching the filesystem.
fn node_resolve(p: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s.to_string()),
        }
    }
    out
}

/// Lexical clone of POSIX `path.relative(from, to)`.
pub fn node_relative(from: &str, to: &str) -> String {
    let f = node_resolve(from);
    let t = node_resolve(to);
    let common = f.iter().zip(t.iter()).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<&str> = vec![".."; f.len() - common];
    parts.extend(t[common..].iter().map(String::as_str));
    parts.join("/")
}

fn strip_jsonl(s: &str) -> String {
    s.strip_suffix(".jsonl").unwrap_or(s).to_string()
}

#[must_use]
pub fn mirror_key(projects_root: &str, file_path: &str) -> Option<MirrorKey> {
    let rel = node_relative(projects_root, file_path);
    let segs: Vec<&str> = rel.split('/').collect();
    if segs[0] == ".." || rel.starts_with('/') {
        return None;
    }
    if segs.len() < 2 {
        return None;
    }
    let project_key = segs[0].to_string();
    let second = segs[1];
    if segs.len() == 2 {
        if second.ends_with(".jsonl") {
            return Some(MirrorKey { project_key, session_id: strip_jsonl(second), subpath: None });
        }
        return None;
    }
    if segs.len() >= 4 {
        let mut rest: Vec<String> = segs[2..].iter().map(|s| (*s).to_string()).collect();
        if let Some(last) = rest.last_mut() {
            *last = strip_jsonl(last);
        }
        return Some(MirrorKey { project_key, session_id: second.to_string(), subpath: Some(rest.join("/")) });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = "/Users/mike/.claude/projects";
    const P: &str = "-Users-mike-Documents-DeFi-ai-env";
    const S: &str = "0fc50cce-c5c3-418e-980e-ff1861ab423d";

    fn key(sub: Option<&str>) -> Option<MirrorKey> {
        Some(MirrorKey { project_key: P.to_string(), session_id: S.to_string(), subpath: sub.map(str::to_string) })
    }

    #[test]
    fn node_relative_kats() {
        assert_eq!(node_relative("/a/b", "/a/b/c"), "c");
        assert_eq!(node_relative("/a/b", "/a/c"), "../c");
        assert_eq!(node_relative("/a", "/a"), "");
        assert_eq!(node_relative("/a/b/", "/a//b/./c"), "c");
    }

    #[test]
    fn mirror_key_kats() {
        assert_eq!(mirror_key(R, &format!("{R}/{P}/{S}.jsonl")), key(None));
        assert_eq!(
            mirror_key(R, &format!("{R}/{P}/{S}/subagents/agent-a34bd0532e489ebd0.jsonl")),
            key(Some("subagents/agent-a34bd0532e489ebd0"))
        );
        assert_eq!(
            mirror_key(R, &format!("{R}/{P}/{S}/subagents/workflows/x.jsonl")),
            key(Some("subagents/workflows/x"))
        );
        assert_eq!(
            mirror_key(R, &format!("{R}/{P}/{S}/subagents/agent-a1.meta.json")),
            key(Some("subagents/agent-a1.meta.json"))
        );
        assert_eq!(mirror_key(R, &format!("{R}/{P}/{S}/subagents")), None);
        assert_eq!(mirror_key(R, &format!("{R}/{P}/{S}.meta.json")), None);
        assert_eq!(mirror_key(R, &format!("{R}/{P}")), None);
        assert_eq!(mirror_key(R, &format!("/Users/mike/other/{P}/{S}.jsonl")), None);
        assert_eq!(mirror_key(R, &format!("{R}/../projects/{P}/{S}.jsonl")), key(None));
        assert_eq!(mirror_key(R, &format!("{R}/{P}/{S}/x.jsonl")), None);
        assert_eq!(mirror_key(R, R), None);
    }
}
