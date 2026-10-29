//! The pages, written by hand (B §B5.5, §B5.7): every value through [`esc`];
//! no inline script, no inline style, no `style` attribute (the CSP forbids
//! them); every URL relative, written with the page's root prefix (`./` on the
//! top pages, `../` one level below the bearer) and put on
//! `<body data-root>`, where `assets/app.js` reads it.
use super::actions::{Action, ActionView, NO_TARGET};
use super::model::{AuditPage, Confirm, CostPage, Sessions, SettingsPage};
use super::REFRESH_S;
use crate::bridge::audit::read::Read;
use crate::bridge::registry::{SessionView, VmEntry};
use crate::bridge::title::{self, inert};
use crate::bridge::vm::cmd::fmt_secs;
use crate::bridge::vm::ops::Survey;
use crate::wire::redact::scrub;

/// The root prefix of a top page.
pub const TOP: &str = "./";
/// The root prefix of a page one level below the bearer (`session/<sid>`, `settings/<sid>`, `actions/<nonce>`).
pub const BELOW: &str = "../";

/// `&`, `<`, `>`, `"` and `'` as entities: every value a page shows.
#[must_use]
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A cell holding text.
fn td(text: &str) -> String {
    format!("<td>{}</td>", esc(text))
}

/// A table of `head` and rows of cells (each already HTML); `empty` when there is no row.
fn table(head: &[&str], rows: &[Vec<String>], empty: &str) -> String {
    if rows.is_empty() {
        return format!("<p class=\"empty\">{}</p>\n", esc(empty));
    }
    let head: String = head.iter().map(|h| format!("<th>{}</th>", esc(h))).collect();
    let body: String = rows.iter().map(|r| format!("<tr>{}</tr>\n", r.concat())).collect();
    format!("<table>\n<thead><tr>{head}</tr></thead>\n<tbody>\n{body}</tbody>\n</table>\n")
}

/// A link to `href` (relative, already prefixed) showing `text`.
fn link(href: &str, text: &str) -> String {
    format!("<a href=\"{}\">{}</a>", esc(href), esc(text))
}

/// `$<usd>` at 3 decimals, or `-`.
fn dollars(usd: Option<f64>) -> String {
    usd.map_or_else(|| "-".into(), |u| format!("${u:.3}"))
}

/// The confirm page of `action` on `target`, from a page whose root prefix is `root`.
fn confirm_href(root: &str, action: Action, target: &str) -> String {
    format!("{root}confirm?action={}&target={target}", action.word())
}

/// A page: the head (its stylesheet and script, the list pages' refresh), the navigation, `main`.
#[must_use]
pub fn page(root: &str, title: &str, refresh: bool, attrs: &[(&str, &str)], main: &str) -> String {
    let refresh = if refresh { format!("<meta http-equiv=\"refresh\" content=\"{REFRESH_S}\">\n") } else { String::new() };
    let attrs: String = attrs.iter().map(|(k, v)| format!(" data-{k}=\"{}\"", esc(v))).collect();
    let root_e = esc(root);
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n{refresh}<title>{} · ai-env panel</title>\n<link rel=\"stylesheet\" href=\"{root_e}assets/app.css\">\n<script src=\"{root_e}assets/app.js\" defer></script>\n</head>\n<body data-root=\"{root_e}\"{attrs}>\n<nav><a href=\"{root_e}\">Sessions</a> <a href=\"{root_e}vms\">VMs</a> <a href=\"{root_e}audit\">Audit</a> <a href=\"{root_e}cost\">Cost</a></nav>\n<main>\n<h1>{}</h1>\n{main}</main>\n</body>\n</html>\n",
        esc(title),
        esc(title)
    )
}

/// A model's error, or a refusal a page explains: its one line.
#[must_use]
pub fn error(root: &str, status: u16, line: &str) -> String {
    page(root, &format!("Error {status}"), false, &[], &format!("<p class=\"error\">{}</p>\n", esc(line)))
}

/// `/`: the sessions, newest first. S12 (T, §T3 U5, U6): the search form first (the Audit page's), the Title
/// column second (the name through `title::inert`, `-` without one); with a search, the note `<n> of <m> sessions
/// match` and a link to every session, and `no session matches` for none. A `q` of spaces alone is no search.
#[must_use]
pub fn sessions(m: &Sessions) -> String {
    let rows: Vec<Vec<String>> = m
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let extra = m.extras.get(i);
            let sid = &r.session_id;
            let mut actions = Vec::new();
            if r.mode == "remote" {
                actions.push(link(&format!("{TOP}settings/{sid}"), "Settings"));
                if r.microvm_id.is_some() {
                    actions.push(link(&confirm_href(TOP, Action::SessionMigrate, sid), "Migrate"));
                }
            }
            vec![
                format!("<td>{}</td>", link(&format!("{TOP}session/{sid}"), sid)),
                td(&r.title.as_deref().filter(|t| !t.is_empty()).map_or(std::borrow::Cow::Borrowed("-"), inert)),
                td(&r.status),
                td(&r.mode),
                td(&r.last_seen),
                td(r.slug.as_deref().unwrap_or("-")),
                td(extra.map_or("-", |e| e.vm.as_str())),
                td(&extra.map_or_else(|| "-".into(), |e| e.moves.to_string())),
                td(&dollars(extra.and_then(|e| e.usd))),
                format!("<td class=\"actions\">{}</td>", actions.join(" ")),
            ]
        })
        .collect();
    let searching = m.q.as_deref().and_then(title::needle).is_some();
    let form = format!(
        "<form method=\"get\" action=\"{TOP}\" class=\"filters\">\n<label>search <input name=\"q\" value=\"{}\"></label>\n<button type=\"submit\">Search</button>\n</form>\n",
        esc(m.q.as_deref().unwrap_or_default())
    );
    let note = if searching { format!("<p class=\"note\">{} of {} sessions match · {}</p>\n", m.rows.len(), m.total, link(TOP, "all sessions")) } else { String::new() };
    let main = table(&["Session", "Title", "Status", "Mode", "Last seen", "Slug", "VM", "Moves", "Cost", ""], &rows, if searching { "no session matches" } else { "no sessions yet" });
    page(TOP, "Sessions", true, &[("page", "sessions")], &format!("{form}{note}{main}<p class=\"note\">Every action asks for a confirmation first and names its CLI twin.</p>\n"))
}

/// One generation's line.
fn generation(g: &VmEntry) -> Vec<String> {
    vec![td(&g.gen.to_string()), td(&g.pid.to_string()), td(&g.vm), td(&g.from), td(g.to.as_deref().unwrap_or("-")), td(if g.why.is_empty() { "-" } else { &g.why }), td(g.end.as_deref().unwrap_or("-"))]
}

/// `/session/<sid>`: `session show`'s view. S12 (T, §T3 U7): with a name (`title::of_row`), the heading and
/// `<title>` are `<name> · <sid's first 8>`, else `Session <sid>`; the list gains `session` and `title` (the name
/// and its source, or `-`) first.
#[must_use]
pub fn session(v: &SessionView) -> String {
    let r = &v.row;
    let sid = &r.session_id;
    let named = title::of_row(r);
    let heading = named.as_ref().map_or_else(|| format!("Session {sid}"), |t| format!("{} · {}", inert(&t.text), sid.chars().take(8).collect::<String>()));
    let head = [
        ("session", sid.clone()),
        ("title", named.as_ref().map_or_else(|| "-".to_string(), |t| format!("{} ({})", inert(&t.text), t.source.word()))),
        ("status", r.status.clone()),
        ("mode", r.mode.clone()),
        ("cwd", r.cwd.clone().unwrap_or_else(|| "-".into())),
        ("extension", r.ext.clone().unwrap_or_else(|| "-".into())),
        ("VM", r.microvm_id.clone().unwrap_or_else(|| "-".into())),
        ("wrapper", if v.wrapper_live { format!("live (pid {})", r.pid) } else { "none".into() }),
        ("last seen", r.last_seen.clone()),
    ];
    let mut main: String = format!("<dl>\n{}</dl>\n", head.iter().map(|(k, val)| format!("<dt>{}</dt><dd>{}</dd>\n", esc(k), esc(val))).collect::<String>());
    if r.mode == "remote" && r.microvm_id.is_some() {
        main.push_str(&format!("<p>{}</p>\n", link(&confirm_href(BELOW, Action::SessionMigrate, sid), "Migrate to a new VM")));
    }
    main.push_str("<h2>Generations</h2>\n");
    main.push_str(&table(&["Gen", "Pid", "VM", "From", "To", "Why", "End"], &v.generations.iter().map(generation).collect::<Vec<_>>(), "no generation"));
    main.push_str("<h2>Moves</h2>\n");
    let moves: Vec<Vec<String>> = v
        .moves
        .iter()
        .map(|m| {
            vec![
                td(&m.at),
                td(&m.gen.to_string()),
                td(&m.kind),
                td(&m.why),
                td(&format!("{} → {}", m.from_vm, m.to_vm)),
                td(&m.outcome),
                td(&m.ms.map_or_else(|| "-".into(), |ms| format!("{ms} ms"))),
                td(&m.touchid),
                td(m.request.as_deref().unwrap_or("-")),
                td(&m.actor),
            ]
        })
        .collect();
    main.push_str(&table(&["At", "Gen", "Kind", "Why", "VMs", "Outcome", "Took", "Touch ID", "Request", "Actor"], &moves, "no move"));
    main.push_str("<h2>Timeline</h2>\n");
    let spans: Vec<Vec<String>> = v.timeline.iter().map(|s| vec![td(&s.vm), td(&s.phase), td(&s.from), td(&s.to), td(if s.inferred { "inferred" } else { "-" })]).collect();
    main.push_str(&table(&["VM", "Phase", "From", "To", "End"], &spans, "no span"));
    main.push_str("<h2>Cost</h2>\n");
    main.push_str(&match &v.cost {
        Some(c) => format!("<p>{} (range {}–{}), running {}, suspended {}, on {}</p>\n", esc(&dollars(Some(c.usd))), esc(&dollars(Some(c.low_usd))), esc(&dollars(Some(c.high_usd))), esc(&fmt_secs(i64::try_from(c.running_s).unwrap_or(i64::MAX))), esc(&fmt_secs(i64::try_from(c.suspended_s).unwrap_or(i64::MAX))), esc(&c.vms.join(", "))),
        None => "<p>none: the chat runs on this Mac</p>\n".to_string(),
    });
    main.push_str(&format!("<p>Settings captures: {}{}</p>\n", v.settings_captures, if v.settings_captures > 0 { format!(" ({})", link(&format!("{BELOW}settings/{sid}"), "the diff")) } else { String::new() }));
    page(BELOW, &heading, false, &[("page", "session")], &main)
}

/// The VM row's `vm list` WALL-LEFT cell: `-` for one gone or going.
fn wall_left(state: &str, row: Option<&crate::bridge::vm::registry::VmRow>, now: u64) -> String {
    let ended = matches!(state, "TERMINATED" | "TERMINATING" | "(terminated)") || row.is_some_and(|r| r.status == crate::bridge::vm::registry::RowStatus::Terminated);
    if ended {
        return "-".into();
    }
    row.and_then(|r| r.wall_left(now)).map_or_else(|| "-".into(), fmt_secs)
}

/// An age of `now - at`, or `-`.
fn age(at: Option<u64>, now: u64) -> String {
    at.map_or_else(|| "-".into(), |t| fmt_secs(i64::try_from(now.saturating_sub(t)).unwrap_or(i64::MAX)))
}

/// `/vms`: the registry's VMs as `vm list` shows them, their last state seen; the buttons by that state.
#[must_use]
pub fn vms(s: &Survey) -> String {
    let rows: Vec<Vec<String>> = s
        .items
        .iter()
        .map(|i| {
            let row = i.row.as_ref();
            let state = i.state.as_str();
            let mut actions = Vec::new();
            if i.state != "PENDING-ROW" && row.is_some() {
                if matches!(state, "RUNNING" | "(running)") {
                    actions.push(link(&confirm_href(TOP, Action::VmSuspend, &i.id), "Suspend"));
                }
                if matches!(state, "SUSPENDED" | "(suspended)") {
                    actions.push(link(&confirm_href(TOP, Action::VmResume, &i.id), "Resume"));
                }
                actions.push(link(&confirm_href(TOP, Action::VmTerminate, &i.id), "Terminate"));
            }
            let place = row.and_then(|r| r.workspace.clone().or_else(|| r.label.clone())).unwrap_or_else(|| "-".into());
            vec![
                td(&i.id),
                td(state),
                td(&row.and_then(|r| r.state_seen_at).map_or_else(|| "-".into(), |t| format!("{} ago", age(Some(t), s.now)))),
                td(&age(i.started_at, s.now)),
                td(&wall_left(state, row, s.now)),
                td(&i.cost.as_ref().map_or_else(|| "-".into(), |c| fmt_secs(i64::try_from(c.running_s).unwrap_or(i64::MAX)))),
                td(&dollars(i.cost.as_ref().map(|c| c.usd))),
                td(&place),
                td(i.source),
                format!("<td class=\"actions\">{}</td>", actions.join(" ")),
            ]
        })
        .collect();
    let main = format!(
        "<p>From this Mac's VM rows: each state is the last one seen. {} (one Touch ID) asks AWS.</p>\n{}",
        link(&confirm_href(TOP, Action::VmRefresh, NO_TARGET), "Refresh from AWS"),
        table(&["ID", "State", "Seen", "Age", "Wall left", "Run", "Cost", "Where", "Source", ""], &rows, "no VMs (TERMINATED hidden)")
    );
    page(TOP, "VMs", true, &[("page", "vms")], &main)
}

/// One audit row's cells: time, actor, event, session (8), VM, the other detail keys; scrubbed again.
fn audit_cells(r: &Read) -> Vec<String> {
    let shown_vm = r.vms.first().cloned();
    let rest: Vec<String> = r.detail.iter().filter(|(k, v)| k.as_str() != "actor" && Some(*v) != shown_vm.as_ref()).map(|(k, v)| format!("{k}={v}")).collect();
    let session = r.session.as_deref().map_or_else(|| "-".to_string(), |s| s.chars().take(8).collect());
    vec![td(&r.ts), td(r.actor.as_deref().unwrap_or("-")), td(&r.event), td(&session), td(shown_vm.as_deref().unwrap_or("-")), format!("<td class=\"detail\">{}</td>", esc(&scrub(&rest.join(" "))))]
}

/// `/audit`: the filter form, the last rows, then the live ones (`app.js`, over `events`).
#[must_use]
pub fn audit(m: &AuditPage) -> String {
    let field = |name: &str, label: &str, value: &str| format!("<label>{} <input name=\"{name}\" value=\"{}\"></label>\n", esc(label), esc(value));
    let form = format!(
        "<form method=\"get\" action=\"{TOP}audit\" class=\"filters\">\n{}{}{}<button type=\"submit\">Filter</button>\n</form>\n",
        field("event", "events", &m.args.event.join(",")),
        field("session", "session", m.args.session.as_deref().unwrap_or_default()),
        field("vm", "VM", m.args.vm.as_deref().unwrap_or_default())
    );
    let head: String = ["Time", "Actor", "Event", "Session", "VM", "Detail"].iter().map(|h| format!("<th>{h}</th>")).collect();
    let body: String = m.rows.iter().map(|r| format!("<tr>{}</tr>\n", audit_cells(r).concat())).collect();
    let main = format!("{form}<p class=\"note\">The last {} rows that match, then each new one as it is written.</p>\n<table>\n<thead><tr>{head}</tr></thead>\n<tbody id=\"rows\">\n{body}</tbody>\n</table>\n", super::AUDIT_PAGE_ROWS);
    page(TOP, "Audit", false, &[("page", "audit")], &main)
}

/// `/settings/<sid>`: the diff's lines, read-only, and the command that promotes its rules.
#[must_use]
pub fn settings(m: &SettingsPage) -> String {
    let lines: String = m.lines.iter().map(|l| format!("{}\n", esc(l))).collect();
    let main = format!(
        "<pre>{lines}</pre>\n<p>Read-only: this page writes nothing (not even diff.json). To promote the rules the session added into the image's settings, run on this Mac:</p>\n<pre>ai-env wrapper settings-sync {sid} --all-safe\nai-env wrapper settings-sync {sid} --rule &lt;R&gt;</pre>\n<p class=\"note\">Each is a dry run; add --write to write.</p>\n",
        sid = esc(&m.sid)
    );
    page(BELOW, &format!("Settings of {}", m.sid), false, &[("page", "settings")], &main)
}

/// `/cost`: the estimate, its VMs and its lines, what it leaves out and its caveats.
#[must_use]
pub fn cost(m: &CostPage) -> String {
    let e = &m.estimate;
    let form = format!("<form method=\"get\" action=\"{TOP}cost\" class=\"filters\">\n<label>since <input name=\"since\" value=\"{}\"></label>\n<button type=\"submit\">Estimate</button>\n</form>\n", esc(&m.since));
    let secs = |s: u64| fmt_secs(i64::try_from(s).unwrap_or(i64::MAX));
    let vms: Vec<Vec<String>> = e
        .vms
        .iter()
        .map(|v| vec![td(&v.id), td(&secs(v.running_s)), td(&secs(v.suspended_s)), td(&v.starts.to_string()), td(&v.resumes.to_string()), td(&v.suspends.to_string()), td(&dollars(Some(v.usd))), td(&v.note)])
        .collect();
    let lines: Vec<Vec<String>> = e.lines.iter().map(|l| vec![td(l.usage_type), td(l.service), td(&format!("{:.3} {}", l.quantity, l.unit)), td(&dollars(Some(l.usd)))]).collect();
    let list = |items: &[String]| items.iter().map(|i| format!("<li>{}</li>\n", esc(i))).collect::<String>();
    let main = format!(
        "{form}<p>window {} .. {}</p>\n<p class=\"total\">estimate {} (range {}–{}): MicroVMs {}, the proxy {}{}</p>\n{}{}<p>not counted: {}</p>\n<p>not estimated: {}</p>\n<h2>Caveats</h2>\n<ul>\n{}</ul>\n",
        esc(&e.since),
        esc(&e.until),
        esc(&dollars(Some(e.usd))),
        esc(&dollars(Some(e.low_usd))),
        esc(&dollars(Some(e.high_usd))),
        esc(&dollars(Some(e.microvm_usd))),
        esc(&dollars(Some(e.proxy_usd))),
        if e.proxy_assumed { " (the proxy assumed running)" } else { "" },
        table(&["VM", "Run", "Suspended", "Starts", "Resumes", "Suspends", "Cost", "Note"], &vms, "no VM in the window"),
        table(&["Usage type", "Service", "Quantity", "Cost"], &lines, "no line"),
        esc(&if e.not_counted.is_empty() { "-".to_string() } else { e.not_counted.join(", ") }),
        esc(&e.not_estimated.join(", ")),
        list(&e.caveats.iter().map(|c| (*c).to_string()).collect::<Vec<_>>())
    );
    page(TOP, "Cost", false, &[("page", "cost")], &main)
}

/// `/confirm`: what will happen, its Touch IDs, its CLI twin, the chats a terminate moves, and the form with the
/// nonce (none for HEAD). `app.js` posts it with `fetch`, so the request carries this page's origin.
#[must_use]
pub fn confirm(c: &Confirm) -> String {
    let mut main = format!("<p>{}</p>\n<dl>\n<dt>Touch ID</dt><dd>{}</dd>\n<dt>CLI twin</dt><dd><code>{}</code></dd>\n</dl>\n", esc(&c.what), esc(&c.touch_ids), esc(&c.twin));
    if !c.chats.is_empty() {
        main.push_str(&format!("<p>Chats on it, each moved to a new VM at its next message:</p>\n<ul>\n{}</ul>\n", c.chats.iter().map(|s| format!("<li>{}</li>\n", esc(s))).collect::<String>()));
    }
    if let Some(nonce) = &c.nonce {
        main.push_str(&format!(
            "<form method=\"post\" action=\"{TOP}actions\" data-post=\"1\">\n<input type=\"hidden\" name=\"nonce\" value=\"{}\">\n<input type=\"hidden\" name=\"action\" value=\"{}\">\n<input type=\"hidden\" name=\"target\" value=\"{}\">\n<button type=\"submit\">Run {}</button>\n</form>\n<p id=\"result\" class=\"error\"></p>\n",
            esc(nonce),
            esc(c.action),
            esc(&c.target),
            esc(c.action)
        ));
    }
    page(TOP, &format!("Confirm {} {}", c.action, c.target), false, &[("page", "confirm")], &main)
}

/// `/actions/<nonce>`: the action's state, its CLI twin, its line and exit code (updated over `events`).
#[must_use]
pub fn action(a: &ActionView) -> String {
    let code = a.code.map_or_else(|| "-".into(), |c| c.to_string());
    let main = format!(
        "<dl>\n<dt>Action</dt><dd>{}</dd>\n<dt>Target</dt><dd>{}</dd>\n<dt>Since</dt><dd>{}</dd>\n<dt>State</dt><dd id=\"state\">{}</dd>\n<dt>CLI twin</dt><dd><code>{}</code></dd>\n<dt>Exit code</dt><dd id=\"code\">{}</dd>\n</dl>\n<pre id=\"line\">{}</pre>\n",
        esc(a.action),
        esc(&a.target),
        esc(&a.since),
        esc(a.state),
        esc(&a.twin),
        esc(&code),
        esc(&a.line)
    );
    page(BELOW, &format!("Action {} {}", a.action, a.target), false, &[("page", "action"), ("action", &a.id)], &main)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_escapes_the_five() {
        assert_eq!(esc(r#"<a href="x" title='y'>&amp;</a>"#), "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;amp;&lt;/a&gt;");
        assert_eq!(esc("plain text, é ü 😀"), "plain text, é ü 😀");
        assert_eq!(esc(""), "");
        let page = error(TOP, 500, "<script>alert(1)</script>");
        assert!(!page.contains("<script>alert") && page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{page}");
        assert!(!page.contains("style=") && !page.contains("<style") && page.matches("<script").count() == 1, "the one script is app.js: {page}");
    }
}
