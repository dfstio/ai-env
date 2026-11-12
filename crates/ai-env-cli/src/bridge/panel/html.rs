//! The pages, written by hand (B §B5.5, §B5.7): every value through [`esc`];
//! no inline script, no inline style, no `style` attribute (the CSP forbids
//! them); every URL relative, written with the page's root prefix (`./` on the
//! top pages, `../` one level below the bearer) and put on
//! `<body data-root>`, where `assets/app.js` reads it.
use super::actions::{Action, ActionView, NO_TARGET};
use super::model::{AccessPanel, AuditPage, Confirm, CostPage, SessionPage, Sessions, SettingsPage};
use super::REFRESH_S;
use crate::bridge::audit::read::Read;
use crate::bridge::registry::{SessionRow, VmEntry};
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

/// A chat's mint word (R-151): `minted`, else so that a chat with no token says so (`no token (no_agent)`).
fn mint_word(r: &SessionRow) -> String {
    match r.relay.as_deref() {
        Some("minted") => "minted".to_string(),
        Some(word) => format!("no token ({word})"),
        None => "-".to_string(),
    }
}

/// A chat's grants, each `[x] <grant> until <day> Remove` or `[ ] <grant> Allow`, linked to its confirm page (R-151):
/// every offered grant, then any other it holds, which must stay removable. A held grant whose id a form refuses (a `.`,
/// off the offer) names the CLI line instead. A row now on this Mac is offered nothing, and what it holds stays removable,
/// since a later remote `--resume` takes its id. R-156: a restricted grant says so, `<grant> (restricted)`, and a chat whose
/// folder is in no `sole_vm` workspace gets `[ ] <grant> (restricted: its workspace is not sole_vm)`, with no link. Each line
/// already HTML.
fn access_lines(root: &str, r: &SessionRow, a: &AccessPanel) -> Vec<String> {
    let sid = &r.session_id;
    let remote = r.mode == "remote";
    let Some(chat) = r.access() else {
        return if remote && !a.offer.is_empty() { vec![esc("no access id: it last ran before this ai-env, so reopen the chat")] } else { Vec::new() };
    };
    let offer = if remote { a.offer.as_slice() } else { &[] };
    let (held, until) = a.held(chat).map_or((&[][..], ""), |(grants, until)| (grants, until.get(..10).unwrap_or(until)));
    let extra = held.iter().filter(|g| !offer.contains(g));
    offer
        .iter()
        .chain(extra)
        .map(|grant| {
            let target = format!("{sid}_{grant}");
            let restricted = a.restricted.contains(grant);
            let mark = if restricted { " (restricted)" } else { "" };
            if !held.contains(grant) {
                if restricted && !a.alone.contains(sid) {
                    return format!("[ ] {} (restricted: its workspace is not sole_vm)", esc(grant));
                }
                return format!("[ ] {}{mark} {}", esc(grant), link(&confirm_href(root, Action::RelayAllow, &target), "Allow"));
            }
            let how = if grant.contains('.') { format!("<code>{}</code>", esc(&Action::RelayRemove.twin(&target))) } else { link(&confirm_href(root, Action::RelayRemove, &target), "Remove") };
            format!("[x] {}{mark} until {} {how}", esc(grant), esc(until))
        })
        .collect()
}

/// What the Sessions and session pages say of the access list and the agent (R-151, R-152): `as of v<n>, <time>`, the
/// relay remaining the gate; the agent's state, since a chat spawned with none holds no token.
fn access_note(a: &AccessPanel) -> String {
    let agent = a.agent.map_or_else(|| "not running (ai-env relay agent): a chat spawned now holds no session token".to_string(), |(pid, until)| format!("running (pid {pid}, until {})", crate::wire::time::rfc3339_utc(until)));
    let list = a.cache.as_ref().map_or_else(|| "not read yet (ai-env relay status)".to_string(), |c| format!("as of v{}, {}", c.version, c.at));
    let problem = a.problem.as_ref().map_or_else(String::new, |p| format!(" {p}."));
    format!("<p class=\"note\">Relay agent: {}. Access list: {}; the relay remains the gate.{}</p>\n", esc(&agent), esc(&list), esc(&problem))
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
                {
                    let lines: Vec<String> = (r.mode == "remote").then(|| esc(&mint_word(r))).into_iter().chain(access_lines(TOP, r, &m.access)).collect();
                    if lines.is_empty() {
                        td("-")
                    } else {
                        format!("<td class=\"relay\">{}</td>", lines.join("<br>"))
                    }
                },
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
    let main = table(&["Session", "Title", "Status", "Mode", "Last seen", "Slug", "VM", "Moves", "Cost", "Relay", ""], &rows, if searching { "no session matches" } else { "no sessions yet" });
    page(TOP, "Sessions", true, &[("page", "sessions")], &format!("{form}{note}{main}{}<p class=\"note\">Every action asks for a confirmation first and names its CLI twin.</p>\n", access_note(&m.access)))
}

/// One generation's line.
fn generation(g: &VmEntry) -> Vec<String> {
    vec![td(&g.gen.to_string()), td(&g.pid.to_string()), td(&g.vm), td(&g.from), td(g.to.as_deref().unwrap_or("-")), td(if g.why.is_empty() { "-" } else { &g.why }), td(g.end.as_deref().unwrap_or("-"))]
}

/// `/session/<sid>`: `session show`'s view. S12 (T, §T3 U7): with a name (`title::of_row`), the heading and
/// `<title>` are `<name> · <sid's first 8>`, else `Session <sid>`; the list gains `session` and `title` (the name
/// and its source, or `-`) first. R-151: a remote chat's mint word, its grants and the agent's state follow them; a row
/// back on this Mac shows what it still holds, with its Remove.
#[must_use]
pub fn session(p: &SessionPage) -> String {
    let v = &p.view;
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
    let lines = access_lines(BELOW, r, &p.access);
    if r.mode == "remote" || !lines.is_empty() {
        main.push_str("<h2>Relay</h2>\n");
        if r.mode == "remote" {
            main.push_str(&format!("<p>Session token: {}</p>\n", esc(&mint_word(r))));
        } else {
            main.push_str("<p>This chat runs on this Mac now; a later remote --resume still reaches what it holds.</p>\n");
        }
        if !lines.is_empty() {
            main.push_str(&format!("<ul>\n{}</ul>\n", lines.iter().map(|l| format!("<li>{l}</li>\n")).collect::<String>()));
        }
        main.push_str(&access_note(&p.access));
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
        let about = if c.action == Action::VmTerminate.word() { "Chats on it, each moved to a new VM at its next message:" } else { "Other chats on this chat's VM, whose processes could use its access:" };
        main.push_str(&format!("<p>{about}</p>\n<ul>\n{}</ul>\n", c.chats.iter().map(|s| format!("<li>{}</li>\n", esc(s))).collect::<String>()));
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

    /// R-151, R-152: a chat's grants as the cache has them. Every offered grant has its line, then any other it holds, which
    /// must stay removable, by its CLI line when a form would refuse its id. An entry lapsed by the page's clock holds
    /// nothing. The mint word says when there is no token. A row with no id, or a text that is no uuid, says so where
    /// anything is offered. A row now on this Mac is offered nothing and can still remove what it holds. R-156: a restricted
    /// grant is marked, and offered with no link to a chat outside a `sole_vm` workspace.
    #[test]
    fn a_chats_grants_and_its_token_are_shown() {
        use crate::bridge::relay::params::AccessCache;
        use ai_env_worker::policy::AccessEntry;
        const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        const CHAT: &str = "0199a1b2-0000-7000-8000-0000000012a1";
        let now = 1_792_713_600; // 2026-10-23T00:00:00Z
        let entry = |grants: &[&str], not_after: &str| AccessEntry { chat: CHAT.into(), grants: grants.iter().map(|g| (*g).to_string()).collect(), not_after: not_after.into() };
        let with = |entries: Vec<AccessEntry>| AccessPanel { offer: vec!["g-a".into(), "g-b".into()], cache: Some(AccessCache { version: 3, at: "2026-10-22T10:00:00Z".into(), entries }), now, ..AccessPanel::default() };
        let row = |access: Option<&str>, relay: Option<&str>| SessionRow { session_id: SID.into(), mode: "remote".into(), access_id: access.map(str::to_string), relay: relay.map(str::to_string), ..SessionRow::default() };
        let remove = |grant: &str| format!("[x] {grant} until 2026-11-01 <a href=\"{TOP}confirm?action=relay-remove&amp;target={SID}_{grant}\">Remove</a>");
        let allow = |grant: &str| format!("[ ] {grant} <a href=\"{TOP}confirm?action=relay-allow&amp;target={SID}_{grant}\">Allow</a>");
        let held = with(vec![entry(&["g-b", "g-old", "g.dot"], "2026-11-01T23:59:59Z")]);
        let chat = row(Some(CHAT), Some("minted"));
        assert_eq!(
            access_lines(TOP, &chat, &held),
            [allow("g-a"), remove("g-b"), remove("g-old"), format!("[x] g.dot until 2026-11-01 <code>ai-env relay access {SID} --remove g.dot</code>")],
            "the offer's, then what else it holds"
        );
        // Lapsed, another chat's, no list yet: nothing held.
        let lapsed = with(vec![entry(&["g-b"], "2026-10-22T23:59:59Z")]);
        assert_eq!(access_lines(TOP, &chat, &lapsed), [allow("g-a"), allow("g-b")]);
        let at_its_last_second = with(vec![entry(&["g-b"], "2026-10-23T00:00:00Z")]);
        assert_eq!(access_lines(TOP, &chat, &at_its_last_second)[1], format!("[x] g-b until 2026-10-23 <a href=\"{TOP}confirm?action=relay-remove&amp;target={SID}_g-b\">Remove</a>"));
        let theirs = with(vec![AccessEntry { chat: "0199a1b2-0000-7000-8000-0000000012a2".into(), ..entry(&["g-b"], "2026-11-01T23:59:59Z") }]);
        assert_eq!(access_lines(TOP, &chat, &theirs), [allow("g-a"), allow("g-b")]);
        // No id: said only where something is offered.
        let bare = row(None, None);
        assert_eq!(access_lines(TOP, &bare, &with(Vec::new())), ["no access id: it last ran before this ai-env, so reopen the chat"]);
        assert!(access_lines(TOP, &bare, &AccessPanel::default()).is_empty());
        let hand_edited = row(Some("not a uuid"), Some("minted"));
        assert_eq!(access_lines(TOP, &hand_edited, &with(vec![AccessEntry { chat: "not a uuid".into(), ..entry(&["g-b"], "2026-11-01T23:59:59Z") }])), ["no access id: it last ran before this ai-env, so reopen the chat"], "no uuid is no id");
        // On this Mac now: what it holds, each with its Remove, and nothing to allow; nothing at all when it holds nothing.
        let local = |access| SessionRow { mode: "local-child".into(), ..row(access, None) };
        assert_eq!(access_lines(TOP, &local(Some(CHAT)), &with(vec![entry(&["g-b", "g-old"], "2026-11-01T23:59:59Z")])), [remove("g-b"), remove("g-old")]);
        assert!(access_lines(TOP, &local(Some(CHAT)), &with(Vec::new())).is_empty());
        assert!(access_lines(TOP, &local(None), &with(Vec::new())).is_empty());
        assert_eq!((mint_word(&chat), mint_word(&row(Some(CHAT), Some("no_agent"))), mint_word(&bare)), ("minted".to_string(), "no token (no_agent)".to_string(), "-".to_string()));
        // R-156: a restricted grant says so; outside a sole_vm workspace it has no link, and what it holds stays removable.
        let restricted = |alone: bool, entries: Vec<AccessEntry>| AccessPanel { restricted: vec!["g-b".into()], alone: if alone { [SID.to_string()].into() } else { std::collections::BTreeSet::new() }, ..with(entries) };
        assert_eq!(access_lines(TOP, &chat, &restricted(false, Vec::new())), [allow("g-a"), "[ ] g-b (restricted: its workspace is not sole_vm)".to_string()]);
        assert_eq!(access_lines(TOP, &chat, &restricted(true, Vec::new()))[1], format!("[ ] g-b (restricted) <a href=\"{TOP}confirm?action=relay-allow&amp;target={SID}_g-b\">Allow</a>"));
        for alone in [false, true] {
            assert_eq!(access_lines(TOP, &chat, &restricted(alone, vec![entry(&["g-b"], "2026-11-01T23:59:59Z")]))[1], format!("[x] g-b (restricted) until 2026-11-01 <a href=\"{TOP}confirm?action=relay-remove&amp;target={SID}_g-b\">Remove</a>"), "alone: {alone}");
        }
        // The note: the agent's state, `as of v<n>, <time>`, a [relay] that does not validate.
        let note = access_note(&AccessPanel { agent: Some((42, now + 3600)), problem: Some("[relay].offer[0] = \"<G>\" is not an id".into()), ..held });
        assert_eq!(note, "<p class=\"note\">Relay agent: running (pid 42, until 2026-10-23T01:00:00Z). Access list: as of v3, 2026-10-22T10:00:00Z; the relay remains the gate. [relay].offer[0] = &quot;&lt;G&gt;&quot; is not an id.</p>\n");
    }
}
