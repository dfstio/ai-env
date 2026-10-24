// ai-env panel (S11 B.5): the one script every page loads (the CSP allows no other).
// It writes only through textContent, never innerHTML. Every URL is relative to the
// page's root prefix (<body data-root>), so the bearer in the path carries itself.
(function () {
  "use strict";
  var body = document.body;
  var root = body.dataset.root || "./";

  // An action's form is posted with fetch: a plain form POST under this page's
  // Referrer-Policy (no-referrer) carries "Origin: null", which the panel refuses.
  Array.prototype.forEach.call(document.querySelectorAll("form[data-post]"), function (form) {
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("result");
      var button = form.querySelector("button");
      if (button) { button.disabled = true; }
      var said = function (text) {
        if (out) { out.textContent = text; }
        if (button) { button.disabled = false; }
      };
      fetch(form.getAttribute("action"), {
        method: "POST",
        body: new URLSearchParams(new FormData(form)),
        credentials: "omit",
        cache: "no-store"
      }).then(function (res) {
        if (res.ok && res.redirected) {
          location.assign(res.url);
          return null;
        }
        return res.text().then(function (text) { said(res.status + ": " + text); });
      }).catch(function (e) { said(String(e)); });
    });
  });

  var page = body.dataset.page;
  if (page !== "audit" && page !== "action") { return; }

  var cell = function (row, text) {
    var td = document.createElement("td");
    td.textContent = text;
    row.appendChild(td);
    return td;
  };

  var appendRow = function (line) {
    var rows = document.getElementById("rows");
    if (!rows) { return; }
    var r;
    try { r = JSON.parse(line); } catch (e) { r = null; }
    var tr = document.createElement("tr");
    if (!r || typeof r !== "object") {
      cell(tr, "-"); cell(tr, "-"); cell(tr, "-"); cell(tr, "-"); cell(tr, "-");
      cell(tr, line).className = "detail";
    } else {
      var d = (r.detail && typeof r.detail === "object") ? r.detail : {};
      var session = r.session_id || d.session || d.session_id || "-";
      var vm = d.id || d.vm || d.from_vm || "-";
      var rest = [];
      Object.keys(d).sort().forEach(function (k) {
        if (k !== "actor" && d[k] !== vm) { rest.push(k + "=" + d[k]); }
      });
      cell(tr, String(r.ts || "-"));
      cell(tr, String(d.actor || "-"));
      cell(tr, String(r.event || "-"));
      cell(tr, String(session).slice(0, 8));
      cell(tr, String(vm));
      cell(tr, rest.join(" ")).className = "detail";
    }
    tr.className = "live";
    rows.appendChild(tr);
  };

  var showAction = function (data) {
    var a;
    try { a = JSON.parse(data); } catch (e) { return; }
    if (!a || a.id !== body.dataset.action) { return; }
    var set = function (id, text) {
      var el = document.getElementById(id);
      if (el) { el.textContent = text; }
    };
    set("state", a.state);
    set("line", a.line || "");
    set("code", a.code === null || a.code === undefined ? "-" : String(a.code));
  };

  var events = new EventSource(root + "events" + location.search);
  events.addEventListener("audit", function (ev) {
    if (page === "audit") { appendRow(ev.data); }
  });
  events.addEventListener("action", function (ev) {
    if (page === "action") { showAction(ev.data); }
  });
}());
