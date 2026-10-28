// poi dashboard. All data from the run (bodies, paths, hosts) can be attacker-controlled:
// it is only ever inserted with textContent / createTextNode, never parsed as HTML.
"use strict";

const SVG = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);
const state = { kind: "all", summary: null, level: null, eventsVersion: -1 };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function svg(tag, attrs = {}, text) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, opts) {
  const r = await fetch(path, { credentials: "same-origin", ...opts });
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}

const WORDS = {
  verified: ["Verified", "Nothing left the container except requests your policy allows."],
  attention: ["Needs attention", "The proof still holds, but something needs your attention."],
  broken: ["Proof broken", "This run can no longer be trusted. The evidence is kept on this computer."],
  pending: ["Connecting…", "Fetching the operator's checkpoints."],
};
const GLYPH = { verified: "M70 102 L92 124 L132 80", attention: "M100 72 L100 108 M100 128 L100 130",
                broken: "M78 78 L122 122 M122 78 L78 122", pending: "M80 100 L120 100" };

function age(s) {
  if (s === null || s === undefined) return "never";
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${(s / 3600).toFixed(1)} h ago`;
}

function drawSeal(level, sum) {
  const seal = $("seal");
  seal.replaceChildren();
  const digest = sum && sum.last_checkpoint ? sum.last_checkpoint.state : "";
  const seq = sum && sum.last_checkpoint ? sum.last_checkpoint.seq : "–";
  const ring = `CHECKPOINT ${seq} · STATE ${digest.slice(0, 32)} · ${digest.slice(32)} · `;
  const defs = svg("defs");
  defs.append(svg("path", { id: "ring", d: "M100,100 m-82,0 a82,82 0 1,1 164,0 a82,82 0 1,1 -164,0" }));
  seal.append(defs,
    svg("circle", { class: "ring", cx: 100, cy: 100, r: 96, "stroke-width": 2 }),
    svg("circle", { class: "ring", cx: 100, cy: 100, r: 70, "stroke-width": 1 }));
  const text = svg("text", { class: "ring-text" });
  text.append(svg("textPath", { href: "#ring", textLength: 512 }, ring));
  seal.append(text, svg("circle", { class: "core", cx: 100, cy: 100, r: 62 }),
    svg("path", { class: "glyph", d: GLYPH[level] || GLYPH.pending }));
}

function renderSummary(sum) {
  state.summary = sum;
  const level = sum.verdict.level;
  const [word, lede] = WORDS[level] || WORDS.pending;
  $("verdict").dataset.level = level;
  $("verdict-word").textContent = word;
  $("verdict-lede").textContent = lede;
  $("reasons").replaceChildren(...sum.verdict.reasons.map((r) => el("li", {}, r)));
  const last = sum.last_checkpoint;
  $("last").textContent = !last ? "No checkpoint received yet."
    : sum.finished ? `Run finished · final signed checkpoint #${last.seq} · operator clock ${last.t}`
    : `Last signed checkpoint #${last.seq} · received ${age(last.age_s)} · operator clock ${last.t}`;
  drawSeal(level, sum);
  if (state.level !== null && state.level !== level) {
    $("seal").classList.remove("stamp"); void $("seal").getBBox(); $("seal").classList.add("stamp");
    notify(level, sum.verdict.reasons[0]);
  }
  state.level = level;
  document.title = (level === "verified" ? "" : "● ") + `poi · ${word}`;
  $("source").textContent = sum.source || "";

  $("t-sent").textContent = sum.sent;
  $("t-blocked").textContent = sum.blocked;
  $("t-dns").textContent = `${sum.dns} DNS lookups`;
  const hits = $("t-hits");
  hits.textContent = `${sum.hits_allowed} sent · ${sum.hits_blocked} blocked`;
  hits.className = "value" + (sum.hits_allowed ? " bad" : sum.hits_blocked ? " warn" : "");
  $("t-hits-note").textContent = sum.hits_allowed ? "your data left the container" : "checked with your private key";
  $("t-cap").textContent = sum.capacity_bits === null ? "unbounded" : `${Math.ceil(sum.capacity_bits)} bits`;
  $("t-cap").className = "value" + (sum.capacity_bits === null ? " warn" : "");

  renderTape(sum.timeline);
  renderOperator(sum.operator, sum.source_error);
  if (sum.version !== state.eventsVersion) {
    state.eventsVersion = sum.version;
    loadEvents();
  }
}

function renderTape(timeline) {
  const tape = $("tape");
  const max = Math.max(1, ...timeline.map((c) => (c.changes || 0) + (c.egress || 0)));
  tape.replaceChildren(...timeline.map((c) => {
    const h = 14 + Math.round(38 * ((c.changes || 0) + (c.egress || 0)) / max);
    const cls = ["link", c.failed ? "failed" : "", c.hit ? "hit" : "", c.config ? "config" : ""].join(" ");
    const label = c.failed ? `Checkpoint ${c.seq}: failed verification`
      : `Checkpoint ${c.seq} · ${c.t} · ${c.changes} file changes · ${c.egress} outbound events`;
    const link = el("button", { class: cls, type: "button", role: "listitem", title: label, "aria-label": label,
      onclick: () => c.failed ? null : openCheckpoint(c.seq) });
    link.style.height = `${h}px`;   // CSSOM, not a style attribute: allowed by the CSP
    return link;
  }));
  tape.scrollLeft = tape.scrollWidth;
}

function renderOperator(op, err) {
  const rows = [];
  const add = (k, v) => rows.push(el("dt", {}, k), el("dd", {}, v));
  if (err) add("Feed", `unreachable: ${err}`);
  if (!op) { add("Status", "not reported"); }
  else {
    add("Container", op.status || "unknown");
    if (op.started_at) add("Started", op.started_at.replace("T", " ").slice(0, 19));
    if (op.cpu_percent !== null && op.cpu_percent !== undefined) add("CPU", `${op.cpu_percent} %`);
    if (op.mem_bytes) add("Memory", `${(op.mem_bytes / 1048576).toFixed(1)} MiB`);
    if (op.observed_at) add("Reported at", op.observed_at.replace("T", " ").slice(0, 19));
  }
  $("operator").replaceChildren(...rows);
}

async function loadEvents() {
  const rows = await api(`/api/events?kind=${state.kind}&limit=200`);
  $("events").replaceChildren(...rows.map((r) => el("li", {},
    el("button", { class: "ev", type: "button", onclick: () => openEvent(r.seq) },
      el("span", { class: "time" }, r.t.slice(11, 19)),
      el("span", { class: `tag ${r.verdict}` }, r.kind === "dns" ? `dns ${r.verdict === "allow" ? "ok" : "no"}` : r.verdict === "allow" ? "sent" : "blocked"),
      el("span", {}, el("span", { class: "target" }, r.target), r.reason ? el("span", { class: "why" }, ` — ${r.reason}`) : null),
      r.hit ? el("span", { class: "badge" + (r.acked ? " acked" : "") }, r.acked ? "your data · seen" : "contains your data") : el("span")))));
  $("events-empty").hidden = rows.length > 0;
}

function kv(pairs) {
  return el("dl", { class: "kv" }, pairs.filter(Boolean).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
}

function bodyBlock(title, b) {
  if (!b) return null;
  const note = b.truncated ? ` (first 64 KB of ${b.size} bytes)` : ` (${b.size} bytes)`;
  return el("div", {}, el("p", { class: "block-title" }, title + note), el("pre", {}, b.text !== undefined ? b.text : b.hex));
}

function openDrawer(title, children) {
  $("drawer-title").textContent = title;
  $("drawer-body").replaceChildren(...children.filter(Boolean));
  $("drawer").setAttribute("aria-hidden", "false");
  $("drawer-close").focus();
}

async function openEvent(seq) {
  const e = await api(`/api/event/${seq}`);
  const sent = e.verdict === "allow";
  const parts = [];
  if (e.hit) {
    parts.push(el("div", { class: "callout" + (sent ? " bad" : "") },
      sent ? "Your data was found in a request that LEFT the container: " : "This blocked request contained your data: ",
      e.hit.join(", ")));
    if (!sent && !e.acked) parts.push(el("button", { class: "primary", type: "button", onclick: () => ack(seq) }, "Mark as seen"));
  }
  parts.push(kv([
    ["Event", `#${e.seq}`], ["Time (operator)", e.t],
    ["Outcome", sent ? "sent" : `blocked — ${e.reason}`],
    e.kind === "dns" ? ["DNS name", e.target] : ["Request", e.target],
    e.policy_recheck && ["Policy re-check here", e.policy_recheck.verdict === "allow" ? "passes the policy" : `fails: ${e.policy_recheck.reason}`],
  ]));
  if (e.headers) parts.push(el("div", {}, el("p", { class: "block-title" }, sent ? "Headers as sent" : "Headers the container tried to send"),
    el("pre", {}, e.headers.map(([k, v]) => `${k}: ${v}`).join("\n") || "(none)")));
  parts.push(bodyBlock(sent ? "Body as sent" : "Body the container tried to send", e.body));
  if (e.response) parts.push(el("div", {}, el("p", { class: "block-title" }, `Response · HTTP ${e.response.status}`)),
    bodyBlock("Response body", e.response.body));
  parts.push(el("div", {}, el("p", { class: "block-title" }, "Proof"), kv([
    ["Checkpoint", `#${e.proof.checkpoint} (${e.proof.checkpoint_t})`], ["Signature", e.proof.signature],
    ["Egress hash", e.proof.egress_accumulator], ["Element", e.proof.element]])));
  openDrawer(e.kind === "dns" ? `DNS lookup #${seq}` : `Request #${seq}`, parts);
}

async function openCheckpoint(seq) {
  const c = await api(`/api/checkpoint/${seq}`);
  const files = (title, list) => list.length ? el("div", {}, el("p", { class: "block-title" }, `${title} (${list.length})`),
    el("ul", { class: "paths" }, list.slice(0, 200).map((p) => el("li", {}, p)))) : null;
  const parts = [kv([
    ["Signed at (operator)", c.t], ["Signature", c.signature], ["Restart", c.restart ? "yes — operator daemon restarted" : "no"],
    ["State hash", c.state], ["Egress hash", `${c.egress} (${c.egress_count} events)`],
    ["Ingress hash", `${c.ingress} (${c.ingress_count})`], ["Previous", c.prev || "— genesis"],
    c.rotate && ["New signing key", c.rotate]]),
    files("Files added", c.files.added), files("Files changed", c.files.changed), files("Files removed", c.files.removed)];
  if (!c.files.added.length && !c.files.changed.length && !c.files.removed.length) parts.push(el("p", {}, "No file changes in this checkpoint."));
  if (c.config_change) parts.push(el("div", {}, el("p", { class: "block-title" }, seq === 0 ? "Container configuration" : "Container configuration changed"),
    el("pre", {}, JSON.stringify(c.config_change.after, null, 2))));
  if (c.events.length) parts.push(el("p", {}, `Outbound events in this checkpoint: ${c.events.map((s) => "#" + s).join(", ")}`));
  openDrawer(`Checkpoint #${seq}`, parts);
}

async function ack(seq) {
  await api(`/api/ack/${seq}`, { method: "POST", headers: { "x-poi": "1" } });
  toast("Marked as seen");
  openEvent(seq);
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, 2200);
}

function notify(level, reason) {
  if (level === "verified" || !("Notification" in window) || Notification.permission !== "granted") return;
  new Notification(`poi: ${WORDS[level][0]}`, { body: reason || "" });
}

function connect() {
  api("/api/summary").then(renderSummary).catch((e) => { $("last").textContent = `Could not load the summary: ${e.message}`; });
  const es = new EventSource("/api/stream");
  es.addEventListener("update", (m) => renderSummary(JSON.parse(m.data)));
  es.onerror = () => { $("last").textContent = "Lost connection to the local dashboard — retrying…"; };
}

document.addEventListener("DOMContentLoaded", () => {
  history.replaceState(null, "", "/");
  document.querySelectorAll(".filters button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".filters button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    state.kind = b.dataset.kind; loadEvents();
  }));
  $("drawer-close").addEventListener("click", () => $("drawer").setAttribute("aria-hidden", "true"));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("drawer").setAttribute("aria-hidden", "true"); });
  const alerts = $("alerts");
  if (!("Notification" in window)) alerts.hidden = true;
  else if (Notification.permission === "granted") alerts.textContent = "Alerts on";
  alerts.addEventListener("click", async () => {
    if (await Notification.requestPermission() === "granted") alerts.textContent = "Alerts on";
  });
  drawSeal("pending", null);
  connect();
});
