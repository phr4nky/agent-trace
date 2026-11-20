// agent-trace causal graph viewer. Self-contained: no network, no libraries.
// Trace content is untrusted: it is only ever inserted with textContent / setAttribute.
(function () {
  "use strict";
  const SVG = "http://www.w3.org/2000/svg";
  const report = JSON.parse(document.getElementById("trace-data").textContent);
  const events = report.events || [];
  const findings = report.findings || [];
  const byId = new Map(events.map((e) => [e.event_id, e]));

  // ---- model ---------------------------------------------------------------------------
  const KIND = {
    user_prompt_received: "user",
    model_request: "model",
    model_response: "model",
    agent_decision: "agent",
    agent_started: "agent",
    agent_completed: "agent",
    agent_delegated: "message",
    agent_message_sent: "message",
    agent_message_received: "message",
    tool_call_requested: "request",
    tool_policy_decision: "policy",
    tool_call_executed: "agent",
    tool_call_completed: "agent",
    tool_call_failed: "blocked",
    tool_result_received: "result",
    external_content_observed: "content",
  };
  function kindClass(e) {
    if (e.kind === "tool_policy_decision" &&
        (e.tool_state === "blocked" || (e.payload && e.payload.decision === "deny"))) {
      return "blocked";
    }
    return KIND[e.kind] || "agent";
  }
  function meta(e, key) {
    const v = e.metadata && e.metadata[key];
    return typeof v === "string" ? v : null;
  }
  // Lanes: one per agent, and one per MCP server for what the server returned.
  function laneOf(e) {
    const server = meta(e, "mcp_server");
    if (server && (e.kind === "tool_call_executed" || e.kind === "tool_result_received" ||
                   e.kind === "external_content_observed")) {
      return "server · " + server;
    }
    return "agent · " + (e.agent_id || "main");
  }

  // Links: [from (earlier), to (later), type].
  const links = [];
  for (const e of events) {
    if (e.caused_by_event_id && byId.has(e.caused_by_event_id)) {
      links.push({ from: e.caused_by_event_id, to: e.event_id, type: "cause" });
    }
    for (const c of e.context_event_ids || []) {
      if (byId.has(c)) links.push({ from: c, to: e.event_id, type: "context" });
    }
    if (e.parent_event_id && byId.has(e.parent_event_id) &&
        e.parent_event_id !== e.caused_by_event_id) {
      links.push({ from: e.parent_event_id, to: e.event_id, type: "parent" });
    }
  }
  const incoming = new Map();
  const outgoing = new Map();
  for (const l of links) {
    if (!incoming.has(l.to)) incoming.set(l.to, []);
    if (!outgoing.has(l.from)) outgoing.set(l.from, []);
    incoming.get(l.to).push(l);
    outgoing.get(l.from).push(l);
  }

  // Provenance follows the cause (or the parent if no cause was recorded) plus context, like
  // the analyzer does, independent of which edge types are shown.
  function provenanceOf(e) {
    const out = [];
    const c = e.caused_by_event_id || e.parent_event_id;
    if (c && byId.has(c)) out.push(c);
    for (const x of e.context_event_ids || []) if (byId.has(x) && !out.includes(x)) out.push(x);
    return out;
  }
  const provUp = new Map(events.map((e) => [e.event_id, provenanceOf(e)]));
  const provDown = new Map();
  for (const [id, ups] of provUp) {
    for (const u of ups) {
      if (!provDown.has(u)) provDown.set(u, []);
      provDown.get(u).push(id);
    }
  }
  function closure(id, map) {
    const seen = new Set([id]);
    const stack = [id];
    while (stack.length) {
      for (const next of map.get(stack.pop()) || []) {
        if (!seen.has(next)) { seen.add(next); stack.push(next); }
      }
    }
    seen.delete(id);
    return [...seen].map((x) => byId.get(x)).sort((a, b) => a.sequence - b.sequence);
  }

  const SEVERITY = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const bySeverity = (a, b) =>
    (SEVERITY[a.severity] ?? 9) - (SEVERITY[b.severity] ?? 9) || a.rule_id.localeCompare(b.rule_id);
  const findingsOf = new Map();
  for (const f of findings) {
    for (const id of f.evidence_event_ids || []) {
      if (!findingsOf.has(id)) findingsOf.set(id, []);
      if (!findingsOf.get(id).includes(f)) findingsOf.get(id).push(f);
    }
  }
  for (const list of findingsOf.values()) list.sort(bySeverity);

  // Timing. Timestamps are RFC 3339, possibly with nanoseconds; Date.parse wants milliseconds.
  function millis(ts) {
    return typeof ts === "string" ? Date.parse(ts.replace(/(\.\d{3})\d+/, "$1")) : NaN;
  }
  const startMs = (() => {
    const all = events.map((e) => millis(e.timestamp)).filter(Number.isFinite);
    const created = millis(report.trace && report.trace.created_at);
    if (Number.isFinite(created)) all.push(created);
    return all.length ? Math.min(...all) : NaN;
  })();
  function delta(d) {
    if (!Number.isFinite(d)) return null;
    const a = Math.abs(d);
    const s = a < 1000 ? Math.round(a) + " ms"
      : a < 60000 ? (a / 1000).toFixed(2) + " s"
      : Math.floor(a / 60000) + " min " + Math.round((a % 60000) / 1000) + " s";
    return (d < 0 ? "−" : "+") + s;
  }
  function timing(e) {
    const i = events.indexOf(e);
    const t = millis(e.timestamp);
    const rows = [];
    const sinceStart = delta(t - startMs);
    if (sinceStart) rows.push(["since start", sinceStart]);
    if (i > 0) {
      const prev = events[i - 1];
      const d = delta(t - millis(prev.timestamp));
      if (d) rows.push(["after #" + prev.sequence, d]);
    }
    const cause = e.caused_by_event_id && byId.get(e.caused_by_event_id);
    if (cause) {
      const d = delta(t - millis(cause.timestamp));
      if (d) rows.push(["after cause #" + cause.sequence, d]);
    }
    return rows;
  }

  // A short, flat view of the payload: top-level values and one level of nested values.
  function short(v, n) {
    let s = typeof v === "string" ? v : JSON.stringify(v);
    if (s === undefined) s = String(v);
    s = s.replace(/\s+/g, " ").trim();
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }
  function payloadSummary(payload, max) {
    const rows = [];
    const add = (k, v) => { if (rows.length < max) rows.push([k, short(v, 160)]); };
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      for (const [k, v] of Object.entries(payload)) {
        if (v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length) {
          for (const [k2, v2] of Object.entries(v)) add(k + "." + k2, v2);
        } else {
          add(k, v);
        }
      }
    } else if (payload != null) {
      add("value", payload);
    }
    return rows;
  }
  function payloadFacts(e) {
    const json = JSON.stringify(e.payload) || "";
    const bytes = new TextEncoder().encode(json).length;
    const placeholders = (json.match(/\[REDACTED/g) || []).length;
    const counted = e.metadata && typeof e.metadata.redactions === "number" ? e.metadata.redactions : 0;
    return { bytes, redactions: Math.max(placeholders, counted) };
  }
  function bytesText(n) {
    return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KiB" : (n / 1048576).toFixed(1) + " MiB";
  }

  // ---- layout --------------------------------------------------------------------------
  const DX = 104, DY = 110, LEFT = 40, TOP = 70, R = 9;
  const lanes = [];
  for (const e of events) {
    const lane = laneOf(e);
    if (!lanes.includes(lane)) lanes.push(lane);
  }
  const pos = new Map();
  events.forEach((e, i) => {
    pos.set(e.event_id, { x: LEFT + i * DX, y: TOP + lanes.indexOf(laneOf(e)) * DY });
  });
  const width = LEFT + Math.max(events.length, 1) * DX + 40;
  const height = TOP + Math.max(lanes.length, 1) * DY;

  // ---- drawing -------------------------------------------------------------------------
  const svg = document.getElementById("svg");
  function el(name, attrs, parent) {
    const n = document.createElementNS(SVG, name);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
    if (parent) parent.appendChild(n);
    return n;
  }
  const defs = el("defs", {}, svg);
  // Arrowheads are styled by class: the page's CSP allows no inline style attributes.
  for (const [id, cls] of [["arrow", "arrowhead"], ["arrow-hl", "arrowhead hl"]]) {
    const m = el("marker", { id, viewBox: "0 0 10 10", refX: 10, refY: 5,
      markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" }, defs);
    el("path", { d: "M0,0 L10,5 L0,10 z", class: cls }, m);
  }
  const viewport = el("g", { id: "viewport" }, svg);
  const laneLayer = el("g", {}, viewport);
  const edgeLayer = el("g", {}, viewport);
  const nodeLayer = el("g", {}, viewport);
  // Lane names stay at the left edge while panning (outside the zoomed group).
  const laneNames = el("g", {}, svg);

  const laneLabels = lanes.map((lane, i) => {
    el("rect", { class: "lane-bg" + (i % 2 ? " alt" : ""), x: -10000, y: TOP + i * DY - DY / 2,
      width: width + 20000, height: DY }, laneLayer);
    const label = el("text", { class: "lane-label", x: 8 }, laneNames);
    label.textContent = lane.length > 40 ? lane.slice(0, 39) + "…" : lane;
    return label;
  });

  function edgePath(a, b) {
    if (a.y === b.y) {
      const h = Math.min(70, 18 + Math.abs(b.x - a.x) * 0.18);
      return `M${a.x},${a.y - R} C${a.x},${a.y - R - h} ${b.x},${b.y - R - h} ${b.x},${b.y - R}`;
    }
    const mx = (a.x + b.x) / 2;
    const dy = b.y > a.y ? R : -R;
    return `M${a.x},${a.y + dy} C${mx},${a.y + dy} ${mx},${b.y - dy} ${b.x},${b.y - dy}`;
  }
  const edgeEls = links.map((l) => {
    const p = el("path", { class: "edge " + l.type, d: edgePath(pos.get(l.from), pos.get(l.to)) },
      edgeLayer);
    if (l.type !== "parent") p.setAttribute("marker-end", "url(#arrow)");
    l.el = p;
    return p;
  });

  const nodeEls = new Map();
  for (const e of events) {
    const p = pos.get(e.event_id);
    const lower = e.trust_level === "lower_trust";
    const g = el("g", { class: "node" + (lower ? " lower" : ""), transform: `translate(${p.x},${p.y})`,
      tabindex: 0 }, nodeLayer);
    el("circle", { r: R, class: "k-" + kindClass(e) }, g);
    const flagged = findingsOf.get(e.event_id);
    if (flagged) {
      // A dot in the colour of the most severe finding this event is evidence for.
      el("circle", { r: 3.5, cx: R * 0.8, cy: -R * 0.8, class: "flag " + flagged[0].severity }, g);
    }
    // Labels below the node; same-lane arcs run above it.
    const seq = el("text", { class: "seq", y: R + 12, "text-anchor": "middle" }, g);
    seq.textContent = "#" + e.sequence;
    const name = String(e.name || e.kind);
    const label = el("text", { y: R + 25, "text-anchor": "middle" }, g);
    label.textContent = name.length > 15 ? name.slice(0, 14) + "…" : name;
    const tip = el("title", {}, g);
    tip.textContent = `#${e.sequence} ${e.kind} · ${name}` + (lower ? " · lower trust" : "") +
      (flagged ? ` · ${flagged.length} finding${flagged.length > 1 ? "s" : ""}` : "");
    g.addEventListener("click", (ev) => { ev.stopPropagation(); selectEvent(e.event_id); });
    g.addEventListener("keydown", (ev) => { if (ev.key === "Enter") selectEvent(e.event_id); });
    nodeEls.set(e.event_id, g);
  }

  // ---- pan & zoom ----------------------------------------------------------------------
  let view = { x: 0, y: 0, k: 1 };
  function apply() {
    viewport.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`);
    svg.classList.toggle("far", view.k < 0.55);
    laneLabels.forEach((label, i) => {
      // Top of the lane band, in screen coordinates.
      label.setAttribute("y", String(view.y + (TOP + i * DY - DY / 2) * view.k + 14));
    });
    placeCard();
  }
  // Pans (without zooming) so that an event is comfortably inside the view.
  function ensureVisible(id) {
    const p = pos.get(id);
    const box = svg.getBoundingClientRect();
    const sx = view.x + p.x * view.k, sy = view.y + p.y * view.k;
    const mx = Math.min(160, box.width / 4), my = Math.min(80, box.height / 4);
    if (sx < mx || sx > box.width - mx) view.x = box.width / 3 - p.x * view.k;
    if (sy < my || sy > box.height - my) view.y = box.height / 2 - p.y * view.k;
    apply();
  }
  function fit(ids) {
    const box = svg.getBoundingClientRect();
    let pts = (ids && ids.length ? ids : events.map((e) => e.event_id))
      .map((id) => pos.get(id)).filter(Boolean);
    if (!pts.length) pts = [{ x: 0, y: 0 }];
    const minX = Math.min(...pts.map((p) => p.x)) - 70, maxX = Math.max(...pts.map((p) => p.x)) + 70;
    const minY = Math.min(...pts.map((p) => p.y)) - DY / 2, maxY = Math.max(...pts.map((p) => p.y)) + DY / 2;
    const k = Math.max(0.15, Math.min(1.6, box.width / (maxX - minX), box.height / (maxY - minY)));
    view = { k, x: (box.width - (maxX - minX) * k) / 2 - minX * k,
      y: (box.height - (maxY - minY) * k) / 2 - minY * k };
    if (!ids || !ids.length) view.x = Math.min(view.x, 10);
    apply();
  }
  svg.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const box = svg.getBoundingClientRect();
    const px = ev.clientX - box.left, py = ev.clientY - box.top;
    const k = Math.max(0.1, Math.min(4, view.k * Math.exp(-ev.deltaY * 0.0015)));
    view.x = px - (px - view.x) * (k / view.k);
    view.y = py - (py - view.y) * (k / view.k);
    view.k = k;
    apply();
  }, { passive: false });
  // The pointer is captured only once it really drags: capturing on pointerdown would send
  // the click to the svg instead of the node under it, so clicking a node would do nothing.
  let drag = null;
  let suppressClick = false;
  svg.addEventListener("pointerdown", (ev) => {
    if (ev.button !== 0) return;
    suppressClick = false;
    drag = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y, moved: false, id: ev.pointerId };
  });
  svg.addEventListener("pointermove", (ev) => {
    if (!drag || ev.pointerId !== drag.id) return;
    const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (!drag.moved) {
      if (Math.abs(dx) + Math.abs(dy) <= 3) return;
      drag.moved = true;
      svg.setPointerCapture(drag.id);
      svg.classList.add("dragging");
    }
    view.x = drag.vx + dx;
    view.y = drag.vy + dy;
    apply();
  });
  function endDrag() {
    svg.classList.remove("dragging");
    suppressClick = !!(drag && drag.moved);
    drag = null;
  }
  svg.addEventListener("pointerup", endDrag);
  svg.addEventListener("pointercancel", endDrag);
  // Clicks on nodes stop propagation; a click that reaches the svg is on the background,
  // unless it ends a drag.
  svg.addEventListener("click", () => {
    if (suppressClick) { suppressClick = false; return; }
    clearSelection();
  });

  // ---- highlighting --------------------------------------------------------------------
  function reach(start, map, pick) {
    const seen = new Set([start]);
    const stack = [start];
    while (stack.length) {
      for (const l of map.get(stack.pop()) || []) {
        if (!visibleType(l.type)) continue;
        const next = pick(l);
        if (!seen.has(next)) { seen.add(next); stack.push(next); }
      }
    }
    return seen;
  }
  function highlight(ids, edgeTest) {
    for (const [id, g] of nodeEls) g.classList.toggle("dim", !ids.has(id));
    for (const l of links) {
      const on = edgeTest(l);
      l.el.classList.toggle("dim", !on);
      l.el.classList.toggle("hl", on);
      l.el.setAttribute("marker-end", l.type === "parent" ? "" : on ? "url(#arrow-hl)" : "url(#arrow)");
    }
  }
  function clearHighlight() {
    for (const g of nodeEls.values()) g.classList.remove("dim", "selected");
    for (const l of links) {
      l.el.classList.remove("dim", "hl");
      if (l.type !== "parent") l.el.setAttribute("marker-end", "url(#arrow)");
    }
  }

  // ---- details panel -------------------------------------------------------------------
  const details = document.getElementById("details");
  function text(tag, value, cls) {
    const n = document.createElement(tag);
    n.textContent = value == null ? "" : String(value);
    if (cls) n.className = cls;
    return n;
  }
  function button(label, cls, onClick) {
    const b = text("button", label, cls);
    b.type = "button";
    b.addEventListener("click", (ev) => { ev.stopPropagation(); onClick(b); });
    return b;
  }
  function linkButton(id) {
    const e = byId.get(id);
    const b = button(e ? `#${e.sequence} ${e.kind}` : id, "linkbtn", () => selectEvent(id));
    if (e && e.trust_level === "lower_trust") {
      b.classList.add("lower");
      b.title = "lower-trust content";
    }
    return b;
  }
  function linkList(ids) {
    const box = document.createElement("div");
    box.className = "links";
    for (const id of ids) box.append(linkButton(id));
    return box;
  }
  function defList(rows) {
    const dl = document.createElement("dl");
    for (const [k, v] of rows) {
      if (v === "" || v == null) continue;
      dl.append(text("dt", k), text("dd", v));
    }
    return dl;
  }
  function findingButton(f) {
    const b = button("", "findingbtn", () => { clearHighlight(); selectFinding(f); });
    b.append(text("span", f.severity, "sev " + f.severity), text("strong", f.rule_id),
      text("span", f.title, "ftitle"));
    return b;
  }
  const canCopy = !!(navigator.clipboard && navigator.clipboard.writeText);
  function copyButton(label, value) {
    return button(label, "linkbtn", (b) => {
      navigator.clipboard.writeText(value).then(() => {
        b.textContent = "copied";
        setTimeout(() => { b.textContent = label; }, 1200);
      }, () => { b.textContent = "copy failed"; });
    });
  }
  function showDetails(e) {
    details.replaceChildren();
    const facts = payloadFacts(e);
    details.append(defList([
      ["sequence", "#" + e.sequence], ["kind", e.kind], ["name", e.name],
      ["agent", e.agent_id || "main"], ["lane", laneOf(e)], ["origin", e.origin],
      ["trust", e.trust_level], ["state", e.tool_state || ""],
      ["mode", e.execution_mode], ["schema", e.schema_version],
      ["time", e.timestamp], ...timing(e),
      ["payload", bytesText(facts.bytes) + (facts.redactions ? ` · ${facts.redactions} redacted` : "")],
      ["event id", e.event_id],
    ]));

    const fs = findingsOf.get(e.event_id) || [];
    if (fs.length) {
      details.append(text("h2", `evidence for ${fs.length} finding${fs.length > 1 ? "s" : ""}`));
      const box = document.createElement("div");
      box.className = "stack";
      for (const f of fs) box.append(findingButton(f));
      details.append(box);
    }

    for (const [label, ids] of [
      ["caused by", e.caused_by_event_id ? [e.caused_by_event_id] : []],
      ["context", e.context_event_ids || []],
      ["parent", e.parent_event_id ? [e.parent_event_id] : []],
      ["leads to", (outgoing.get(e.event_id) || []).filter((l) => l.type !== "parent").map((l) => l.to)],
    ]) {
      if (!ids.length) continue;
      details.append(text("h2", label), linkList(ids));
    }

    const up = closure(e.event_id, provUp);
    const down = closure(e.event_id, provDown);
    const tainted = up.filter((x) => x.trust_level === "lower_trust");
    if (up.length || down.length) {
      details.append(text("h2", "provenance"));
      details.append(defList([
        ["upstream", up.length + " event" + (up.length === 1 ? "" : "s")],
        ["downstream", down.length + " event" + (down.length === 1 ? "" : "s")],
      ]));
      if (tainted.length) {
        details.append(text("p", `Influenced by ${tainted.length} lower-trust event${tainted.length > 1 ? "s" : ""}:`, "taint"),
          linkList(tainted.map((x) => x.event_id)));
      }
      if (up.length) {
        details.append(text("h2", "upstream chain"), linkList(up.map((x) => x.event_id)));
      }
    }

    const head = text("h2", "payload (redacted)");
    if (canCopy) head.append(copyButton("copy", JSON.stringify(e.payload, null, 2)));
    details.append(head, text("pre", JSON.stringify(e.payload, null, 2)));
    if (e.metadata && Object.keys(e.metadata).length) {
      details.append(text("h2", "metadata"), text("pre", JSON.stringify(e.metadata, null, 2)));
    }
  }

  // ---- info card next to the selected node ---------------------------------------------
  const graphBox = document.getElementById("graph");
  const card = document.getElementById("card");
  let cardFor = null;
  function showCard(e) {
    cardFor = e.event_id;
    card.replaceChildren();
    const i = events.indexOf(e);

    const head = document.createElement("div");
    head.className = "card-head";
    head.append(text("span", "", "dot k-" + kindClass(e)), text("span", `#${e.sequence} ${e.kind}`, "card-kind"));
    const nav = document.createElement("span");
    nav.className = "card-nav";
    const prev = button("‹", "iconbtn", () => selectEvent(events[i - 1].event_id, true));
    prev.title = "previous event (←)";
    prev.disabled = i <= 0;
    const next = button("›", "iconbtn", () => selectEvent(events[i + 1].event_id, true));
    next.title = "next event (→)";
    next.disabled = i >= events.length - 1;
    const close = button("×", "iconbtn", () => clearSelection());
    close.title = "close (Esc)";
    nav.append(prev, next, close);
    head.append(nav);
    card.append(head, text("div", e.name || e.kind, "card-name"));

    const chips = document.createElement("div");
    chips.className = "chips";
    const chip = (label, cls) => chips.append(text("span", label, "chip" + (cls ? " " + cls : "")));
    chip(e.agent_id || "main");
    chip(e.origin);
    chip(String(e.trust_level).replace(/_/g, " "), e.trust_level === "lower_trust" ? "bad" : e.trust_level === "trusted" ? "good" : "");
    if (e.tool_state) chip(e.tool_state, /blocked|failed|denied/.test(e.tool_state) ? "bad" : "");
    const facts = payloadFacts(e);
    if (facts.redactions) chip(`${facts.redactions} redacted`, "warn");
    card.append(chips);

    const t = timing(e);
    if (t.length) card.append(text("div", t.map(([k, v]) => `${v} ${k}`).join(" · "), "card-time"));

    const rows = payloadSummary(e.payload, 6);
    if (rows.length) {
      const dl = defList(rows);
      dl.className = "card-payload";
      card.append(dl);
    }

    const fs = findingsOf.get(e.event_id) || [];
    if (fs.length) {
      const box = document.createElement("div");
      box.className = "stack";
      for (const f of fs) box.append(findingButton(f));
      card.append(box);
    }

    const up = closure(e.event_id, provUp);
    const down = closure(e.event_id, provDown);
    const tainted = up.filter((x) => x.trust_level === "lower_trust");
    card.append(text("div", `${up.length} upstream · ${down.length} downstream`, "card-time"));
    if (tainted.length) {
      card.append(text("div", "Influenced by lower-trust content:", "taint"), linkList(tainted.map((x) => x.event_id)));
    }

    const actions = document.createElement("div");
    actions.className = "card-actions";
    actions.append(
      button("Focus chain", "linkbtn", () => fit([e.event_id, ...up.map((x) => x.event_id), ...down.map((x) => x.event_id)])),
      button("All details", "linkbtn", () => document.getElementById("event-section").scrollIntoView({ behavior: "smooth", block: "start" })),
    );
    if (canCopy) actions.append(copyButton("Copy payload", JSON.stringify(e.payload, null, 2)));
    card.append(actions);

    card.hidden = false;
    placeCard();
  }
  function hideCard() {
    cardFor = null;
    card.hidden = true;
  }
  function placeCard() {
    if (!cardFor || card.hidden) return;
    const p = pos.get(cardFor);
    const W = graphBox.clientWidth, H = graphBox.clientHeight;
    const w = card.offsetWidth, h = card.offsetHeight;
    const sx = view.x + p.x * view.k, sy = view.y + p.y * view.k, gap = R * view.k + 14;
    let x = sx + gap;
    if (x + w > W - 8) x = sx - gap - w;
    x = Math.max(8, Math.min(x, W - w - 8));
    const y = Math.max(8, Math.min(sy - 28, H - h - 8));
    card.style.left = x + "px";
    card.style.top = y + "px";
  }
  // Wheel and drag on the card scroll the card, not the graph.
  card.addEventListener("pointerdown", (ev) => ev.stopPropagation());
  card.addEventListener("click", (ev) => ev.stopPropagation());

  let selectedFinding = null;
  let selectedEvent = null;
  function selectEvent(id, reveal) {
    const e = byId.get(id);
    if (!e) return;
    selectFinding(null, false);
    selectedEvent = id;
    const up = reach(id, incoming, (l) => l.from);
    const down = reach(id, outgoing, (l) => l.to);
    const ids = new Set([...up, ...down]);
    highlight(ids, (l) => visibleType(l.type) &&
      ((up.has(l.from) && up.has(l.to)) || (down.has(l.from) && down.has(l.to))));
    for (const [nid, g] of nodeEls) g.classList.toggle("selected", nid === id);
    showDetails(e);
    showCard(e);
    if (reveal) ensureVisible(id);
  }
  function clearSelection() {
    selectFinding(null, false);
    selectedEvent = null;
    hideCard();
    clearHighlight();
    details.replaceChildren(text("p", "Select an event to see its links and payload.", "empty"));
  }

  // ---- findings ------------------------------------------------------------------------
  const findingBox = document.getElementById("findings");
  const findingEls = [];
  function selectFinding(f, doHighlight = true) {
    selectedFinding = f;
    for (const { f: other, n } of findingEls) n.classList.toggle("selected", other === f);
    if (!f || !doHighlight) return;
    selectedEvent = null;
    hideCard();
    const ids = new Set(f.evidence_event_ids || []);
    highlight(ids, (l) => ids.has(l.from) && ids.has(l.to));
    for (const g of nodeEls.values()) g.classList.remove("selected");
    fit([...ids]);
    const n = findingEls.find((x) => x.f === f);
    if (n) n.n.scrollIntoView({ block: "nearest" });
  }
  const sorted = [...findings].sort(bySeverity);
  if (!sorted.length) findingBox.append(text("p", "No findings.", "empty"));
  for (const f of sorted) {
    const n = document.createElement("div");
    n.className = "finding";
    n.tabIndex = 0;
    const top = document.createElement("div");
    top.className = "top";
    top.append(text("span", f.severity, "sev " + f.severity), text("strong", f.rule_id),
      text("span", f.attempt_status + " · " + f.confidence + " confidence", "tag"));
    const more = document.createElement("div");
    more.className = "desc";
    more.append(text("div", f.description));
    if (f.remediation) more.append(text("div", "Remediation: " + f.remediation, "remedy"));
    const evidence = (f.evidence_event_ids || []).filter((id) => byId.has(id));
    if (evidence.length) more.append(linkList(evidence));
    n.append(top, text("div", f.title, "title"), more);
    const pick = () => {
      if (selectedFinding === f) { clearSelection(); return; }
      clearHighlight();
      selectFinding(f);
    };
    n.addEventListener("click", pick);
    n.addEventListener("keydown", (ev) => { if (ev.key === "Enter" && ev.target === n) pick(); });
    findingBox.append(n);
    findingEls.push({ f, n });
  }

  // ---- toolbar -------------------------------------------------------------------------
  const show = {
    cause: document.getElementById("show-cause"),
    context: document.getElementById("show-context"),
    parent: document.getElementById("show-parent"),
  };
  function visibleType(type) { return show[type].checked; }
  function applyEdgeFilters() {
    for (const l of links) l.el.classList.toggle("hidden", !visibleType(l.type));
  }
  for (const box of Object.values(show)) box.addEventListener("change", applyEdgeFilters);
  applyEdgeFilters();

  const search = document.getElementById("search");
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    for (const e of events) {
      const hay = (e.kind + " " + e.name + " " + JSON.stringify(e.payload)).toLowerCase();
      nodeEls.get(e.event_id).classList.toggle("match", q.length > 0 && hay.includes(q));
    }
  });
  document.getElementById("fit").addEventListener("click", () => fit());
  document.getElementById("clear").addEventListener("click", clearSelection);
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") { clearSelection(); return; }
    if ((ev.key === "ArrowLeft" || ev.key === "ArrowRight") && !(ev.target instanceof Element && ev.target.closest("input, textarea, select"))) {
      if (!events.length) return;
      const i = selectedEvent ? events.indexOf(byId.get(selectedEvent)) : -1;
      const j = ev.key === "ArrowRight" ? Math.min(events.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1);
      ev.preventDefault();
      selectEvent(events[j].event_id, true);
    }
  });

  // ---- header & legend -----------------------------------------------------------------
  const t = report.trace || {};
  document.title = "agent-trace · " + (t.name || "trace");
  document.getElementById("trace-name").textContent = t.name || "trace";
  document.getElementById("trace-meta").textContent = [
    t.trace_id, t.execution_mode, t.status, events.length + " events",
    findings.length + " findings", report.generated_by,
  ].filter(Boolean).join(" · ");
  if (t.execution_mode === "simulated") document.getElementById("simulated").classList.add("on");
  document.getElementById("disclaimer").textContent = report.disclaimer || "";
  const legend = document.getElementById("legend");
  for (const [cls, label] of [
    ["user", "user prompt"], ["model", "model"], ["request", "tool request"],
    ["policy", "policy decision"], ["blocked", "blocked / failed"], ["result", "tool result"],
    ["content", "external content"], ["message", "agent message"], ["agent", "lifecycle"],
  ]) {
    const sw = document.createElement("span");
    sw.className = "sw";
    sw.style.background = `var(--${cls})`;
    legend.append(sw, text("span", label));
  }
  for (const [cls, label] of [["", "caused by"], ["ctx", "context (in view of)"],
    ["par", "structure (parent)"]]) {
    const ln = document.createElement("span");
    ln.className = "ln " + cls;
    legend.append(ln, text("span", label));
  }
  const lower = document.createElement("span");
  lower.className = "sw";
  lower.style.border = "2px dashed var(--blocked)";
  legend.append(lower, text("span", "lower-trust content"));

  fit();
  // Open on the most severe finding, if any.
  if (sorted.length) selectFinding(sorted[0]);
})();
