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
    // Labels below the node; same-lane arcs run above it.
    const seq = el("text", { class: "seq", y: R + 12, "text-anchor": "middle" }, g);
    seq.textContent = "#" + e.sequence;
    const name = String(e.name || e.kind);
    const label = el("text", { y: R + 25, "text-anchor": "middle" }, g);
    label.textContent = name.length > 15 ? name.slice(0, 14) + "…" : name;
    const tip = el("title", {}, g);
    tip.textContent = `#${e.sequence} ${e.kind} · ${name}` + (lower ? " · lower trust" : "");
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
  let drag = null;
  svg.addEventListener("pointerdown", (ev) => {
    drag = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y, moved: false };
    svg.setPointerCapture(ev.pointerId);
    svg.classList.add("dragging");
  });
  svg.addEventListener("pointermove", (ev) => {
    if (!drag) return;
    const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    view.x = drag.vx + dx;
    view.y = drag.vy + dy;
    apply();
  });
  svg.addEventListener("pointerup", () => {
    svg.classList.remove("dragging");
    const moved = drag && drag.moved;
    drag = null;
    if (!moved) svg.dataset.clickedBackground = "1";
  });
  svg.addEventListener("click", () => {
    if (svg.dataset.clickedBackground) { delete svg.dataset.clickedBackground; clearSelection(); }
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
  function linkButton(id) {
    const e = byId.get(id);
    const b = text("button", e ? `#${e.sequence} ${e.kind}` : id, "linkbtn");
    b.type = "button";
    b.addEventListener("click", () => selectEvent(id));
    return b;
  }
  function showDetails(e) {
    details.replaceChildren();
    const dl = document.createElement("dl");
    const rows = [
      ["sequence", "#" + e.sequence], ["kind", e.kind], ["name", e.name],
      ["agent", e.agent_id || "main"], ["origin", e.origin], ["trust", e.trust_level],
      ["state", e.tool_state || ""], ["time", e.timestamp], ["event id", e.event_id],
    ];
    for (const [k, v] of rows) {
      if (v === "" || v == null) continue;
      dl.append(text("dt", k), text("dd", v));
    }
    details.append(dl);
    for (const [label, ids] of [
      ["caused by", e.caused_by_event_id ? [e.caused_by_event_id] : []],
      ["context", e.context_event_ids || []],
      ["parent", e.parent_event_id ? [e.parent_event_id] : []],
      ["leads to", (outgoing.get(e.event_id) || []).filter((l) => l.type !== "parent").map((l) => l.to)],
    ]) {
      if (!ids.length) continue;
      details.append(text("h2", label));
      const box = document.createElement("div");
      box.className = "links";
      for (const id of ids) box.append(linkButton(id));
      details.append(box);
    }
    details.append(text("h2", "payload (redacted)"), text("pre", JSON.stringify(e.payload, null, 2)));
    if (e.metadata && Object.keys(e.metadata).length) {
      details.append(text("h2", "metadata"), text("pre", JSON.stringify(e.metadata, null, 2)));
    }
  }

  let selectedFinding = null;
  function selectEvent(id) {
    const e = byId.get(id);
    if (!e) return;
    selectFinding(null, false);
    const up = reach(id, incoming, (l) => l.from);
    const down = reach(id, outgoing, (l) => l.to);
    const ids = new Set([...up, ...down]);
    highlight(ids, (l) => visibleType(l.type) &&
      ((up.has(l.from) && up.has(l.to)) || (down.has(l.from) && down.has(l.to))));
    for (const [nid, g] of nodeEls) g.classList.toggle("selected", nid === id);
    showDetails(e);
  }
  function clearSelection() {
    selectFinding(null, false);
    clearHighlight();
    details.replaceChildren(text("p", "Select an event to see its links and payload.", "empty"));
  }

  // ---- findings ------------------------------------------------------------------------
  const SEVERITY = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const findingBox = document.getElementById("findings");
  const findingEls = [];
  function selectFinding(f, doHighlight = true) {
    selectedFinding = f;
    for (const { f: other, n } of findingEls) n.classList.toggle("selected", other === f);
    if (!f || !doHighlight) return;
    const ids = new Set(f.evidence_event_ids || []);
    highlight(ids, (l) => ids.has(l.from) && ids.has(l.to));
    for (const g of nodeEls.values()) g.classList.remove("selected");
    fit([...ids]);
  }
  const sorted = [...findings].sort((a, b) =>
    (SEVERITY[a.severity] ?? 9) - (SEVERITY[b.severity] ?? 9) || a.rule_id.localeCompare(b.rule_id));
  if (!sorted.length) findingBox.append(text("p", "No findings.", "empty"));
  for (const f of sorted) {
    const n = document.createElement("div");
    n.className = "finding";
    n.tabIndex = 0;
    const top = document.createElement("div");
    top.className = "top";
    top.append(text("span", f.severity, "sev " + f.severity), text("strong", f.rule_id),
      text("span", f.attempt_status + " · " + f.confidence + " confidence", "tag"));
    n.append(top, text("div", f.title, "title"), text("div", f.description, "desc"));
    const pick = () => {
      if (selectedFinding === f) { clearSelection(); return; }
      clearHighlight();
      selectFinding(f);
    };
    n.addEventListener("click", pick);
    n.addEventListener("keydown", (ev) => { if (ev.key === "Enter") pick(); });
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
    if (ev.key === "Escape") clearSelection();
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
