(() => {
  "use strict";

  const MAX_FILE_BYTES = 25 * 1024 * 1024;
  const MAX_EVENTS = 100000;
  const REDACTED_KEY = /(?:reasoning|thought|chain.?of.?thought)/i;
  const state = { runs: [], scorecards: [], selectedRun: 0, selectedEvent: null, visible: [], undo: null, toastTimer: 0 };
  const byId = (id) => document.getElementById(id);
  const text = (value, fallback = "Not recorded") => {
    if (value === undefined || value === null || value === "") return fallback;
    if (typeof value === "boolean") return value ? "Yes" : "No";
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  };
  const safeCopy = (value) => {
    if (Array.isArray(value)) return value.map(safeCopy);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).filter(([key]) => !REDACTED_KEY.test(key)).map(([key, item]) => [key, safeCopy(item)]));
    }
    return value;
  };
  const create = (tag, className, value) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined) element.textContent = value;
    return element;
  };
  const getPayload = (event) => event.payload && typeof event.payload === "object" ? event.payload : {};
  const getDecision = (event) => {
    const payload = getPayload(event);
    return payload.defense_decision || event.defense_decision || (event.type === "defense_decision" ? payload : null);
  };
  const getVerdict = (event) => {
    const decision = getDecision(event);
    return text(decision?.decision || decision?.action || getPayload(event).decision, "").toLowerCase();
  };
  const getTrust = (event) => {
    const refs = event.provenance_refs || getPayload(event).provenance_refs;
    const values = Array.isArray(refs) ? refs : refs ? [refs] : [];
    const trust = values.map((ref) => typeof ref === "object" ? ref.trust || ref.trust_level : "").filter(Boolean).join(" ").toLowerCase();
    if (!trust) return "unknown";
    return /untrusted|tainted|external/.test(trust) ? "untrusted" : "trusted";
  };
  const currentRun = () => state.runs[state.selectedRun];
  const currentEvents = () => currentRun()?.events || [];
  const notify = (message, undo = false) => {
    byId("toast-message").textContent = message;
    byId("undo-clear").classList.toggle("hidden", !undo);
    byId("toast").classList.remove("hidden");
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => byId("toast").classList.add("hidden"), 6500);
  };
  const statePill = (label, tone = "") => {
    const pill = create("span", `state ${tone}`, label);
    return pill;
  };

  function renderEmptyInspector(message = "Choose a trace row to inspect its recorded decision, provenance and related effects.") {
    const root = byId("inspector"); root.replaceChildren();
    const empty = create("div", "inspector-empty");
    empty.append(create("span", "inspector-icon", "◎"), create("p", "eyebrow", "EVIDENCE INSPECTOR"));
    const heading = create("h2", "", "Select an event"); heading.id = "inspector-title";
    empty.append(heading, create("p", "", message)); root.append(empty);
  }

  function buildRunTabs() {
    const root = byId("run-tabs");
    root.replaceChildren();
    state.runs.forEach((run, index) => {
      const button = create("button", "run-tab", run.id || run.source);
      button.type = "button";
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", String(index === state.selectedRun));
      button.setAttribute("aria-controls", "summary-grid");
      button.addEventListener("click", () => { state.selectedRun = index; state.selectedEvent = null; fillTypes(); render(); });
      root.append(button);
    });
  }

  function deriveRun(run) {
    const findValue = (keys) => {
      for (const event of run.events) {
        const payload = getPayload(event);
        for (const key of keys) {
          const value = payload[key] ?? event[key];
          if (value !== undefined && value !== null) return value;
        }
      }
      return undefined;
    };
    const scorecard = run.scorecard;
    const outcomes = Array.isArray(scorecard?.outcomes) ? scorecard.outcomes : [];
    const scenario = findValue(["scenario_id", "scenario"]);
    const outcome = run.events.map((event) => ({ ...getPayload(event), ...event })).find((event) => typeof event.attack_success === "boolean" || typeof event.task_success === "boolean") || {};
    const aggregate = outcomes.find((item) => item.scenario_id === scenario) || (outcomes.length === 1 ? outcomes[0] : null);
    const merged = { ...aggregate, ...outcome };
    return {
      scenario: scenario ?? merged.scenario_id,
      model: findValue(["model_id", "model", "model_name"]) ?? scorecard?.model_id,
      runtime: findValue(["runtime", "runtime_name", "backend"]) ?? scorecard?.runtime,
      attack: merged.attack_success,
      task: merged.task_success,
      metrics: scorecard?.metrics,
      benchmark: scorecard?.benchmark_version,
    };
  }

  function renderSummary() {
    const run = currentRun();
    if (!run) return;
    const details = deriveRun(run);
    byId("run-title").textContent = run.id || run.source;
    const root = byId("summary-grid");
    root.replaceChildren();
    const values = [
      ["Scenario", details.scenario], ["Model", details.model], ["Runtime", details.runtime],
      ["Attack reachability", typeof details.attack === "boolean" ? (details.attack ? "Reached" : "Not reached") : undefined],
      ["Task outcome", typeof details.task === "boolean" ? (details.task ? "Succeeded" : "Failed") : undefined],
      ["Trace events", run.events.length],
    ];
    for (const [label, value] of values) {
      const cell = create("div", "summary-item");
      cell.append(create("small", "", label));
      if (label === "Attack reachability" && typeof details.attack === "boolean") cell.append(statePill(details.attack ? "Attack reached" : "Attack not reached", details.attack ? "reached" : "unreached"));
      else if (label === "Task outcome" && typeof details.task === "boolean") cell.append(statePill(details.task ? "Task succeeded" : "Task failed", details.task ? "allow" : "block"));
      else cell.append(create("strong", "", text(value)));
      root.append(cell);
    }
  }

  function filteredEvents() {
    const query = `${byId("global-search").value} ${byId("event-search").value}`.trim().toLowerCase();
    const type = byId("type-filter").value;
    const verdict = byId("verdict-filter").value;
    const trust = byId("trust-filter").value;
    return currentEvents().filter((event) => {
      if (type && event.type !== type) return false;
      if (verdict && getVerdict(event) !== verdict) return false;
      if (trust && getTrust(event) !== trust) return false;
      return !query || JSON.stringify(event).toLowerCase().includes(query);
    });
  }

  function renderEvents() {
    const filtered = filteredEvents();
    state.visible = filtered;
    const body = byId("event-rows");
    body.replaceChildren();
    byId("event-count").textContent = `${filtered.length} / ${currentEvents().length}`;
    const status = filtered.length ? `${filtered.length} of ${currentEvents().length} events shown.` : currentEvents().length ? "No events match the current search and filters. Use Reset to show all events." : "No trace events are recorded for this run.";
    byId("live-status").textContent = status;
    if (!filtered.length) {
      const row = create("tr"); const cell = create("td", "empty-row", status); cell.colSpan = 4; row.append(cell); body.append(row); return;
    }
    for (const event of filtered) {
      const row = create("tr", "event-row");
      const selected = state.selectedEvent === event;
      row.tabIndex = 0;
      row.setAttribute("aria-selected", String(selected));
      row.setAttribute("aria-label", `${text(event.type, "Event")}, ${getVerdict(event) || "decision not recorded"}`);
      const payload = getPayload(event);
      const decision = getDecision(event);
      const timeCell = create("td");
      timeCell.append(create("span", "event-time", `#${text(event.seq ?? event.step_id, "–")} · ${text(event.timestamp, "time not recorded")}`));
      const eventCell = create("td");
      eventCell.append(create("span", "event-label", text(event.type, "Event")));
      const actor = event.actor ?? payload.actor;
      if (actor !== undefined) eventCell.append(create("span", "event-sub", text(actor)));
      const decisionCell = create("td");
      const verdict = getVerdict(event);
      if (verdict) decisionCell.append(create("span", `verdict verdict-${verdict}`, verdict));
      else decisionCell.append(create("span", "event-sub", "Not recorded"));
      const metricCell = create("td", "metric-cell");
      const risk = decision?.risk_score;
      const confidence = decision?.confidence;
      metricCell.textContent = risk === undefined && confidence === undefined ? "Not recorded" : `${risk === undefined ? "—" : Number(risk).toFixed(2)} / ${confidence === undefined ? "—" : Number(confidence).toFixed(2)}`;
      row.append(timeCell, eventCell, decisionCell, metricCell);
      row.addEventListener("click", () => selectEvent(event));
      row.addEventListener("keydown", (keyEvent) => {
        if (keyEvent.key === "Enter" || keyEvent.key === " ") { keyEvent.preventDefault(); selectEvent(event); }
        if (keyEvent.key === "ArrowDown" || keyEvent.key === "ArrowUp") {
          keyEvent.preventDefault();
          const index = filtered.indexOf(event) + (keyEvent.key === "ArrowDown" ? 1 : -1);
          const rows = [...body.querySelectorAll(".event-row")];
          rows[Math.max(0, Math.min(rows.length - 1, index))]?.focus();
        }
      });
      body.append(row);
    }
  }

  function appendPairs(root, pairs) {
    for (const [label, value] of pairs) {
      const row = create("div", "detail-pair"); row.append(create("dt", "", label), create("dd", "", text(value))); root.append(row);
    }
  }

  function detailSection(title, pairs) {
    const section = create("section", "detail-section"); section.append(create("h3", "", title));
    const list = create("dl"); list.className = "detail-list"; appendPairs(list, pairs); section.append(list); return section;
  }

  function matchingRelated(event) {
    const eventRun = event.run_id;
    const step = event.step_id ?? getPayload(event).step_id;
    return currentEvents().filter((candidate) => candidate !== event &&
      (eventRun === undefined || candidate.run_id === undefined || candidate.run_id === eventRun) &&
      (step === undefined || (candidate.step_id ?? getPayload(candidate).step_id) === step));
  }

  function renderInspector(event) {
    const root = byId("inspector"); root.replaceChildren();
    const header = create("div", "detail-top");
    const heading = create("div"); heading.append(create("p", "eyebrow", "EVIDENCE INSPECTOR"));
    const eventTitle = create("h2", "", text(event.type, "Event")); eventTitle.id = "inspector-title";
    heading.append(eventTitle, create("p", "", `Sequence ${text(event.seq, "not recorded")} · ${text(event.timestamp, "time not recorded")}`));
    const verdict = getVerdict(event); if (verdict) heading.append(create("span", `verdict verdict-${verdict}`, verdict));
    header.append(heading); root.append(header);
    const payload = getPayload(event); const decision = getDecision(event) || {};
    root.append(detailSection("Defense decision", [
      ["Decision", decision.decision ?? decision.action], ["Risk score", decision.risk_score],
      ["Confidence", decision.confidence], ["Explanation", decision.explanation], ["Rewritten action", decision.rewritten_action],
    ]));
    const reasons = Array.isArray(decision.reason_codes) ? decision.reason_codes : [];
    const reasonSection = create("section", "detail-section"); reasonSection.append(create("h3", "", `Reason codes · ${reasons.length}`));
    const reasonRoot = create("div", "detail-reasons");
    if (reasons.length) reasons.forEach((reason) => reasonRoot.append(create("span", "reason-chip", text(reason))));
    else reasonRoot.append(create("span", "", "Not recorded"));
    reasonSection.append(reasonRoot); root.append(reasonSection);
    root.append(detailSection("Candidate action", [["Actor", event.actor ?? payload.actor], ["Payload", payload.candidate_action ?? payload.action ?? payload]]));
    const provenance = event.provenance_refs ?? payload.provenance_refs;
    root.append(detailSection("Provenance", [["Trust", provenance === undefined ? undefined : getTrust(event)], ["References", provenance]]));
    const related = matchingRelated(event);
    const relatedSection = create("section", "detail-section"); relatedSection.append(create("h3", "", `Related events · ${related.length}`));
    const relatedList = create("div", "related-list");
    if (!related.length) relatedList.append(create("p", "event-sub", "No matching step references recorded."));
    related.forEach((item) => {
      const button = create("button", "related-button", `#${text(item.seq, "–")} · ${text(item.type, "Event")} · ${getVerdict(item) || "outcome"}`);
      button.type = "button"; button.addEventListener("click", () => { state.selectedEvent = item; renderEvents(); renderInspector(item); document.querySelector(".event-row[aria-selected='true']")?.scrollIntoView({ block: "nearest" }); }); relatedList.append(button);
    });
    relatedSection.append(relatedList); root.append(relatedSection);
    const raw = create("section", "detail-section"); raw.append(create("h3", "", "Recorded event"));
    const pre = create("pre", "detail-json", JSON.stringify(safeCopy(event), null, 2)); raw.append(pre); root.append(raw);
  }

  function selectEvent(event) { state.selectedEvent = event; renderEvents(); renderInspector(event); }

  function renderComparison() {
    const region = byId("comparison"); const cards = state.scorecards;
    region.classList.toggle("hidden", cards.length < 2);
    if (cards.length < 2) return;
    for (const id of ["compare-left", "compare-right"]) {
      const select = byId(id); const old = select.value; select.replaceChildren();
      cards.forEach((card, index) => { const option = document.createElement("option"); option.value = String(index); option.textContent = card.source; select.append(option); });
      if (old && Number(old) < cards.length) select.value = old;
    }
    if (byId("compare-left").value === byId("compare-right").value) byId("compare-right").value = "1";
    const left = cards[Number(byId("compare-left").value)]; const right = cards[Number(byId("compare-right").value)];
    const table = create("table", "comparison-table");
    const head = create("thead"); const hr = create("tr");
    ["Recorded metric", left.source, right.source, "Delta"].forEach((value) => hr.append(create("th", "", value)));
    head.append(hr); table.append(head); const body = create("tbody");
    const a = left.data.metrics || {}; const b = right.data.metrics || {};
    const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
    for (const key of keys) {
      const av = a[key]; const bv = b[key]; const row = create("tr");
      row.append(create("th", "", key), create("td", "", formatMetric(av)), create("td", "", formatMetric(bv)), create("td", "delta", typeof av === "number" && typeof bv === "number" ? formatMetric(bv - av) : "Not recorded")); body.append(row);
    }
    table.append(body);
    const wrap = byId("comparison-table"); wrap.replaceChildren(table);
    if (left.data.benchmark_version !== right.data.benchmark_version || left.data.model_id !== right.data.model_id) {
      wrap.append(create("p", "comparison-note", "Comparison metadata differs or is missing. Treat this as an uncontrolled comparison."));
    }
  }

  function formatMetric(value) {
    if (value === null || value === undefined) return "Not recorded";
    return typeof value === "number" ? String(Number(value.toPrecision(5))) : text(value);
  }

  function render() {
    const hasRuns = state.runs.length > 0;
    byId("welcome").classList.toggle("hidden", hasRuns);
    byId("workspace").classList.toggle("hidden", !hasRuns);
    byId("export-button").disabled = !hasRuns;
    byId("print-button").disabled = !hasRuns;
    byId("clear-button").disabled = !hasRuns;
    if (!hasRuns) { state.scorecards = []; state.selectedEvent = null; return; }
    buildRunTabs(); renderSummary(); renderEvents(); renderComparison();
    if (state.selectedEvent) renderInspector(state.selectedEvent);
    else renderEmptyInspector(currentEvents().length ? "Select an event to inspect its recorded evidence." : "No trace events are recorded for this scorecard.");
  }

  function fillTypes() {
    const select = byId("type-filter"); const old = select.value; select.replaceChildren();
    const all = document.createElement("option"); all.value = ""; all.textContent = "All event types"; select.append(all);
    [...new Set(currentEvents().map((event) => event.type).filter((type) => typeof type === "string"))].sort().forEach((type) => {
      const option = document.createElement("option"); option.value = type; option.textContent = type; select.append(option);
    });
    select.value = old;
  }

  function addTrace(file, contents) {
    const records = [];
    const lines = contents.replace(/^\uFEFF/, "").split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index]; if (!line.trim()) continue;
      let parsed;
      try { parsed = JSON.parse(line); }
      catch { throw new Error(`${file.name}: malformed JSON on line ${index + 1}.`); }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${file.name}: line ${index + 1} must contain a JSON object.`);
      records.push(safeCopy(parsed));
      if (records.length > MAX_EVENTS) throw new Error(`${file.name}: more than ${MAX_EVENTS.toLocaleString()} events. Split the trace and select one run.`);
    }
    if (!records.length) throw new Error(`${file.name}: no JSONL event records found.`);
    const groups = new Map();
    for (const record of records) {
      const runId = typeof record.run_id === "string" && record.run_id ? record.run_id : "";
      if (!groups.has(runId)) groups.set(runId, []);
      groups.get(runId).push(record);
    }
    for (const [id, events] of groups) state.runs.push({ id: id || file.name, source: file.name, events, scorecard: null });
  }

  function addScorecard(file, contents) {
    let data;
    try { data = safeCopy(JSON.parse(contents)); }
    catch { throw new Error(`${file.name}: scorecard is not valid JSON.`); }
    if (!data || typeof data !== "object" || Array.isArray(data) || (!data.metrics && !Array.isArray(data.outcomes))) {
      throw new Error(`${file.name}: expected evaluator JSON with metrics or outcomes.`);
    }
    const card = { source: file.name, data };
    state.scorecards.push(card);
    const outcomes = Array.isArray(data.outcomes) ? data.outcomes : [];
    if (!outcomes.length) {
      state.runs.push({ id: file.name, source: file.name, events: [], scorecard: data });
      return;
    }
    for (const outcome of outcomes) {
      const scenarioId = typeof outcome.scenario_id === "string" ? outcome.scenario_id : undefined;
      const existing = state.runs.find((run) => run.id === scenarioId && run.scorecard === null);
      if (existing) existing.scorecard = { ...data, outcomes: [outcome] };
      else state.runs.push({ id: scenarioId || file.name, source: file.name, events: [], scorecard: { ...data, outcomes: [outcome] } });
    }
  }

  async function loadFiles(files) {
    if (!files.length) return;
    for (const file of files) {
      try {
        if (file.size > MAX_FILE_BYTES) throw new Error(`${file.name}: file exceeds the 25 MB limit. Split the artifact or select a smaller run.`);
        const contents = await file.text();
        if (/\.(jsonl|ndjson)$/i.test(file.name) || contents.trimStart().startsWith("{") && contents.includes("\n{\"type\"")) addTrace(file, contents);
        else addScorecard(file, contents);
      } catch (error) { notify(error instanceof Error ? error.message : `${file.name}: could not read this artifact.`); }
    }
    if (state.runs.length) { state.selectedRun = Math.min(state.selectedRun, state.runs.length - 1); fillTypes(); render(); }
  }

  function exportView() {
    const run = currentRun(); if (!run) return;
    const content = {
      source: run.source, run_id: run.id,
      summary: deriveRun(run),
      events: state.visible.map(safeCopy),
      note: "Local view export. Missing source evidence is not inferred.",
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `${run.id.replace(/[^a-z0-9_-]+/gi, "-")}-view.json`; link.click(); URL.revokeObjectURL(url);
  }

  function clearArtifacts() {
    state.undo = { runs: state.runs, scorecards: state.scorecards };
    state.runs = []; state.scorecards = []; state.selectedRun = 0; state.selectedEvent = null;
    byId("artifact-files").value = ""; render(); notify("Imported artifacts cleared from this session.", true);
  }

  function resetFilters() {
    byId("global-search").value = ""; byId("event-search").value = ""; byId("type-filter").value = ""; byId("verdict-filter").value = ""; byId("trust-filter").value = ""; renderEvents();
  }

  byId("artifact-files").addEventListener("change", (event) => { loadFiles([...event.target.files]); event.target.value = ""; });
  ["global-search", "event-search", "type-filter", "verdict-filter", "trust-filter"].forEach((id) => byId(id).addEventListener("input", renderEvents));
  byId("reset-filters").addEventListener("click", resetFilters);
  byId("compare-left").addEventListener("change", renderComparison);
  byId("compare-right").addEventListener("change", renderComparison);
  byId("export-button").addEventListener("click", exportView);
  byId("print-button").addEventListener("click", () => window.print());
  byId("clear-button").addEventListener("click", clearArtifacts);
  byId("undo-clear").addEventListener("click", () => { if (state.undo) { state.runs = state.undo.runs; state.scorecards = state.undo.scorecards; state.undo = null; fillTypes(); render(); } });
  byId("dismiss-toast").addEventListener("click", () => byId("toast").classList.add("hidden"));
  byId("global-search").addEventListener("keydown", (event) => { if (event.key === "Escape") { event.target.value = ""; renderEvents(); } });
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement?.tagName)) { event.preventDefault(); byId("global-search").focus(); }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "o") { event.preventDefault(); byId("artifact-files").click(); }
  });
})();
