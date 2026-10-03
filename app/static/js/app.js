"use strict";

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------
const api = {
  token: localStorage.getItem("aca_token") || "",
  async req(method, path, body) {
    const headers = { "Content-Type": "application/json" };
    if (this.token) headers["Authorization"] = "Bearer " + this.token;
    const res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 401) {
      showLock();
      throw new Error("Session expired. Please unlock again.");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || ("Request failed (" + res.status + ")"));
    return data;
  },
  get(p) { return this.req("GET", p); },
  post(p, b) { return this.req("POST", p, b === undefined ? {} : b); },
  put(p, b) { return this.req("PUT", p, b); },
  del(p) { return this.req("DELETE", p); },
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html !== undefined) n.innerHTML = html;
  return n;
};

function toast(msg, kind = "ok") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast " + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = "toast hidden"), 3200);
}

// ---------------------------------------------------------------------------
// Lock screen
// ---------------------------------------------------------------------------
function showLock() {
  $("#app").classList.add("hidden");
  $("#lock").classList.remove("hidden");
  $("#lock-password").value = "";
  $("#lock-password").focus();
}
function showApp() {
  $("#lock").classList.add("hidden");
  $("#app").classList.remove("hidden");
}

$("#lock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#lock-error").textContent = "";
  try {
    const data = await api.post("/api/auth/login", { password: $("#lock-password").value });
    api.token = data.token;
    localStorage.setItem("aca_token", data.token);
    showApp();
    await boot();
  } catch (err) {
    $("#lock-error").textContent = err.message;
  }
});

$("#logout").addEventListener("click", async () => {
  try { await api.post("/api/auth/logout"); } catch (_) {}
  api.token = "";
  localStorage.removeItem("aca_token");
  showLock();
});

// ---- Mobile sidebar drawer ----
function openSidebar() {
  $("#sidebar").classList.add("open");
  $("#sidebar-backdrop").classList.add("show");
}
function closeSidebar() {
  $("#sidebar").classList.remove("open");
  $("#sidebar-backdrop").classList.remove("show");
}
$("#menu-btn").addEventListener("click", openSidebar);
$("#control-btn").addEventListener("click", () => { closeSidebar(); panelSettings(); });
$("#sidebar-close").addEventListener("click", closeSidebar);
$("#sidebar-backdrop").addEventListener("click", closeSidebar);

// ---------------------------------------------------------------------------
// Chat
// ---------------------------------------------------------------------------
let currentSession = "default";
const messagesEl = $("#messages");

function renderMessage(role, content, toolCalls) {
  if (role === "user") {
    const m = el("div", "msg user");
    m.appendChild(el("div", "avatar", "🧑"));
    m.appendChild(el("div", "bubble", escapeHtml(content)));
    messagesEl.appendChild(m);
    return m;
  }
  if (role === "assistant") {
    const m = el("div", "msg assistant");
    m.appendChild(el("div", "avatar", "🤖"));
    const b = el("div", "bubble");
    b.innerHTML = renderMarkdown(content);
    m.appendChild(b);
    messagesEl.appendChild(m);
    return m;
  }
  if (role === "tool") {
    const t = el("div", "tool" + (toolCalls && toolCalls.error ? " err" : ""));
    t.innerHTML = `<span class="tlabel">tool</span> <span class="tname">${escapeHtml(
      (toolCalls && toolCalls.name) || "result"
    )}</span>\n${escapeHtml(typeof content === "string" ? content : JSON.stringify(content, null, 2))}`;
    messagesEl.appendChild(t);
    return t;
  }
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Minimal, dependency-free Markdown → HTML (escapes first, so it is XSS-safe).
function renderMarkdown(src) {
  let s = escapeHtml(String(src == null ? "" : src));
  const blocks = [];
  const stash = (html) => { blocks.push(html); return "\u0000" + (blocks.length - 1) + "\u0000"; };

  // Fenced code blocks.
  s = s.replace(/```[a-zA-Z0-9]*\n?([\s\S]*?)```/g, (_, code) =>
    stash("<pre class='code'>" + code.replace(/\n+$/g, "") + "</pre>"));
  // Tables (a header row, a separator row, then body rows).
  s = s.replace(
    /^\|(.+)\|\s*\n\|[\s:|-]+\|\s*\n((?:\|.*\|\s*\n?)*)/gm,
    (_, head, body) => {
      const cells = (row) => row.split("|").map((c) => c.trim()).filter((c, i, a) => !(i === 0 && c === "") && !(i === a.length - 1 && c === ""));
      const th = cells(head).map((c) => `<th>${c}</th>`).join("");
      const rows = body.trim().split("\n").map((r) =>
        "<tr>" + cells(r).map((c) => `<td>${c}</td>`).join("") + "</tr>").join("");
      return stash(`<div class="tbl-wrap"><table><thead><tr>${th}</tr></thead><tbody>${rows}</tbody></table></div>`) + "\n";
    });
  s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
  s = s.replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>");
  s = s.replace(/(^|[^*\w])\*([^*\n]+)\*/g, "$1<i>$2</i>");
  s = s.replace(/^#### (.*)$/gm, "<h5>$1</h5>");
  s = s.replace(/^### (.*)$/gm, "<h4>$1</h4>");
  s = s.replace(/^## (.*)$/gm, "<h3>$1</h3>");
  s = s.replace(/^# (.*)$/gm, "<h3>$1</h3>");
  s = s.replace(/^\s*&gt;\s?(.*)$/gm, "<blockquote>$1</blockquote>");
  // Group consecutive list lines into <ul>/<ol>.
  const out = [];
  let list = null;
  const flush = () => { if (list) { out.push("</" + list + ">"); list = null; } };
  for (const ln of s.split("\n")) {
    const ul = ln.match(/^\s*[-*]\s+(.*)$/);
    const ol = ln.match(/^\s*\d+[.)]\s+(.*)$/);
    if (ul) { if (list !== "ul") { flush(); out.push("<ul>"); list = "ul"; } out.push("<li>" + ul[1] + "</li>"); }
    else if (ol) { if (list !== "ol") { flush(); out.push("<ol>"); list = "ol"; } out.push("<li>" + ol[1] + "</li>"); }
    else { flush(); out.push(ln); }
  }
  flush();
  s = out.join("\n").replace(/\n{2,}/g, "\u0001").replace(/\n/g, "<br>").replace(/\u0001/g, "<div class='spacer'></div>");
  s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => blocks[+i]);
  return s;
}

const scrollPill = $("#scroll-down");
function atBottom() {
  return messagesEl.scrollHeight - messagesEl.scrollTop - messagesEl.clientHeight < 80;
}
// Only auto-follow the newest message when the user is already at the bottom,
// so typing or reading an older message is never yanked away.
function scrollDown(force) {
  if (force || atBottom()) {
    messagesEl.scrollTop = messagesEl.scrollHeight;
    scrollPill.classList.add("hidden");
  } else {
    scrollPill.classList.remove("hidden");
  }
}
messagesEl.addEventListener("scroll", () => {
  scrollPill.classList.toggle("hidden", atBottom());
});
scrollPill.addEventListener("click", () => scrollDown(true));

// ---- Live step tracker (shows each task step and its status) ----
function createStepTracker() {
  const card = el("div", "taskcard");
  card.innerHTML = `<div class="taskhead">📋 Task progress</div><div class="steplist"></div>
    <div class="statusline">⏳ Working…</div>`;
  messagesEl.appendChild(card);
  scrollDown();
  return {
    el: card,
    rows: new Map(),
    status: card.querySelector(".statusline"),
    list: card.querySelector(".steplist"),
    step(ev) {
      let row = this.rows.get(ev.n);
      if (!row) {
        row = el("div", "steprow");
        row.innerHTML = `<span class="sicon">•</span><span class="sname">${escapeHtml(ev.name)}</span>`;
        this.rows.set(ev.n, row);
        this.list.appendChild(row);
      }
      const icon = row.querySelector(".sicon");
      if (ev.status === "running") { icon.textContent = "⏳"; row.className = "steprow running"; }
      else if (ev.status === "done") { icon.textContent = "✅"; row.className = "steprow done"; }
      else { icon.textContent = "❌"; row.className = "steprow failed"; }
      scrollDown();
    },
    plan(steps) {
      this.planBox = this.planBox || (() => {
        const b = el("div", "planbox");
        b.innerHTML = `<div class="planhead">🧭 Plan</div>`;
        this.list.parentNode.insertBefore(b, this.list);
        return b;
      })();
      this.planBox.innerHTML = `<div class="planhead">🧭 Plan</div>` +
        steps.map((s, i) => `<div class="planitem">${i + 1}. ${escapeHtml(s)}</div>`).join("");
      scrollDown();
    },
    setStatus(text) { this.status.textContent = text; scrollDown(); },
    finish() {
      const anyFail = [...this.rows.values()].some((r) => r.classList.contains("failed"));
      this.status.textContent = anyFail ? "⚠️ Finished with errors" : "✅ Done";
      this.status.classList.add("final");
    },
  };
}

function addToolCard(kind, name, payload, ok) {
  const t = el("div", "tool" + (ok === false ? " err" : ""));
  t.innerHTML = `<span class="tlabel">${kind}</span> <span class="tname">${escapeHtml(name)}</span>\n${escapeHtml(
    typeof payload === "string" ? payload : JSON.stringify(payload, null, 2)
  )}`;
  messagesEl.appendChild(t);
  scrollDown();
  return t;
}

async function sendMessage(text) {
  if (!text.trim()) return;
  const empty = messagesEl.querySelector(".empty-state");
  if (empty) empty.remove();

  renderMessage("user", text);
  $("#input").value = "";
  autoGrow($("#input"));
  scrollDown();

  const sendBtn = $("#composer button");
  sendBtn.disabled = true;

  const headers = { "Content-Type": "application/json" };
  if (api.token) headers["Authorization"] = "Bearer " + api.token;

  const tracker = createStepTracker();
  let liveAssistant = null;

  const openStream = async (attempt) => {
    const res = await fetch("/api/chat/stream", {
      method: "POST", headers,
      body: JSON.stringify({ session_id: currentSession, message: text }),
    });
    if (res.status === 401) { showLock(); throw new Error("Session expired."); }
    if ((res.status === 404 || res.status >= 500) && attempt < 2) {
      tracker.setStatus("🔁 Server busy/restarting — retrying…");
      await new Promise((r) => setTimeout(r, 2500));
      return openStream(attempt + 1);
    }
    if (!res.ok || !res.body) throw new Error("Stream failed (" + res.status + ")");
    return res;
  };

  try {
    const res = await openStream(0);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop();
      for (const part of parts) {
        const line = part.trim();
        if (!line.startsWith("data:")) continue;
        let ev;
        try { ev = JSON.parse(line.slice(5).trim()); } catch (_) { continue; }
        liveAssistant = handleEvent(ev, tracker, liveAssistant);
      }
    }
    tracker.finish();
  } catch (err) {
    tracker.setStatus("❌ " + err.message);
    addToolCard("error", "request", err.message, false);
  } finally {
    sendBtn.disabled = false;
    refreshRate();
    scrollDown();
  }
}

function handleEvent(ev, tracker, live) {
  switch (ev.type) {
    case "plan":
      tracker.plan(ev.steps || []);
      tracker.setStatus("🧭 Plan ready — executing…");
      break;
    case "step":
      if (ev.status === "running") tracker.setStatus("⏳ Running: " + ev.name);
      tracker.step(ev);
      break;
    case "status":
      tracker.setStatus("⏳ " + ev.message);
      break;
    case "assistant": {
      if (!ev.content || !ev.content.trim()) break;
      // Append streamed assistant text into a single bubble.
      if (live && live.dataset.streaming === "1") {
        live._raw = (live._raw || "") + "\n\n" + ev.content;
        live.querySelector(".bubble").innerHTML = renderMarkdown(live._raw);
      } else {
        live = renderMessage("assistant", ev.content);
        live.dataset.streaming = "1";
        live._raw = ev.content;
      }
      scrollDown();
      break;
    }
    case "tool_call":
    case "tool_result":
      break; // steps are shown in the task-progress card
    case "error":
      tracker.setStatus("❌ " + ev.message);
      addToolCard("error", "agent", ev.message, false);
      break;
    case "done":
      if (ev.rate_limit) updateRateBadge(ev.rate_limit);
      break;
    case "end":
      break;
  }
  return live;
}

$("#composer").addEventListener("submit", (e) => {
  e.preventDefault();
  sendMessage($("#input").value);
});
$("#input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage($("#input").value);
  }
});
function autoGrow(t) { t.style.height = "auto"; t.style.height = Math.min(t.scrollHeight, 180) + "px"; }
$("#input").addEventListener("input", (e) => autoGrow(e.target));

document.querySelectorAll(".chip").forEach((c) =>
  c.addEventListener("click", () => {
    $("#input").value = c.dataset.fill || "";
    autoGrow($("#input"));
    $("#input").focus();
  })
);

$("#new-chat").addEventListener("click", () => {
  currentSession = "chat-" + Date.now();
  $("#session-label").textContent = currentSession;
  messagesEl.innerHTML = "";
  renderEmptyState();
  loadSessions();
});

$("#clear-chat").addEventListener("click", async () => {
  if (!confirm("Clear this chat's history?")) return;
  await api.del("/api/chat/" + encodeURIComponent(currentSession));
  messagesEl.innerHTML = "";
  renderEmptyState();
  loadSessions();
});

function renderEmptyState() {
  messagesEl.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">👋</div>
      <h2>Your private AI agent</h2>
      <p class="muted">Paste an API key, a link, a code snippet, or an MCP config. I'll check it
        step by step and save it only when you ask.</p>
      <div class="chips">
        <button class="chip" data-fill="Check this API key and tell me if it works: sk-...">🔑 Check a key</button>
        <button class="chip" data-fill="Check this link and tell me if it is reachable: https://">🔗 Check a link</button>
        <button class="chip" data-fill="Scan this code for secrets and dangers:&#10;&#10;">🧪 Scan code</button>
        <button class="chip" data-fill="Connect an MCP server named 'filesystem' using stdio command npx with args -y @modelcontextprotocol/server-filesystem /tmp">🔌 Add MCP</button>
        <button class="chip" data-fill="Show me the system layers and how many items each holds.">🗂️ Show layers</button>
        <button class="chip" data-fill="Give me a full health report of the system.">🩺 Health report</button>
        <button class="chip" data-fill="Find the best working model on my provider and set it.">✨ Best model</button>
      </div>
    </div>`;
  document.querySelectorAll(".chip").forEach((c) =>
    c.addEventListener("click", () => {
      $("#input").value = c.dataset.fill || "";
      autoGrow($("#input"));
      $("#input").focus();
    })
  );
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
async function loadSessions() {
  try {
    const data = await api.get("/api/chat/sessions");
    const box = $("#sessions");
    box.innerHTML = "";
    const list = data.sessions || [];
    if (!list.length) { box.innerHTML = '<div class="muted small">No chats yet</div>'; return; }
    for (const s of list) {
      const item = el("div", "session-item" + (s.session_id === currentSession ? " active" : ""));
      item.textContent = s.session_id;
      item.title = s.session_id;
      item.addEventListener("click", () => openSession(s.session_id));
      box.appendChild(item);
    }
  } catch (_) {}
}

async function openSession(sid) {
  currentSession = sid;
  $("#session-label").textContent = sid;
  const data = await api.get("/api/chat/" + encodeURIComponent(sid) + "/messages");
  messagesEl.innerHTML = "";
  if (!data.messages || !data.messages.length) { renderEmptyState(); return; }
  for (const m of data.messages) {
    if (m.role === "user" || m.role === "assistant") renderMessage(m.role, m.content);
  }
  scrollDown(true);
  loadSessions();
}

// ---------------------------------------------------------------------------
// Drawer / panels
// ---------------------------------------------------------------------------
function openDrawer(title) {
  $("#drawer-title").textContent = title;
  $("#drawer").classList.remove("hidden");
}
function closeDrawer() { $("#drawer").classList.add("hidden"); }
document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", closeDrawer));

document.querySelectorAll(".nav").forEach((n) =>
  n.addEventListener("click", () => {
    const p = n.dataset.panel;
    closeSidebar();
    if (p === "settings") panelSettings();
    if (p === "layers") panelLayers();
    if (p === "memory") panelMemory();
    if (p === "mcp") panelMcp();
    if (p === "appmcp") panelAppMcp();
    if (p === "security") panelSecurity();
  })
);

// ---- System layers (number-letter) ----
async function panelLayers() {
  openDrawer("System layers");
  const c = $("#drawer-content");
  const d = await api.get("/api/layers");
  const items = (await api.get("/api/items")).items || [];
  c.innerHTML = `
    <div class="card"><h3>Number-letter layers</h3>
      <div class="meta">Everything you save gets a code like <b>A1</b>, <b>B2</b> — letter = layer, number = slot.</div>
    </div>
    <div id="l-layers"></div>
    <hr class="sep" />
    <div class="card">
      <h3>Save an item</h3>
      <div class="meta">Saved encrypted, with a number-letter code you can recall later.</div>
      <div class="row">
        <div class="field"><label>Kind</label>
          <select id="i-kind">
            <option value="api_key">api_key (A)</option>
            <option value="token">token (A)</option>
            <option value="mcp">mcp (B)</option>
            <option value="link">link (C)</option>
            <option value="code">code (D)</option>
            <option value="note">note (E)</option>
            <option value="fact">fact (F)</option>
          </select></div>
        <div class="field"><label>Name</label><input id="i-name" placeholder="my-key" /></div>
      </div>
      <div class="field"><label>Value</label><input id="i-value" type="password" placeholder="secret / url / text" /></div>
      <div class="field"><label>Description / tags</label><input id="i-desc" placeholder="optional" /></div>
      <div class="card-actions"><button class="btn primary" id="i-save">Save encrypted</button></div>
    </div>
    <div id="l-items"></div>`;

  const lb = $("#l-layers");
  for (const l of d.layers) {
    const row = el("div", "card");
    row.innerHTML = `<h3>${l.letter} — ${escapeHtml(l.label)} <span class="pill off">${l.count}</span></h3>
      <div class="meta">${escapeHtml(l.slug)}</div>`;
    lb.appendChild(row);
  }
  renderItems(items);

  $("#i-save").addEventListener("click", async () => {
    try {
      const r = await api.post("/api/items", {
        kind: $("#i-kind").value, name: $("#i-name").value.trim(),
        value: $("#i-value").value, description: $("#i-desc").value.trim(),
      });
      toast("Saved as " + r.code);
      panelLayers();
    } catch (e) { toast(e.message, "err"); }
  });
}

function renderItems(items) {
  const box = $("#l-items");
  if (!items.length) { box.innerHTML = "<p class='muted small'>Nothing stored yet.</p>"; return; }
  box.innerHTML = "";
  for (const it of items) {
    const card = el("div", "card");
    card.innerHTML = `<h3><span class="pill ok">${escapeHtml(it.code)}</span> ${escapeHtml(it.name)}
        <span class="pill off">${escapeHtml(it.kind)}</span></h3>
      <div class="meta">${escapeHtml(it.value)} ${it.description ? "· " + escapeHtml(it.description) : ""}</div>`;
    const actions = el("div", "card-actions");
    const del = el("button", "btn small danger", "Delete");
    del.addEventListener("click", async () => {
      if (!confirm("Delete " + it.code + " (" + it.name + ")?")) return;
      await api.del("/api/items/" + it.code);
      toast("Deleted " + it.code);
      panelLayers();
    });
    actions.appendChild(del);
    card.appendChild(actions);
    box.appendChild(card);
  }
}

// ---- Memory ----
async function panelMemory() {
  openDrawer("Memory");
  const c = $("#drawer-content");
  const d = await api.get("/api/memory");
  c.innerHTML = `
    <div class="card"><h3>Long-term memory</h3>
      <div class="meta">Facts the assistant recalls automatically across chats. Pin important ones.</div>
      <div class="field"><label>New memory</label><textarea id="mem-text" rows="2" placeholder="e.g. Owner prefers agnes-3-flash on bynara router"></textarea></div>
      <div class="row">
        <div class="field"><label>Tags</label><input id="mem-tags" placeholder="llm,preferences" /></div>
        <div class="field"><label>Importance (1-5)</label><input id="mem-imp" type="number" min="1" max="5" value="3" /></div>
      </div>
      <label class="muted small"><input type="checkbox" id="mem-pin" style="width:auto"> Pin</label>
      <div class="card-actions"><button class="btn primary" id="mem-save">Remember</button></div>
    </div>
    <div id="mem-list"></div>`;
  renderMemories(d.memories || []);
  $("#mem-save").addEventListener("click", async () => {
    try {
      await api.post("/api/memory", {
        text: $("#mem-text").value.trim(), tags: $("#mem-tags").value.trim(),
        importance: parseInt($("#mem-imp").value, 10), pinned: $("#mem-pin").checked,
      });
      toast("Remembered");
      panelMemory();
    } catch (e) { toast(e.message, "err"); }
  });
}

function renderMemories(list) {
  const box = $("#mem-list");
  if (!list.length) { box.innerHTML = "<p class='muted small'>No memories yet.</p>"; return; }
  box.innerHTML = "";
  for (const m of list) {
    const card = el("div", "card");
    card.innerHTML = `<h3>${m.pinned ? "📌 " : ""}${escapeHtml(m.text)}</h3>
      <div class="meta">importance ${m.importance}${m.tags ? " · " + escapeHtml(m.tags) : ""}</div>`;
    const actions = el("div", "card-actions");
    const pin = el("button", "btn small", m.pinned ? "Unpin" : "Pin");
    pin.addEventListener("click", async () => {
      await api.put("/api/memory/" + m.id, { pinned: !m.pinned });
      panelMemory();
    });
    const del = el("button", "btn small danger", "Forget");
    del.addEventListener("click", async () => {
      await api.del("/api/memory/" + m.id);
      toast("Forgotten");
      panelMemory();
    });
    actions.append(pin, del);
    card.appendChild(actions);
    box.appendChild(card);
  }
}

// ---- App MCP (external control) ----
async function panelAppMcp() {
  openDrawer("App MCP (external control)");
  const c = $("#drawer-content");
  const d = await api.get("/api/app-mcp/info");
  c.innerHTML = `
    <div class="card"><h3>🛰️ This app is an MCP server</h3>
      <div class="meta">Connect any external MCP client (including another AI assistant) to control this app — check keys, read/write layers, drive MCP servers and settings.</div>
      <div class="field"><label>SSE URL</label><input id="am-url" readonly value="${escapeAttr(d.sse_url)}" /></div>
      <div class="field"><label>Access token</label><input id="am-token" readonly value="${escapeAttr(d.token)}" /></div>
      <div class="hint">Use: <code>${escapeAttr(d.sse_url)}?token=&lt;token&gt;</code> — or send header <code>Authorization: Bearer &lt;token&gt;</code>.</div>
      <div class="card-actions">
        <button class="btn small" id="am-copy">Copy URL + token</button>
        <button class="btn small danger" id="am-regen">Regenerate token</button>
      </div>
    </div>
    <div class="card"><h3>Tools exposed (${d.tools.length})</h3>
      <div class="meta">${d.tools.map(escapeHtml).join(", ")}</div></div>`;
  $("#am-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(d.sse_url + "?token=" + d.token);
    toast("Copied to clipboard");
  });
  $("#am-regen").addEventListener("click", async () => {
    if (!confirm("Regenerate the MCP token? Existing clients will need the new one.")) return;
    await api.post("/api/app-mcp/token", { regenerate: true });
    toast("Token regenerated");
    panelAppMcp();
  });
}

// ---- AI model settings ----
async function panelSettings() {
  openDrawer("AI Model & API");
  const c = $("#drawer-content");
  c.innerHTML = "<p class='muted'>Loading…</p>";
  const d = await api.get("/api/llm");
  c.innerHTML = `
    <div class="card">
      <h3>Language model</h3>
      <div class="meta">This key powers the assistant itself. It is stored encrypted on this machine.</div>
      <div class="field"><label>API key ${d.api_key_set ? "· " + escapeHtml(d.api_key_masked) : ""}</label>
        <input id="s-key" type="password" placeholder="${d.api_key_set ? "Leave blank to keep current key" : "sk-..."}" /></div>
      <div class="field"><label>Base URL</label>
        <input id="s-url" value="${escapeAttr(d.base_url)}" placeholder="https://api.openai.com/v1" /></div>
      <div class="field"><label>Model</label>
        <input id="s-model" value="${escapeAttr(d.model)}" placeholder="gpt-4o-mini" /></div>
      <div class="row">
        <div class="field"><label>Rate limit / min</label>
          <input id="s-rate" type="number" min="1" max="600" value="${d.rate_limit}" /></div>
        <div class="field"><label>Temperature</label>
          <input id="s-temp" type="number" step="0.1" min="0" max="2" value="${d.temperature}" /></div>
        <div class="field"><label>Max tool steps</label>
          <input id="s-steps" type="number" min="1" max="60" value="${d.max_steps}" /></div>
      </div>
      <div class="hint">The per-minute limit throttles outgoing requests so your API key doesn't get blocked. Current usage: ${d.rate_status.used_last_minute}/${d.rate_status.limit_per_minute}.</div>
      <div class="card-actions">
        <button class="btn primary" id="s-save">Save</button>
        <button class="btn" id="s-test">Test connection</button>
      </div>
    </div>
    <div class="card">
      <h3>Change app password</h3>
      <div class="field"><label>Current password</label><input id="p-cur" type="password" /></div>
      <div class="field"><label>New password</label><input id="p-new" type="password" /></div>
      <div class="card-actions"><button class="btn" id="p-save">Update password</button></div>
    </div>`;

  $("#s-save").addEventListener("click", async () => {
    const body = {
      base_url: $("#s-url").value.trim(),
      model: $("#s-model").value.trim(),
      rate_limit: parseInt($("#s-rate").value, 10),
      temperature: parseFloat($("#s-temp").value),
      max_steps: parseInt($("#s-steps").value, 10),
    };
    const key = $("#s-key").value.trim();
    if (key) body.api_key = key;
    try {
      await api.put("/api/llm", body);
      toast("Settings saved");
      refreshLlmBadge();
      panelSettings();
    } catch (e) { toast(e.message, "err"); }
  });

  $("#s-test").addEventListener("click", async () => {
    const body = { base_url: $("#s-url").value.trim(), model: $("#s-model").value.trim() };
    const key = $("#s-key").value.trim();
    if (key) body.api_key = key;
    toast("Testing…");
    try {
      const r = await api.post("/api/llm/test", body);
      toast(r.ok ? "✓ " + r.message : "✗ " + (r.error || "Failed"), r.ok ? "ok" : "err");
    } catch (e) { toast(e.message, "err"); }
  });

  $("#p-save").addEventListener("click", async () => {
    try {
      await api.post("/api/auth/password", {
        current_password: $("#p-cur").value,
        new_password: $("#p-new").value,
      });
      toast("Password updated");
      $("#p-cur").value = ""; $("#p-new").value = "";
    } catch (e) { toast(e.message, "err"); }
  });
}

function escapeAttr(s) { return String(s == null ? "" : s).replace(/"/g, "&quot;"); }

// ---- Credentials ----
async function panelCredentials() {
  openDrawer("Credentials vault");
  const c = $("#drawer-content");
  const d = await api.get("/api/credentials");
  c.innerHTML = `
    <div class="field"><label>Name</label><input id="c-name" placeholder="openai-main" /></div>
    <div class="field"><label>Value (API key / token / password)</label><input id="c-value" type="password" placeholder="sk-..." /></div>
    <div class="row">
      <div class="field"><label>Kind</label><input id="c-kind" value="api_key" /></div>
      <div class="field"><label>Description</label><input id="c-desc" placeholder="optional" /></div>
    </div>
    <button class="btn primary block" id="c-save">Save encrypted</button>
    <hr class="sep" />
    <div id="c-list"></div>`;
  renderCredList(d.credentials || []);

  $("#c-save").addEventListener("click", async () => {
    try {
      await api.post("/api/credentials", {
        name: $("#c-name").value.trim(),
        value: $("#c-value").value,
        kind: $("#c-kind").value.trim() || "api_key",
        description: $("#c-desc").value.trim(),
      });
      toast("Saved encrypted");
      panelCredentials();
    } catch (e) { toast(e.message, "err"); }
  });
}

function renderCredList(list) {
  const box = $("#c-list");
  if (!list.length) { box.innerHTML = "<p class='muted small'>No credentials stored yet.</p>"; return; }
  box.innerHTML = "";
  for (const cred of list) {
    const card = el("div", "card");
    card.innerHTML = `<h3>${escapeHtml(cred.name)} <span class="pill off">${escapeHtml(cred.kind)}</span></h3>
      <div class="meta">${escapeHtml(cred.description || "—")}</div>`;
    const actions = el("div", "card-actions");
    const del = el("button", "btn small danger", "Delete");
    del.addEventListener("click", async () => {
      if (!confirm("Delete credential '" + cred.name + "'?")) return;
      await api.del("/api/credentials/" + cred.id);
      toast("Deleted");
      panelCredentials();
    });
    actions.appendChild(del);
    card.appendChild(actions);
    box.appendChild(card);
  }
}

// ---- MCP ----
async function panelMcp() {
  openDrawer("MCP servers");
  const c = $("#drawer-content");
  const d = await api.get("/api/mcp");
  c.innerHTML = `
    <div class="card"><h3>Add / update MCP server</h3>
      <div class="meta">stdio = local command. sse = remote URL. Secrets are encrypted.</div>
      <div class="field"><label>Name</label><input id="m-name" placeholder="filesystem" /></div>
      <div class="field"><label>Transport</label>
        <select id="m-transport"><option value="stdio">stdio (local command)</option><option value="sse">sse (remote URL)</option></select></div>
      <div id="m-stdio">
        <div class="field"><label>Command</label><input id="m-command" placeholder="npx" /></div>
        <div class="field"><label>Args (space separated)</label><input id="m-args" placeholder="-y @modelcontextprotocol/server-filesystem /tmp" /></div>
        <div class="field"><label>Env (KEY=VALUE per line)</label><textarea id="m-env" rows="2" placeholder="API_TOKEN=..."></textarea></div>
      </div>
      <div id="m-sse" class="hidden">
        <div class="field"><label>URL</label><input id="m-url" placeholder="https://host/sse" /></div>
        <div class="field"><label>Headers (Key: Value per line)</label><textarea id="m-headers" rows="2" placeholder="Authorization: Bearer ..."></textarea></div>
      </div>
      <div class="card-actions"><button class="btn primary" id="m-save">Save server</button></div>
    </div>
    <div id="m-list"></div>`;

  $("#m-transport").addEventListener("change", (e) => {
    const stdio = e.target.value === "stdio";
    $("#m-stdio").classList.toggle("hidden", !stdio);
    $("#m-sse").classList.toggle("hidden", stdio);
  });

  $("#m-save").addEventListener("click", async () => {
    const transport = $("#m-transport").value;
    const body = { name: $("#m-name").value.trim(), transport };
    if (transport === "stdio") {
      body.command = $("#m-command").value.trim();
      body.args = $("#m-args").value.trim() ? $("#m-args").value.trim().split(/\s+/) : [];
      body.env = parseLines($("#m-env").value, "=");
    } else {
      body.url = $("#m-url").value.trim();
      body.headers = parseLines($("#m-headers").value, ":");
    }
    try {
      await api.post("/api/mcp", body);
      toast("MCP server saved");
      panelMcp();
    } catch (e) { toast(e.message, "err"); }
  });

  renderMcpList(d.servers || []);
}

function parseLines(text, sep) {
  const out = {};
  for (const line of (text || "").split("\n")) {
    const i = line.indexOf(sep);
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

function renderMcpList(servers) {
  const box = $("#m-list");
  if (!servers.length) { box.innerHTML = "<p class='muted small'>No MCP servers configured.</p>"; return; }
  box.innerHTML = "";
  for (const s of servers) {
    const statusClass = s.status === "connected" ? "ok" : s.status === "error" ? "err" : "off";
    const card = el("div", "card");
    card.innerHTML = `<h3>${escapeHtml(s.name)}
        <span class="pill off">${escapeHtml(s.transport)}</span>
        <span class="pill ${statusClass}">${escapeHtml(s.status)}</span></h3>
      <div class="meta">${s.tool_count} tool(s)${s.error ? " · " + escapeHtml(s.error) : ""}</div>`;
    const actions = el("div", "card-actions");
    const connect = el("button", "btn small", s.status === "connected" ? "Reconnect" : "Connect");
    connect.addEventListener("click", async () => {
      toast("Connecting…");
      try {
        const r = await api.post("/api/mcp/" + s.id + "/connect");
        toast(r.ok ? "Connected (" + r.tools.length + " tools)" : "Failed: " + (r.error || ""), r.ok ? "ok" : "err");
        panelMcp();
      } catch (e) { toast(e.message, "err"); }
    });
    const disc = el("button", "btn small ghost", "Disconnect");
    disc.addEventListener("click", async () => { await api.post("/api/mcp/" + s.id + "/disconnect"); panelMcp(); });
    const del = el("button", "btn small danger", "Delete");
    del.addEventListener("click", async () => {
      if (!confirm("Delete MCP server '" + s.name + "'?")) return;
      await api.del("/api/mcp/" + s.id);
      toast("Deleted");
      panelMcp();
    });
    actions.append(connect, disc, del);
    card.appendChild(actions);
    box.appendChild(card);
  }
}

// ---- Security scanner ----
async function panelSecurity() {
  openDrawer("Security scanner");
  const c = $("#drawer-content");
  c.innerHTML = `
    <div class="card"><h3>Scan code or text</h3>
      <div class="meta">Paste a snippet, config, or text. Nothing is saved unless you ask.</div>
      <div class="field"><label>Code / text</label>
        <textarea id="sec-code" rows="8" placeholder="Paste code, a config, or a snippet…"></textarea></div>
      <div class="card-actions"><button class="btn primary" id="sec-run">Scan</button></div>
    </div>
    <div id="sec-out"></div>`;
  $("#sec-run").addEventListener("click", async () => {
    const code = $("#sec-code").value;
    if (!code.trim()) return;
    const r = await api.post("/api/scan", { code });
    const out = $("#sec-out");
    if (!r.findings.length) { out.innerHTML = "<p class='muted small' style='margin-top:14px'>✓ No issues found.</p>"; return; }
    out.innerHTML = `<hr class="sep" /><h3>Risk: <span class="pill ${r.risk_level === "critical" || r.risk_level === "high" ? "err" : "off"}">${r.risk_level}</span></h3>`;
    for (const f of r.findings) {
      const card = el("div", "card");
      card.innerHTML = `<h3>${escapeHtml(f.category)} <span class="pill ${f.severity === "critical" || f.severity === "high" ? "err" : "off"}">${f.severity}</span></h3>
        <div class="meta">Line ${f.line}: ${escapeHtml(f.message)}</div>
        <pre class="tool" style="margin-top:8px">${escapeHtml(f.snippet)}</pre>`;
      out.appendChild(card);
    }
  });
}

// ---------------------------------------------------------------------------
// Badges
// ---------------------------------------------------------------------------
async function refreshLlmBadge() {
  try {
    const d = await api.get("/api/llm");
    const b = $("#llm-badge");
    if (d.configured) { b.textContent = "● AI ready · " + d.model; b.className = "badge ok"; }
    else { b.textContent = "● AI not configured"; b.className = "badge warn"; }
    updateRateBadge(d.rate_status);
  } catch (_) {}
}

function updateRateBadge(r) {
  if (!r) return;
  const b = $("#rate-badge");
  b.textContent = `limit ${r.used_last_minute}/${r.limit_per_minute} per min · ${r.remaining} left`;
}

async function refreshRate() {
  try { updateRateBadge(await api.get("/api/llm/rate")); } catch (_) {}
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function boot() {
  await loadSessions();
  await refreshLlmBadge();
  setInterval(refreshRate, 15000);
}

(async function init() {
  try {
    const s = await api.get("/api/auth/status");
    if (s.authenticated) { showApp(); await boot(); }
    else showLock();
  } catch (_) { showLock(); }
})();
