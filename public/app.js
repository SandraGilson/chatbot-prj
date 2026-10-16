const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const HISTORY_KEY = "scamshield-history-v1";
let historyItems = [];
let toastTimer;

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2800);
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[ch]));
}
function renderMarkdown(value) {
  const escaped = escapeHtml(value);
  const lines = escaped.split(/\r?\n/);
  const out = [];
  let listType = "";
  let inTable = false;

  const closeList = () => {
    if (listType) out.push(`</${listType}>`);
    listType = "";
  };
  const closeTable = () => {
    if (inTable) out.push("</tbody></table>");
    inTable = false;
  };
  const inline = text => text
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");

  for (const line of lines) {
    const trimmed = line.trim();
    const cells = trimmed.startsWith("|") && trimmed.endsWith("|")
      ? trimmed.slice(1, -1).split("|").map(cell => cell.trim())
      : null;

    if (cells && cells.every(cell => /^:?-{3,}:?$/.test(cell))) continue;

    if (cells) {
      closeList();
      if (!inTable) {
        out.push("<table><tbody>");
        inTable = true;
      }
      out.push("<tr>" + cells.map(cell => `<td>${inline(cell)}</td>`).join("") + "</tr>");
      continue;
    }

    closeTable();

    if (!trimmed) {
      closeList();
      continue;
    }

    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/);
    const bullet = trimmed.match(/^[-*]\s+(.+)$/);
    const numbered = trimmed.match(/^\d+[.)]\s+(.+)$/);

    if (heading) {
      closeList();
      const level = heading[1].length;
      out.push(`<h${level + 2}>${inline(heading[2])}</h${level + 2}>`);
    } else if (bullet || numbered) {
      const type = bullet ? "ul" : "ol";
      if (listType !== type) {
        closeList();
        listType = type;
        out.push(`<${type}>`);
      }
      out.push(`<li>${inline((bullet || numbered)[1])}</li>`);
    } else {
      closeList();
      out.push(`<p>${inline(trimmed)}</p>`);
    }
  }

  closeList();
  closeTable();
  return out.join("");
}
function riskLabel(risk) {
  return ({high:"High risk",medium:"Medium risk",low:"Low indicators",inconclusive:"Inconclusive"})[risk] || "Inconclusive";
}
function riskClass(risk) { return `risk-${["high","medium","low","inconclusive"].includes(risk) ? risk : "inconclusive"}`; }
function setLoading(button, loading, label) {
  button.disabled = loading;
  if (loading) { button.dataset.originalText = button.innerHTML; button.textContent = label || "CheckingÃ¢â‚¬Â¦"; }
  else if (button.dataset.originalText) { button.innerHTML = button.dataset.originalText; delete button.dataset.originalText; }
}
async function api(path, body) {
  const response = await fetch(path, {
    method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function renderResult(target, data, original, type) {
  const targetEl = $(target);
  const indicators = Array.isArray(data.indicators) && data.indicators.length
    ? data.indicators.map(item => `<li>${escapeHtml(typeof item === "string" ? item : item.label)}</li>`).join("")
    : "<li>No obvious indicators were detected by these basic checks.</li>";
  const steps = (data.nextSteps || []).map(s => `<li>${escapeHtml(s)}</li>`).join("");
  const score = Number.isFinite(data.score) ? Math.max(0, Math.min(100, data.score)) : 0;
  targetEl.innerHTML = `
    <div class="result-top"><div><h3>${escapeHtml(data.title || "Analysis result")}</h3><p>${escapeHtml(data.summary || "Review the details below and verify independently.")}</p></div><span class="risk-pill ${riskClass(data.risk)}">${escapeHtml(riskLabel(data.risk))}</span></div>
    <div class="score-track" aria-label="Heuristic indicator score"><div class="score-fill" style="width:${score}%"></div></div>
    <div class="result-cols"><div><h4>Warning signs</h4><ul>${indicators}</ul></div><div><h4>Recommended next steps</h4><ul>${steps || "<li>Verify the request independently.</li>"}</ul></div></div>
    <div class="result-footer"><span>${escapeHtml(data.confidence || "Screening only Ã¢â‚¬â€ not a guarantee")}</span><button class="btn btn-secondary btn-small" type="button" data-copy-result>Copy report</button></div>`;
  targetEl.classList.remove("hidden");
  targetEl.querySelector("[data-copy-result]").addEventListener("click", () => {
    const report = `${type.toUpperCase()} CHECK\nInput: ${original}\nResult: ${riskLabel(data.risk)}\nScore: ${score}/100 (heuristic only)\nSummary: ${data.summary}\nWarning signs: ${(data.indicators || []).map(x => typeof x === "string" ? x : x.label).join("; ") || "None found"}\nNext steps: ${(data.nextSteps || []).join("; ")}\nNote: This result does not prove whether content is safe.`;
    copyText(report);
  });
}
function addHistory(type, input, result) {
  historyItems.unshift({ id: `${Date.now()}-${Math.random().toString(36).slice(2,7)}`, type, input: input.slice(0,500), risk: result.risk || "inconclusive", score: Number(result.score) || 0, summary: result.summary || "", time: new Date().toISOString() });
  historyItems = historyItems.slice(0, 30);
  saveHistory(); renderHistory();
}
function saveHistory() {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(historyItems)); } catch { showToast("Browser storage is unavailable; history may not persist."); }
}
function loadHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    historyItems = Array.isArray(parsed) ? parsed.filter(x => x && x.id && x.type && x.input) : [];
  } catch { historyItems = []; }
  renderHistory();
}
function renderHistory() {
  const el = $("#historyList");
  if (!historyItems.length) { el.innerHTML = '<div class="empty-history">Your recent checks will appear here.</div>'; return; }
  el.innerHTML = historyItems.map(item => {
    const date = new Date(item.time);
    return `<div class="history-item"><span class="history-type">${item.type === "url" ? "Ã¢â€ â€”" : "Ã¢â€“Â¤"}</span><div class="history-detail"><strong title="${escapeHtml(item.input)}">${escapeHtml(item.input.replace(/\s+/g," "))}</strong><small>${escapeHtml(date.toLocaleString())} Ã‚Â· ${item.type === "url" ? "URL check" : "Message check"}</small></div><span class="risk-pill ${riskClass(item.risk)}">${escapeHtml(riskLabel(item.risk))}</span><button type="button" data-delete-history="${escapeHtml(item.id)}" aria-label="Delete this history item" title="Delete">Ãƒâ€”</button></div>`;
  }).join("");
  $$("[data-delete-history]").forEach(btn => btn.addEventListener("click", () => {
    historyItems = historyItems.filter(x => x.id !== btn.dataset.deleteHistory); saveHistory(); renderHistory();
  }));
}
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
    else {
      const area = document.createElement("textarea"); area.value = text; area.style.position = "fixed"; area.style.opacity = "0";
      document.body.appendChild(area); area.select();
      const ok = document.execCommand("copy"); area.remove();
      if (!ok) throw new Error("Copy unavailable");
    }
    showToast("Copied to clipboard.");
  } catch { showToast("Copy failed. Please select and copy the text manually."); }
}
function switchTab(tab) {
  $$(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
  const map = {message:"#messagePanel",url:"#urlPanel",chat:"#chatPanel",tips:"#tipsPanel"};
  Object.entries(map).forEach(([key, selector]) => $(selector).classList.toggle("hidden", key !== tab));
}
$$(".tab").forEach(btn => btn.addEventListener("click", () => switchTab(btn.dataset.tab)));

$("#messageInput").addEventListener("input", () => $("#messageCount").textContent = `${$("#messageInput").value.length.toLocaleString()} / 10,000`);
$("#messageForm").addEventListener("submit", async event => {
  event.preventDefault();
  const input = $("#messageInput").value.trim();
  if (!input) { showToast("Please paste a message first."); $("#messageInput").focus(); return; }
  const btn = $("#analyseMessageBtn"); setLoading(btn, true, "AnalysingÃ¢â‚¬Â¦");
  try {
    const data = await api("/api/analyse", {text:input,type:"message"});
    renderResult("#messageResult", data, input, "message"); addHistory("message", input, data);
  } catch (err) { showToast(err.message || "Could not analyse the message."); }
  finally { setLoading(btn, false); }
});
$("#sampleMessageBtn").addEventListener("click", () => {
  $("#messageInput").value = "URGENT: Your bank account will be blocked today. Verify your details now and share the OTP sent to your phone to avoid suspension.";
  $("#messageInput").dispatchEvent(new Event("input")); $("#messageInput").focus();
});
$("#clearMessageBtn").addEventListener("click", () => { $("#messageInput").value = ""; $("#messageInput").dispatchEvent(new Event("input")); $("#messageResult").classList.add("hidden"); $("#messageInput").focus(); });
$("#urlForm").addEventListener("submit", async event => {
  event.preventDefault();
  const input = $("#urlInput").value.trim();
  if (!input) { showToast("Please enter a URL first."); return; }
  const btn = $("#analyseUrlBtn"); setLoading(btn, true, "CheckingÃ¢â‚¬Â¦");
  try {
    const data = await api("/api/analyse", {text:input,type:"url"});
    renderResult("#urlResult", data, input, "url"); addHistory("url", input, data);
  } catch (err) { showToast(err.message || "Could not check the URL."); }
  finally { setLoading(btn, false); }
});
$("#sampleUrlBtn").addEventListener("click", () => { $("#urlInput").value = "http://secure-account-verify.example.com/login"; $("#urlInput").focus(); });
$("#clearUrlBtn").addEventListener("click", () => { $("#urlInput").value = ""; $("#urlResult").classList.add("hidden"); $("#urlInput").focus(); });

function appendChat(role, message, small = "") {
  const row = document.createElement("div"); row.className = `chat-row ${role}`;
  const avatar = document.createElement("div"); avatar.className = "avatar"; avatar.textContent = role === "assistant" ? "S" : "Y";
  const bubble = document.createElement("div"); bubble.className = "bubble";
  const strong = document.createElement("strong"); strong.textContent = role === "assistant" ? "ScamShield" : "You";
  const p = document.createElement("p"); if (role === "assistant") p.innerHTML = renderMarkdown(message); else p.textContent = message;
  bubble.append(strong, p);
  if (small) { const meta = document.createElement("small"); meta.textContent = small; bubble.append(meta); }
  row.append(avatar, bubble); $("#chatMessages").append(row); $("#chatMessages").scrollTop = $("#chatMessages").scrollHeight;
  return row;
}
async function sendChat(message) {
  const trimmed = message.trim(); if (!trimmed) return;
  appendChat("user", trimmed); $("#chatInput").value = "";
  const btn = $("#sendChatBtn"); setLoading(btn, true, "ThinkingÃ¢â‚¬Â¦");
  const pending = appendChat("assistant", "Let me check the best guidance for this questionÃ¢â‚¬Â¦", "Please wait");
  try {
    const data = await api("/api/chat", {message:trimmed});
    const p = pending.querySelector("p"); p.textContent = data.answer || "I could not produce an answer. Please try again.";
    const small = pending.querySelector("small"); if (small) small.textContent = data.mode === "nvidia-nim" ? "AI-assisted guidance - verify important facts" : "Rule-based demo guidance Ã‚Â· not a guarantee";
  } catch (err) {
    pending.querySelector("p").textContent = err.message || "The service is temporarily unavailable. Please try again.";
    const small = pending.querySelector("small"); if (small) small.textContent = "Could not get an answer";
  } finally { setLoading(btn, false); $("#chatMessages").scrollTop = $("#chatMessages").scrollHeight; }
}
$("#chatForm").addEventListener("submit", event => { event.preventDefault(); sendChat($("#chatInput").value); });
$$("[data-question]").forEach(btn => btn.addEventListener("click", () => sendChat(btn.dataset.question)));
$("#clearHistoryBtn").addEventListener("click", () => {
  if (!historyItems.length) { showToast("History is already empty."); return; }
  historyItems = []; saveHistory(); renderHistory(); showToast("Recent checks cleared from this browser.");
});
$("#exportHistoryBtn").addEventListener("click", () => {
  if (!historyItems.length) { showToast("There is no history to export yet."); return; }
  const payload = { app:"ScamShield", exportedAt:new Date().toISOString(), note:"Screening results are heuristic and do not prove safety.", checks:historyItems };
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type:"application/json"});
  const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `scamshield-report-${new Date().toISOString().slice(0,10)}.json`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); showToast("Report exported.");
});
$("#themeToggle").addEventListener("click", () => {
  document.body.classList.toggle("dark");
  const isDark = document.body.classList.contains("dark");
  try { localStorage.setItem("scamshield-theme", isDark ? "dark" : "light"); } catch {}
  $("#themeToggle").setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
});
try { if (localStorage.getItem("scamshield-theme") === "dark") document.body.classList.add("dark"); } catch {}

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error("Service unavailable");
    $("#serviceStatus").textContent = data.nvidiaConfigured ? "AI connected" : "Demo mode";
    $(".status-dot").classList.toggle("online", true);
    $("#footerMode").textContent = data.nvidiaConfigured ? "NVIDIA AI enabled" : "Rule-based demo mode";
    $("#footerMode").title = data.message;
  } catch {
    $("#serviceStatus").textContent = "Server unavailable";
    $("#footerMode").textContent = "Start the Node.js server";
    $(".status-dot").classList.remove("online");
  }
}
loadHistory(); checkHealth();
