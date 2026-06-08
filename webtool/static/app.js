"use strict";

const $ = (id) => document.getElementById(id);

let activeTab = "path";
let currentJobId = null;
let pollTimer = null;
let allFindings = [];
let confFilter = "all";

// --- tab switching ---
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    activeTab = btn.dataset.tab;
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab-panel").forEach((p) =>
      p.classList.toggle("active", p.dataset.panel === activeTab)
    );
  });
});

// --- file upload UX ---
const dropzone = $("dropzone");
$("browse").addEventListener("click", () => $("file").click());
$("file").addEventListener("change", () => {
  if ($("file").files.length) $("filename").textContent = $("file").files[0].name;
});
["dragover", "dragenter"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add("drag"); })
);
["dragleave", "drop"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove("drag"); })
);
dropzone.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) {
    $("file").files = e.dataTransfer.files;
    $("filename").textContent = e.dataTransfer.files[0].name;
  }
});

// --- options ---
function readOptions() {
  return {
    applyExcludes: $("applyExcludes").checked,
    applyFilters: $("applyFilters").checked,
    applyFeedback: $("applyFeedback").checked,
    aggressiveRecall: $("aggressiveRecall").checked,
    withValidation: $("withValidation").checked,
    minEntropy: parseFloat($("minEntropy").value) || 0,
  };
}

// --- scan ---
$("scanBtn").addEventListener("click", startScan);

async function startScan() {
  const opts = readOptions();
  resetUI();
  $("scanBtn").disabled = true;

  try {
    let resp;
    if (activeTab === "zip") {
      if (!$("file").files.length) throw new Error("Choose a zip file first.");
      const fd = new FormData();
      fd.append("file", $("file").files[0]);
      Object.entries(opts).forEach(([k, v]) => fd.append(k, v));
      resp = await fetch("/api/scan", { method: "POST", body: fd });
    } else {
      const body = { ...opts };
      if (activeTab === "path") body.path = $("path").value.trim();
      if (activeTab === "git") body.gitUrl = $("gitUrl").value.trim();
      resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    }
    if (!resp.ok) throw new Error(await resp.text());
    const { id } = await resp.json();
    currentJobId = id;
    $("progressCard").classList.remove("hidden");
    poll();
  } catch (err) {
    showError(err.message || String(err));
    $("scanBtn").disabled = false;
  }
}

function poll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    try {
      const resp = await fetch("/api/scan/" + currentJobId);
      if (!resp.ok) throw new Error(await resp.text());
      const job = await resp.json();
      $("barFill").style.width = job.progress + "%";
      $("progressMsg").textContent = job.message || job.status;
      $("progressSub").textContent = job.source || "";
      if (job.status === "done") {
        $("progressCard").classList.add("hidden");
        $("scanBtn").disabled = false;
        renderResults(job.result);
      } else if (job.status === "error") {
        $("progressCard").classList.add("hidden");
        $("scanBtn").disabled = false;
        showError(job.error);
      } else {
        poll();
      }
    } catch (err) {
      showError(err.message || String(err));
      $("scanBtn").disabled = false;
    }
  }, 700);
}

function resetUI() {
  $("errorCard").classList.add("hidden");
  $("results").classList.add("hidden");
  $("progressCard").classList.add("hidden");
  $("barFill").style.width = "0%";
}

function showError(msg) {
  $("errorCard").textContent = "Error: " + msg;
  $("errorCard").classList.remove("hidden");
}

// --- results ---
function renderResults(res) {
  allFindings = res.findings || [];
  const surfaced = res.surfaced || 0;
  const high = (res.byConfidence && res.byConfidence.high) || 0;
  const medium = (res.byConfidence && res.byConfidence.medium) || 0;

  $("stats").innerHTML = `
    ${stat("Files scanned", res.filesIngested, "")}
    ${stat("Excluded", res.filesExcluded, "")}
    ${stat("Raw findings", res.rawFindings, "")}
    ${stat("Suppressed (noise)", res.suppressed, "good")}
    ${stat("Surfaced", surfaced, surfaced > 0 ? "danger" : "good")}
    ${stat("High / Medium", high + " / " + medium, high > 0 ? "danger" : "warn")}
  `;
  $("results").classList.remove("hidden");
  applyFilters();
}

function stat(lbl, num, cls) {
  return `<div class="stat ${cls}"><span class="num">${num}</span><span class="lbl">${lbl}</span></div>`;
}

document.querySelectorAll(".chip").forEach((c) =>
  c.addEventListener("click", () => {
    confFilter = c.dataset.conf;
    document.querySelectorAll(".chip").forEach((x) => x.classList.toggle("active", x === c));
    applyFilters();
  })
);
$("search").addEventListener("input", applyFilters);
$("showSuppressed").addEventListener("change", applyFilters);
$("revealValues").addEventListener("change", applyFilters);

function applyFilters() {
  const q = $("search").value.toLowerCase();
  const showSup = $("showSuppressed").checked;
  const rows = allFindings.filter((f) => {
    if (f.suppressed && !showSup) return false;
    if (confFilter !== "all" && f.confidence !== confFilter && !f.suppressed) return false;
    if (confFilter !== "all" && f.suppressed) return false;
    if (q) {
      const hay = (f.source + " " + f.ruleName + " " + f.value + " " + (f.rawValue || "") + " " + (f.filterReason || "")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const body = $("resultsBody");
  body.innerHTML = "";
  rows.forEach((f) => body.appendChild(renderRow(f)));
  $("emptyState").classList.toggle("hidden", rows.length > 0);
}

function renderRow(f) {
  const tr = document.createElement("tr");
  if (f.suppressed) tr.classList.add("suppressed");
  const fpLabel = f.learned ? "Unmark FP" : "Mark FP";
  const reveal = $("revealValues").checked;
  const shown = reveal ? (f.rawValue || f.value) : f.value;
  const valTitle = reveal ? "Click to copy" : "Enable 'Reveal values' to see the full secret";
  tr.innerHTML = `
    <td><span class="badge ${f.confidence}">${f.confidence}</span></td>
    <td>${f.severity || "-"}</td>
    <td>${escapeHtml(f.ruleName)}</td>
    <td><span class="loc">${escapeHtml(f.source)}:${f.startLine}</span></td>
    <td><span class="val${reveal ? " revealed" : ""}" title="${escapeHtml(valTitle)}">${escapeHtml(shown)}</span></td>
    <td><span class="why">${escapeHtml(f.filterReason || "")}</span></td>
    <td></td>
  `;
  if (reveal) {
    const valEl = tr.querySelector(".val");
    valEl.addEventListener("click", () => copyValue(f.rawValue || f.value, valEl));
  }
  const btn = document.createElement("button");
  btn.className = "fp" + (f.learned ? " undo" : "");
  btn.textContent = fpLabel;
  btn.addEventListener("click", () => toggleFP(f, btn));
  tr.lastElementChild.appendChild(btn);
  return tr;
}

async function toggleFP(f, btn) {
  btn.disabled = true;
  try {
    const resp = await fetch("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jobId: currentJobId, findingId: f.id, undo: !!f.learned }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    f.learned = !f.learned;
    f.suppressed = f.learned;
    if (f.learned) f.filterReason = "marked as false positive";
    applyFilters();
  } catch (err) {
    showError(err.message || String(err));
  } finally {
    btn.disabled = false;
  }
}

// --- exports ---
$("exportJson").addEventListener("click", () => {
  if (currentJobId) window.open("/api/export/" + currentJobId + "?format=json", "_blank");
});
$("exportCsv").addEventListener("click", () => {
  if (currentJobId) window.open("/api/export/" + currentJobId + "?format=csv", "_blank");
});

function copyValue(text, el) {
  navigator.clipboard?.writeText(text).then(() => {
    const prev = el.textContent;
    el.textContent = "copied!";
    setTimeout(() => { el.textContent = prev; }, 800);
  }).catch(() => {});
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
