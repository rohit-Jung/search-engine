const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function severityColor(sev) {
  switch (sev) {
    case "CRITICAL":
      return "#e63329";
    case "HIGH":
      return "#d9534f";
    case "MEDIUM":
      return "#f0ad4e";
    case "LOW":
      return "#5cb85c";
    default:
      return "#888888";
  }
}

function fmtDate(t) {
  if (!t) return "";
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString();
}

async function getJSON(url) {
  const res = await fetch(url);
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.error || res.statusText);
  return data;
}

// build a single card DOM element — no innerHTML on the whole list
function buildCard(r, delay) {
  const sev = (r.severity || "").toUpperCase();
  const color = severityColor(sev);
  const link = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(r.id || r.cve_id)}`;
  const cvss = typeof r.cvss === "number" ? r.cvss.toFixed(1) : "";

  const card = document.createElement("div");
  card.className = "card";
  card.style.borderColor = color;
  card.innerHTML = `
          <div class="cardHeader">
            <div>
              <p class="cveId">
                <a href="${link}" target="_blank" rel="noreferrer" style="color:inherit;text-decoration:none">
                  ${esc(r.id || r.cve_id || "")}
                </a>
              </p>
              <p class="libLine">${esc((r.library || r.product || "").trim())}${r.version ? " " + esc(r.version) : ""}</p>
            </div>
            <div class="badge" style="background:${color}">${esc(sev)}</div>
          </div>
          <p class="desc">${esc(r.description || "")}</p>
          <div class="facts">
            <div><p class="factLabel">CVSS Score</p><p class="factValue"><b>${esc(cvss)}</b></p></div>
            <div><p class="factLabel">Attack Vector</p><p class="factValue">${esc(r.attackVector || "")}</p></div>
            <div><p class="factLabel">Published</p><p class="factValue">${esc(fmtDate(r.published))}</p></div>
            <div><p class="factLabel">CWE ID</p><p class="factValue" style="font-family:Monaco,Menlo,monospace">${esc(r.cwe || "")}</p></div>
            <div><p class="factLabel">Weakness</p><p class="factValue" style="color:#666">${esc(r.cweName || "")}</p></div>
            <div><p class="factLabel">Source</p><p class="factValue" style="font-family:Monaco,Menlo,monospace">${esc(r._source || "")}</p></div>
          </div>
        `;

  // fade in after a short stagger delay — done via raf, not css animation on re-render
  setTimeout(() => card.classList.add("visible"), delay);
  return card;
}

// append cards one by one — never touch existing dom nodes
function progressiveReveal(container, rows) {
  container.innerHTML = "";
  rows.forEach((r, i) => {
    const card = buildCard(r, i * 80);
    container.appendChild(card);
  });
}

function setMeta(text) {
  $("meta").textContent = text || "";
}
function setError(text) {
  $("error").textContent = text || "";
}

function severityFromCVSS(cvss) {
  if (typeof cvss !== "number") return "";
  if (cvss >= 9.0) return "CRITICAL";
  if (cvss >= 7.0) return "HIGH";
  if (cvss >= 4.0) return "MEDIUM";
  if (cvss > 0) return "LOW";
  return "";
}

async function run() {
  setError("");
  $("baseline-error").innerHTML = "";
  $("search").disabled = true;
  try {
    const library = $("library").value.trim();
    const severity = $("severity").value;
    const top = $("topN").value;

    const [ranked, baseline] = await Promise.all([
      getJSON(
        `/api/search?q=${encodeURIComponent(library)}&severity=${encodeURIComponent(severity)}&top=${top}`,
      ),
      getJSON(
        `/api/baseline?q=${encodeURIComponent(library)}&severity=${encodeURIComponent(severity)}&top=${top}&order=published&field=all`,
      ).catch((e) => ({ _err: e.message, meta: {}, results: [] })),
    ]);

    const rankedRows = (ranked.results || []).map((r) => ({
      ...r,
      _source: "engine",
    }));
    const baseRows = (baseline.results || []).map((r) => ({
      id: r.cve_id,
      library: r.product || "",
      vendor: r.vendor || "",
      version: r.version || "",
      cvss: r.cvss,
      severity: severityFromCVSS(r.cvss),
      cwe: "",
      cweName: "",
      description: r.description,
      published: r.published,
      attackVector: "",
      _source: "sql",
    }));

    $("count-ranked").textContent = `${rankedRows.length} results`;

    if (baseline._err) {
      $("count-baseline").textContent = "error";
      $("baseline-error").innerHTML =
        `<div class="sql-error-banner">&#9888; SQL baseline error: ${esc(baseline._err)}</div>`;
    } else {
      $("count-baseline").textContent = `${baseRows.length} results`;
    }

    progressiveReveal($("ranked"), rankedRows);
    progressiveReveal($("baseline"), baseRows);

    const msRanked = ranked.meta?.elapsed_ms ?? "?";
    const msBase = baseline._err ? `err` : (baseline.meta?.elapsed_ms ?? "?");
    setMeta(`ENGINE ${msRanked}ms · SQL ${msBase}`);
  } catch (e) {
    setError(e.message || String(e));
  } finally {
    $("search").disabled = false;
  }
}

async function health() {
  setError("");
  $("health").disabled = true;
  try {
    const h = await getJSON("/api/health");
    const engine = h.engine || {};
    setMeta(
      `OK · CORPUS ${engine.corpus_n ?? "?"} · TERMS ${engine.idf_terms ?? "?"} · DB ${h.db?.enabled ? "ON" : "OFF"}`,
    );
  } catch (e) {
    setError(e.message || String(e));
  } finally {
    $("health").disabled = false;
  }
}

$("search").addEventListener("click", run);
$("health").addEventListener("click", health);
$("library").addEventListener("keydown", (e) => {
  if (e.key === "Enter") run();
});

health();
run();
