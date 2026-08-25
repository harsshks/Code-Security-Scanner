import { useState, useRef, useCallback, useEffect } from "react";

const API = "/api";
const POLL_MS = 2500;
const MAX_POLLS = 80; // ~3.3 min

// ── Severity config ───────────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { color: "text-purple-400", bg: "bg-purple-500/15 border-purple-500/40", bar: "bg-purple-500", dot: "bg-purple-500", order: 0 },
  HIGH:     { color: "text-red-400",    bg: "bg-red-500/15 border-red-500/40",       bar: "bg-red-500",    dot: "bg-red-500",    order: 1 },
  MEDIUM:   { color: "text-yellow-400", bg: "bg-yellow-500/15 border-yellow-500/40", bar: "bg-yellow-400", dot: "bg-yellow-400", order: 2 },
  LOW:      { color: "text-blue-400",   bg: "bg-blue-500/15 border-blue-500/40",     bar: "bg-blue-400",   dot: "bg-blue-400",   order: 3 },
  INFO:     { color: "text-gray-400",   bg: "bg-gray-500/15 border-gray-500/40",     bar: "bg-gray-400",   dot: "bg-gray-400",   order: 4 },
};

function SeverityBadge({ severity }) {
  const s = SEV[severity] || SEV.INFO;
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded border ${s.bg} ${s.color}`}>
      {severity}
    </span>
  );
}

// ── Score ring ────────────────────────────────────────────────────────────────
function ScoreRing({ score }) {
  const r = 44, circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 75 ? "#34d399" : score >= 50 ? "#facc15" : score >= 25 ? "#f97316" : "#ef4444";
  const label = score >= 75 ? "LOW RISK" : score >= 50 ? "MODERATE" : score >= 25 ? "HIGH RISK" : "CRITICAL";

  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative w-28 h-28">
        <svg width="112" height="112" className="-rotate-90 absolute inset-0">
          <circle cx="56" cy="56" r={r} fill="none" stroke="#1f2937" strokeWidth="10" />
          <circle cx="56" cy="56" r={r} fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 0.8s ease" }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>{score}</span>
          <span className="text-xs text-gray-500">/100</span>
        </div>
      </div>
      <span className="text-xs font-semibold tracking-widest" style={{ color }}>{label}</span>
    </div>
  );
}

// ── Summary counts row ────────────────────────────────────────────────────────
function SummaryBar({ summary }) {
  const items = [
    { key: "critical", label: "Critical", ...SEV.CRITICAL },
    { key: "high",     label: "High",     ...SEV.HIGH },
    { key: "medium",   label: "Medium",   ...SEV.MEDIUM },
    { key: "low",      label: "Low",      ...SEV.LOW },
  ];
  return (
    <div className="grid grid-cols-4 gap-2">
      {items.map(({ key, label, color, bg }) => (
        <div key={key} className={`rounded-lg border p-3 text-center ${bg}`}>
          <div className={`text-xl font-bold ${color}`}>{summary?.[key] ?? 0}</div>
          <div className="text-xs text-gray-400 mt-0.5">{label}</div>
        </div>
      ))}
    </div>
  );
}

// ── Finding card ──────────────────────────────────────────────────────────────
function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const s = SEV[f.severity] || SEV.INFO;
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden">
      <button
        className="w-full flex items-start gap-3 px-4 py-3 hover:bg-gray-800/40 transition-colors text-left"
        onClick={() => setOpen(p => !p)}
        aria-expanded={open}
      >
        <span className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={f.severity} />
            <span className="text-sm font-semibold text-gray-100">{f.type}</span>
            {f.cwe && <span className="text-xs text-gray-500">{f.cwe}</span>}
          </div>
          {f.file && (
            <p className="text-xs text-gray-500 mt-1 font-mono truncate">
              {f.file}{f.line ? `:${f.line}` : ""}
            </p>
          )}
          <p className="text-xs text-gray-500 mt-0.5">
            Confidence: {Math.round(f.confidence * 100)}%
            {f.language && ` · ${f.language}`}
          </p>
        </div>
        <span className="text-gray-600 text-xs flex-shrink-0 mt-1">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-gray-800 pt-3 flex flex-col gap-3">
          {f.codeSnippet && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">
                {f.file ? `${f.file}${f.line ? ` · Line ${f.line}` : ""}` : "Code"}
              </p>
              <pre className="bg-gray-950 text-red-300 text-xs rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-words font-mono border border-gray-800">
                {f.line ? `${f.line} | ` : ""}{f.codeSnippet}
              </pre>
            </div>
          )}
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Why this is dangerous</p>
            <p className="text-sm text-gray-300">{f.description}</p>
          </div>
          {f.impact && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Impact</p>
              <p className="text-sm text-orange-300">{f.impact}</p>
            </div>
          )}
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Recommended Fix</p>
            <p className="text-sm text-green-400">{f.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Scan history card ─────────────────────────────────────────────────────────
function HistoryCard({ scan, onOpen }) {
  const score = scan.securityScore ?? "—";
  const color = typeof score === "number"
    ? score >= 75 ? "#34d399" : score >= 50 ? "#facc15" : score >= 25 ? "#f97316" : "#ef4444"
    : "#6b7280";

  return (
    <div
      className="rounded-xl border border-gray-800 bg-gray-900 px-4 py-3 flex items-center gap-4 cursor-pointer hover:bg-gray-800/50 transition-colors"
      onClick={() => onOpen(scan.scanId)}
    >
      <div className="text-center w-12 flex-shrink-0">
        <span className="text-xl font-bold" style={{ color }}>{score}</span>
        <p className="text-xs text-gray-600">score</p>
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-200 truncate">
          {scan.repositoryName || scan.repositoryUrl || "Quick Scan"}
        </p>
        <p className="text-xs text-gray-500 mt-0.5">
          {new Date(scan.createdAt).toLocaleString()} ·{" "}
          {scan.status === "completed"
            ? `${scan.summary?.total ?? 0} findings`
            : scan.status}
        </p>
      </div>
      <div className="flex gap-2 flex-shrink-0 flex-wrap justify-end">
        {(scan.summary?.critical > 0) && (
          <span className="text-xs font-semibold text-purple-400">{scan.summary.critical} CRIT</span>
        )}
        {(scan.summary?.high > 0) && (
          <span className="text-xs font-semibold text-red-400">{scan.summary.high} HIGH</span>
        )}
      </div>
    </div>
  );
}

// ── Trend chart (simple inline SVG) ──────────────────────────────────────────
function TrendChart({ scans }) {
  if (scans.length < 2) return null;
  const scores = scans.map(s => s.securityScore ?? 0);
  const maxV = 100, minV = 0, w = 300, h = 60, pad = 8;
  const pts = scores.map((v, i) => {
    const x = pad + (i / (scores.length - 1)) * (w - 2 * pad);
    const y = pad + ((maxV - v) / (maxV - minV)) * (h - 2 * pad);
    return `${x},${y}`;
  }).join(" ");
  const last = scores[scores.length - 1];
  const prev = scores[scores.length - 2];
  const trend = last > prev + 3 ? "↑ Improving" : last < prev - 3 ? "↓ Degrading" : "→ Stable";
  const trendColor = last > prev + 3 ? "text-green-400" : last < prev - 3 ? "text-red-400" : "text-gray-400";

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500 uppercase tracking-wide">Score Trend</p>
        <span className={`text-xs font-semibold ${trendColor}`}>{trend}</span>
      </div>
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-12">
        <polyline points={pts} fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        {scores.map((v, i) => {
          const x = pad + (i / (scores.length - 1)) * (w - 2 * pad);
          const y = pad + ((maxV - v) / (maxV - minV)) * (h - 2 * pad);
          return <circle key={i} cx={x} cy={y} r="3" fill="#6366f1" />;
        })}
      </svg>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  // Tab: "scan" | "history"
  const [tab, setTab] = useState("scan");

  // Scan form
  const [repoUrl, setRepoUrl]   = useState("");
  const [snippetMode, setSnippetMode] = useState(false);
  const [code, setCode]         = useState("");

  // Scan lifecycle
  const [scanState, setScanState] = useState("idle"); // idle scanning done error
  const [result, setResult]     = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  // Findings filters
  const [filterSev,  setFilterSev]  = useState("ALL");
  const [filterType, setFilterType] = useState("");
  const [filterLang, setFilterLang] = useState("ALL");

  // History
  const [history, setHistory]   = useState([]);
  const [histLoading, setHistLoading] = useState(false);

  const pollRef   = useRef(null);
  const pollCount = useRef(0);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  // ── Fetch history ───────────────────────────────────────────────────────────
  const loadHistory = useCallback(async () => {
    setHistLoading(true);
    try {
      const res = await fetch(`${API}/scans?limit=30`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHistory(data.scans || []);
    } catch (e) {
      console.error("History load failed:", e.message);
    } finally {
      setHistLoading(false);
    }
  }, []);

  useEffect(() => { if (tab === "history") loadHistory(); }, [tab, loadHistory]);

  // ── Polling ─────────────────────────────────────────────────────────────────
  const pollScan = useCallback((scanId) => {
    pollCount.current = 0;
    pollRef.current = setInterval(async () => {
      pollCount.current++;
      if (pollCount.current > MAX_POLLS) {
        stopPolling();
        setScanState("error");
        setErrorMsg("Scan timed out. The repository may be too large.");
        return;
      }
      try {
        const res = await fetch(`${API}/scans/${scanId}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (data.status === "completed") {
          stopPolling(); setResult(data); setScanState("done");
        } else if (data.status === "failed") {
          stopPolling(); setScanState("error"); setErrorMsg(data.error || "Scan failed.");
        }
      } catch (err) {
        stopPolling(); setScanState("error"); setErrorMsg(err.message);
      }
    }, POLL_MS);
  }, [stopPolling]);

  // ── Submit ──────────────────────────────────────────────────────────────────
  const handleScan = useCallback(async () => {
    stopPolling();
    setScanState("scanning"); setResult(null); setErrorMsg("");

    const body = snippetMode ? { code } : { repositoryUrl: repoUrl.trim() };

    try {
      const res = await fetch(`${API}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.error || `HTTP ${res.status}`); }
      const { scanId } = await res.json();
      pollScan(scanId);
    } catch (err) {
      setScanState("error"); setErrorMsg(err.message);
    }
  }, [repoUrl, code, snippetMode, pollScan, stopPolling]);

  const handleReset = () => {
    stopPolling(); setScanState("idle"); setResult(null); setErrorMsg("");
  };

  const openScan = useCallback(async (scanId) => {
    setTab("scan");
    setScanState("scanning"); setResult(null); setErrorMsg("");
    pollScan(scanId);
  }, [pollScan]);

  // ── Derived ─────────────────────────────────────────────────────────────────
  const isScanning = scanState === "scanning";
  const findings = result?.findings || [];

  const allLanguages = [...new Set(findings.map(f => f.language).filter(Boolean))];
  const allTypes     = [...new Set(findings.map(f => f.type))];

  const filtered = findings.filter(f => {
    if (filterSev !== "ALL" && f.severity !== filterSev) return false;
    if (filterType && f.type !== filterType) return false;
    if (filterLang !== "ALL" && f.language !== filterLang) return false;
    return true;
  }).sort((a, b) => (SEV[a.severity]?.order ?? 9) - (SEV[b.severity]?.order ?? 9));

  const canScan = snippetMode ? code.trim().length > 0 : repoUrl.trim().length > 0;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col">
      {/* ── Header ── */}
      <header className="border-b border-gray-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center text-white font-bold text-sm select-none">R</div>
          <div>
            <span className="font-bold text-gray-100 tracking-tight">RepoSentinel</span>
            <span className="text-xs text-gray-500 ml-2 hidden sm:inline">Repository Security Monitoring</span>
          </div>
        </div>
        <nav className="flex gap-1">
          {["scan", "history"].map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors capitalize ${tab === t ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"}`}>
              {t === "scan" ? "Scanner" : "History"}
            </button>
          ))}
        </nav>
      </header>

      {/* ── Scanner Tab ── */}
      {tab === "scan" && (
        <main className="flex-1 flex flex-col lg:flex-row gap-6 p-6 max-w-7xl mx-auto w-full">

          {/* Left — input */}
          <section className="lg:w-96 flex-shrink-0 flex flex-col gap-4">
            <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 flex flex-col gap-4">
              <div>
                <p className="text-sm font-semibold text-gray-200 mb-1">Security Scanner</p>
                <p className="text-xs text-gray-500">Enter a public GitHub repository URL to start a full scan.</p>
              </div>

              {/* Mode toggle */}
              <div className="flex rounded-lg overflow-hidden border border-gray-800 text-xs font-medium">
                <button onClick={() => setSnippetMode(false)}
                  className={`flex-1 py-2 transition-colors ${!snippetMode ? "bg-indigo-600 text-white" : "text-gray-400 hover:bg-gray-800"}`}>
                  Repository
                </button>
                <button onClick={() => setSnippetMode(true)}
                  className={`flex-1 py-2 transition-colors ${snippetMode ? "bg-indigo-600 text-white" : "text-gray-400 hover:bg-gray-800"}`}>
                  Quick Snippet
                </button>
              </div>

              {!snippetMode ? (
                <div>
                  <label className="text-xs text-gray-500 mb-1 block">GitHub Repository URL</label>
                  <input
                    type="text"
                    value={repoUrl}
                    onChange={e => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    disabled={isScanning}
                    className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors"
                    onKeyDown={e => e.key === "Enter" && canScan && !isScanning && handleScan()}
                  />
                  <p className="text-xs text-gray-600 mt-1">Public repositories only. Clone may take 15–30s.</p>
                </div>
              ) : (
                <div>
                  <label className="text-xs text-gray-500 mb-1 block">Code Snippet</label>
                  <textarea
                    value={code}
                    onChange={e => setCode(e.target.value)}
                    placeholder="Paste code here..."
                    disabled={isScanning}
                    className="w-full h-48 bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-200 placeholder-gray-600 font-mono resize-none focus:outline-none focus:ring-2 focus:ring-indigo-500/50 transition-colors"
                    spellCheck={false}
                  />
                </div>
              )}

              <button
                onClick={handleScan}
                disabled={isScanning || !canScan}
                className="w-full py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-600/40 disabled:cursor-not-allowed text-white font-semibold text-sm transition-colors flex items-center justify-center gap-2"
              >
                {isScanning
                  ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Scanning...</>
                  : "Start Security Scan"}
              </button>

              {(scanState === "done" || scanState === "error") && (
                <button onClick={handleReset}
                  className="w-full py-2 rounded-xl bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm transition-colors">
                  New Scan
                </button>
              )}
            </div>

            {/* Info box */}
            <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4 flex flex-col gap-2">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Detects</p>
              {["SQL Injection · CWE-89", "XSS · CWE-79", "Hardcoded Secrets · CWE-798",
                "Command Injection · CWE-78", "Path Traversal · CWE-22",
                "Insecure Deserialization · CWE-502", "Open Redirect · CWE-601", "eval() Injection · CWE-95"].map(t => (
                <p key={t} className="text-xs text-gray-500">• {t}</p>
              ))}
              <p className="text-xs text-gray-600 mt-1 italic">Heuristic static analysis — not a replacement for SAST tools.</p>
            </div>
          </section>

          {/* Right — results */}
          <section className="flex-1 flex flex-col gap-4 min-w-0">
            {/* Idle */}
            {scanState === "idle" && (
              <div className="flex-1 flex flex-col items-center justify-center rounded-xl border border-dashed border-gray-800 text-gray-600 gap-3 p-16 text-center">
                <div className="text-5xl">🛡️</div>
                <p className="text-sm">Enter a repository URL and click Start Security Scan.</p>
                <p className="text-xs text-gray-700">Supports JavaScript, TypeScript, Python, and Java.</p>
              </div>
            )}

            {/* Scanning */}
            {isScanning && (
              <div className="flex-1 flex flex-col items-center justify-center rounded-xl border border-gray-800 bg-gray-900/50 gap-4 p-16">
                <div className="w-12 h-12 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
                <p className="text-sm text-gray-300 font-medium">
                  {snippetMode ? "Analyzing snippet…" : "Cloning and scanning repository…"}
                </p>
                <p className="text-xs text-gray-600">This may take up to 60 seconds for large repositories.</p>
              </div>
            )}

            {/* Error */}
            {scanState === "error" && (
              <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-5">
                <p className="font-semibold text-red-400 mb-1">Scan failed</p>
                <p className="text-sm text-red-300/80">{errorMsg}</p>
              </div>
            )}

            {/* Results */}
            {scanState === "done" && result && (
              <div className="flex flex-col gap-5">
                {/* Score + summary */}
                <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
                  <div className="flex flex-col sm:flex-row gap-5 items-start sm:items-center">
                    <ScoreRing score={result.securityScore ?? 0} />
                    <div className="flex-1 flex flex-col gap-3">
                      <div className="flex flex-wrap gap-4 text-sm text-gray-400">
                        {result.repositoryName && (
                          <span className="font-mono text-indigo-400">{result.repositoryName}</span>
                        )}
                        <span>{result.filesScanned} files scanned</span>
                        {result.duration && <span>{(result.duration / 1000).toFixed(1)}s</span>}
                      </div>
                      <SummaryBar summary={result.summary} />
                      {/* Language summary */}
                      {result.languageSummary && Object.keys(result.languageSummary).length > 0 && (
                        <div className="flex gap-3 flex-wrap">
                          {Object.entries(result.languageSummary).map(([lang, count]) => (
                            <span key={lang} className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">
                              {lang}: {count} files
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Filters */}
                {findings.length > 0 && (
                  <div className="flex gap-3 flex-wrap">
                    <select value={filterSev} onChange={e => setFilterSev(e.target.value)}
                      className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-300 focus:outline-none">
                      <option value="ALL">Severity: All</option>
                      {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                    <select value={filterType} onChange={e => setFilterType(e.target.value)}
                      className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-300 focus:outline-none">
                      <option value="">Type: All</option>
                      {allTypes.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                    {allLanguages.length > 1 && (
                      <select value={filterLang} onChange={e => setFilterLang(e.target.value)}
                        className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-300 focus:outline-none">
                        <option value="ALL">Language: All</option>
                        {allLanguages.map(l => <option key={l} value={l}>{l}</option>)}
                      </select>
                    )}
                    <span className="text-xs text-gray-500 self-center ml-auto">
                      {filtered.length} of {findings.length} findings
                    </span>
                  </div>
                )}

                {/* Findings list */}
                {findings.length === 0 ? (
                  <div className="rounded-xl border border-green-500/30 bg-green-500/10 p-6 text-center">
                    <div className="text-3xl mb-2">✅</div>
                    <p className="text-green-400 font-semibold">No vulnerabilities detected.</p>
                    <p className="text-xs text-green-400/60 mt-1">
                      Static analysis is limited — combine with manual code review and dynamic testing.
                    </p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-2">
                    {filtered.map(f => <FindingCard key={f.id} f={f} />)}
                    {filtered.length === 0 && (
                      <p className="text-sm text-gray-500 text-center py-6">No findings match current filters.</p>
                    )}
                  </div>
                )}
              </div>
            )}
          </section>
        </main>
      )}

      {/* ── History Tab ── */}
      {tab === "history" && (
        <main className="flex-1 p-6 max-w-4xl mx-auto w-full flex flex-col gap-5">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-gray-300">Recent Scans</p>
            <button onClick={loadHistory} className="text-xs text-gray-500 hover:text-gray-300 transition-colors">
              ↺ Refresh
            </button>
          </div>

          {histLoading && (
            <div className="flex items-center justify-center py-12">
              <div className="w-8 h-8 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
            </div>
          )}

          {!histLoading && history.length === 0 && (
            <div className="text-center py-16 text-gray-600">
              <p className="text-4xl mb-3">📭</p>
              <p className="text-sm">No scans yet. Run your first scan.</p>
            </div>
          )}

          {!histLoading && history.length > 0 && (
            <>
              {/* Group by repo for trend */}
              {(() => {
                const repos = {};
                history.forEach(s => {
                  const key = s.repositoryName || "Quick Scans";
                  if (!repos[key]) repos[key] = [];
                  repos[key].push(s);
                });
                return Object.entries(repos).map(([name, scans]) => (
                  <div key={name} className="flex flex-col gap-2">
                    <div className="flex items-center gap-3">
                      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide truncate">{name}</p>
                      {scans.length > 1 && <div className="flex-1"><TrendChart scans={[...scans].reverse()} /></div>}
                    </div>
                    {scans.map(s => <HistoryCard key={s.scanId} scan={s} onOpen={openScan} />)}
                  </div>
                ));
              })()}
            </>
          )}
        </main>
      )}
    </div>
  );
}
