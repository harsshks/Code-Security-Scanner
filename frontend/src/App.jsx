import { useState, useRef, useCallback } from "react";

const API_BASE = "/api";
const POLL_INTERVAL_MS = 2000;
const MAX_POLLS = 60; // 2 min timeout

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEVERITY_STYLES = {
  High: {
    badge: "bg-red-500/20 text-red-400 border border-red-500/40",
    dot: "bg-red-500",
    bar: "bg-red-500",
  },
  Medium: {
    badge: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40",
    dot: "bg-yellow-400",
    bar: "bg-yellow-400",
  },
  Low: {
    badge: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
    dot: "bg-blue-400",
    bar: "bg-blue-400",
  },
};

function SeverityBadge({ severity }) {
  const s = SEVERITY_STYLES[severity] || SEVERITY_STYLES.Low;
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${s.badge}`}>
      {severity}
    </span>
  );
}

// ── Risk score ring ───────────────────────────────────────────────────────────

function RiskRing({ score }) {
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color =
    score >= 70 ? "#ef4444" : score >= 40 ? "#facc15" : "#34d399";

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="100" height="100" className="-rotate-90">
        <circle
          cx="50" cy="50" r={radius}
          fill="none" stroke="#1f2937" strokeWidth="10"
        />
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <span className="text-2xl font-bold -mt-16" style={{ color }}>
        {score}
      </span>
      <span className="text-xs text-gray-400 mt-8">Risk Score</span>
    </div>
  );
}

// ── Severity breakdown bar chart ──────────────────────────────────────────────

function SeverityBreakdown({ vulnerabilities }) {
  const counts = { High: 0, Medium: 0, Low: 0 };
  vulnerabilities.forEach((v) => {
    if (counts[v.severity] !== undefined) counts[v.severity]++;
  });
  const total = vulnerabilities.length || 1;

  return (
    <div className="flex flex-col gap-2">
      {Object.entries(counts).map(([level, count]) => {
        const pct = Math.round((count / total) * 100);
        const s = SEVERITY_STYLES[level];
        return (
          <div key={level} className="flex items-center gap-3">
            <span className="w-16 text-xs text-gray-400">{level}</span>
            <div className="flex-1 h-2 rounded-full bg-gray-800">
              <div
                className={`h-2 rounded-full ${s.bar} transition-all duration-500`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="w-6 text-xs text-right text-gray-300">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

// ── Single vulnerability card ─────────────────────────────────────────────────

function VulnCard({ vuln, index }) {
  const [expanded, setExpanded] = useState(false);
  const s = SEVERITY_STYLES[vuln.severity] || SEVERITY_STYLES.Low;

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden">
      <button
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-gray-800/50 transition-colors text-left"
        onClick={() => setExpanded((p) => !p)}
        aria-expanded={expanded}
      >
        <div className="flex items-center gap-3">
          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`} />
          <span className="text-sm font-medium text-gray-100">{vuln.type}</span>
          {vuln.line && (
            <span className="text-xs text-gray-500">Line {vuln.line}</span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <SeverityBadge severity={vuln.severity} />
          <span className="text-gray-500 text-xs">{expanded ? "▲" : "▼"}</span>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 flex flex-col gap-3 border-t border-gray-800 pt-3">
          {vuln.snippet && (
            <div>
              <p className="text-xs text-gray-500 mb-1 uppercase tracking-wide">Flagged Code</p>
              <pre className="bg-gray-950 text-red-300 text-xs rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-words font-mono">
                {vuln.snippet}
              </pre>
            </div>
          )}
          <div>
            <p className="text-xs text-gray-500 mb-1 uppercase tracking-wide">Description</p>
            <p className="text-sm text-gray-300">{vuln.description}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-1 uppercase tracking-wide">Suggested Fix</p>
            <p className="text-sm text-green-400">{vuln.suggestedFix}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────

const SAMPLE_CODE = `// Sample vulnerable code — try scanning this!
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // SQL injection risk
  db.query("SELECT * FROM users WHERE id = " + userId, (err, rows) => {
    res.send(rows);
  });
});

app.post('/comment', (req, res) => {
  const comment = req.body.text;
  // XSS risk
  document.getElementById('output').innerHTML = comment;
});

// Hardcoded secret
const API_KEY = "sk-abc123supersecrettoken9999";
const DB_PASSWORD = "admin1234";
`;

export default function App() {
  const [code, setCode] = useState(SAMPLE_CODE);
  const [scanState, setScanState] = useState("idle"); // idle | scanning | done | error
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const pollRef = useRef(null);
  const pollCount = useRef(0);
  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const pollScan = useCallback(
    (scanId) => {
      pollCount.current = 0;
      pollRef.current = setInterval(async () => {
        pollCount.current++;
        if (pollCount.current > MAX_POLLS) {
          stopPolling();
          setScanState("error");
          setErrorMsg("Scan timed out. Please try again.");
          return;
        }

        try {
          const res = await fetch(`${API_BASE}/scan/${scanId}`);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const data = await res.json();

          if (data.status === "completed") {
            stopPolling();
            setResult(data);
            setScanState("done");
          } else if (data.status === "failed") {
            stopPolling();
            setScanState("error");
            setErrorMsg(data.error || "Scan failed.");
          }
        } catch (err) {
          stopPolling();
          setScanState("error");
          setErrorMsg(err.message);
        }
      }, POLL_INTERVAL_MS);
    },
    [stopPolling]
  );

  const handleScan = useCallback(async () => {
    if (!code.trim()) return;
    stopPolling();
    setScanState("scanning");
    setResult(null);
    setErrorMsg("");

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `HTTP ${res.status}`);
      }

      const { scanId } = await res.json();
      pollScan(scanId);
    } catch (err) {
      setScanState("error");
      setErrorMsg(err.message);
    }
  }, [code, pollScan, stopPolling]);

  const handleReset = () => {
    stopPolling();
    setScanState("idle");
    setResult(null);
    setErrorMsg("");
  };

  const isScanning = scanState === "scanning";
  const totalVulns = result?.vulnerabilities?.length ?? 0;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center text-white font-bold text-sm">
            S
          </div>
          <span className="font-semibold text-gray-100 text-lg tracking-tight">
            Code Security Scanner
          </span>
        </div>
        <span className="text-xs text-gray-500 hidden sm:block">
          SQL Injection · XSS · Hardcoded Secrets · Command Injection · More
        </span>
      </header>

      <main className="flex-1 flex flex-col lg:flex-row gap-6 p-6 max-w-7xl mx-auto w-full">
        {/* Left panel — editor */}
        <section className="flex-1 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
              Code Input
            </h2>
            <span className="text-xs text-gray-600">{code.length} chars</span>
          </div>

          <textarea
            className="flex-1 min-h-[400px] w-full bg-gray-900 border border-gray-800 rounded-xl p-4 font-mono text-sm text-gray-200 resize-none focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 placeholder-gray-700 transition-colors"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste your code here..."
            spellCheck={false}
            aria-label="Code input"
            disabled={isScanning}
          />

          <div className="flex gap-3">
            <button
              onClick={handleScan}
              disabled={isScanning || !code.trim()}
              className="flex-1 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-600/40 disabled:cursor-not-allowed text-white font-semibold text-sm transition-colors flex items-center justify-center gap-2"
            >
              {isScanning ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Scanning...
                </>
              ) : (
                "Scan Code"
              )}
            </button>

            {(scanState === "done" || scanState === "error") && (
              <button
                onClick={handleReset}
                className="px-5 py-3 rounded-xl bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium transition-colors"
              >
                Reset
              </button>
            )}
          </div>
        </section>

        {/* Right panel — results */}
        <section className="flex-1 flex flex-col gap-4">
          <h2 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
            Results
          </h2>

          {/* Idle state */}
          {scanState === "idle" && (
            <div className="flex-1 flex flex-col items-center justify-center rounded-xl border border-dashed border-gray-800 text-gray-600 gap-2 p-10 text-center">
              <div className="text-4xl">🔍</div>
              <p className="text-sm">Submit your code to see the security report.</p>
            </div>
          )}

          {/* Scanning state */}
          {isScanning && (
            <div className="flex-1 flex flex-col items-center justify-center rounded-xl border border-gray-800 bg-gray-900/50 gap-4">
              <div className="w-10 h-10 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
              <p className="text-sm text-gray-400">Analyzing your code for vulnerabilities…</p>
            </div>
          )}

          {/* Error state */}
          {scanState === "error" && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-5 text-red-400 text-sm">
              <p className="font-semibold mb-1">Scan failed</p>
              <p className="text-red-300/80">{errorMsg}</p>
            </div>
          )}

          {/* Done state */}
          {scanState === "done" && result && (
            <div className="flex flex-col gap-5 overflow-y-auto">
              {/* Summary row */}
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 flex items-center justify-center">
                  <RiskRing score={result.riskScore ?? 0} />
                </div>

                <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 flex flex-col justify-between gap-4">
                  <div>
                    <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">
                      Vulnerabilities
                    </p>
                    <p className="text-3xl font-bold text-gray-100">{totalVulns}</p>
                  </div>
                  <SeverityBreakdown vulnerabilities={result.vulnerabilities} />
                </div>
              </div>

              {/* Vulnerability list */}
              {totalVulns === 0 ? (
                <div className="rounded-xl border border-green-500/30 bg-green-500/10 p-5 text-center">
                  <div className="text-3xl mb-2">✅</div>
                  <p className="text-green-400 font-semibold">No vulnerabilities detected.</p>
                  <p className="text-xs text-green-400/60 mt-1">
                    Always combine automated scanning with manual review.
                  </p>
                </div>
              ) : (
                <div className="flex flex-col gap-3">
                  <p className="text-xs text-gray-500 uppercase tracking-wide">
                    Findings — click to expand
                  </p>
                  {result.vulnerabilities.map((v, i) => (
                    <VulnCard key={i} vuln={v} index={i} />
                  ))}
                </div>
              )}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
