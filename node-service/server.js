require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");

const Scan = require("./models/Scan");
const { scanQueue } = require("./queue");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: "512kb" }));

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many scan requests. Please wait a minute." },
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseGitHubUrl(url) {
  try {
    const u = new URL(url.trim());
    if (u.hostname !== "github.com") return null;
    const parts = u.pathname.replace(/^\//, "").replace(/\.git$/, "").split("/");
    if (parts.length < 2 || !parts[0] || !parts[1]) return null;
    return { owner: parts[0], repo: parts[1], name: `${parts[0]}/${parts[1]}` };
  } catch {
    return null;
  }
}

// ── POST /api/scans  — start a repo or snippet scan ──────────────────────────
app.post("/api/scans", scanLimiter, async (req, res) => {
  try {
    const { repositoryUrl, code } = req.body;

    if (!repositoryUrl && !code) {
      return res.status(400).json({ error: "Provide 'repositoryUrl' or 'code'." });
    }

    let repoInfo = null;
    let inputType = "snippet";

    if (repositoryUrl) {
      repoInfo = parseGitHubUrl(repositoryUrl);
      if (!repoInfo) {
        return res.status(400).json({
          error: "Invalid GitHub URL. Expected: https://github.com/owner/repo",
        });
      }
      inputType = "repo";
    }

    if (code && typeof code !== "string") {
      return res.status(400).json({ error: "'code' must be a string." });
    }
    if (code && code.trim().length === 0) {
      return res.status(400).json({ error: "'code' must not be empty." });
    }

    const scanId = uuidv4();
    const doc = {
      scanId,
      inputType,
      status: "pending",
      ...(repoInfo && {
        repositoryUrl: repositoryUrl.trim(),
        repositoryName: repoInfo.name,
      }),
    };

    await Scan.create(doc);
    await scanQueue.add(
      "analyze",
      { scanId, inputType, repositoryUrl: repositoryUrl?.trim(), code },
      { attempts: 2, backoff: { type: "fixed", delay: 5000 } }
    );

    return res.status(202).json({ scanId, status: "pending" });
  } catch (err) {
    console.error("POST /api/scans error:", err.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── GET /api/scans/:id  — get scan status + full result ──────────────────────
app.get("/api/scans/:id", async (req, res) => {
  try {
    const scan = await Scan.findOne({ scanId: req.params.id }).lean();
    if (!scan) return res.status(404).json({ error: "Scan not found." });
    return res.json(scan);
  } catch (err) {
    console.error("GET /api/scans/:id error:", err.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── GET /api/scans  — list recent scans (paginated) ──────────────────────────
app.get("/api/scans", async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const skip = (page - 1) * limit;

    const [scans, total] = await Promise.all([
      Scan.find({}, {
        scanId: 1, repositoryUrl: 1, repositoryName: 1, inputType: 1,
        status: 1, securityScore: 1, summary: 1, filesScanned: 1,
        duration: 1, createdAt: 1, completedAt: 1,
      })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Scan.countDocuments(),
    ]);

    return res.json({ scans, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error("GET /api/scans error:", err.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── GET /api/scans/:id/findings  — findings with optional filter ──────────────
app.get("/api/scans/:id/findings", async (req, res) => {
  try {
    const scan = await Scan.findOne({ scanId: req.params.id }, { findings: 1 }).lean();
    if (!scan) return res.status(404).json({ error: "Scan not found." });

    let findings = scan.findings || [];
    const { severity, type, language, file } = req.query;
    if (severity) findings = findings.filter(f => f.severity === severity.toUpperCase());
    if (type) findings = findings.filter(f => f.type.toLowerCase().includes(type.toLowerCase()));
    if (language) findings = findings.filter(f => f.language === language);
    if (file) findings = findings.filter(f => f.file && f.file.includes(file));

    return res.json({ findings, total: findings.length });
  } catch (err) {
    console.error("GET /api/scans/:id/findings error:", err.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── GET /api/repositories/:name/history  — trend for a repo ──────────────────
app.get("/api/repositories/:owner/:repo/history", async (req, res) => {
  try {
    const repoName = `${req.params.owner}/${req.params.repo}`;
    const scans = await Scan.find(
      { repositoryName: repoName, status: "completed" },
      { scanId: 1, securityScore: 1, summary: 1, createdAt: 1, filesScanned: 1 }
    )
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    // Trend: compare last two completed scores
    let trend = "stable";
    if (scans.length >= 2) {
      const diff = scans[0].securityScore - scans[1].securityScore;
      if (diff > 3) trend = "improving";
      else if (diff < -3) trend = "degrading";
    }

    return res.json({ repository: repoName, scans: scans.reverse(), trend });
  } catch (err) {
    console.error("GET repository history error:", err.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => res.json({ ok: true, service: "reposentinel-api" }));

// ── Legacy shim — old /api/scan routes still work ────────────────────────────
app.post("/api/scan", scanLimiter, (req, res) => {
  req.body.code = req.body.code || "";
  return res.redirect(307, "/api/scans");
});
app.get("/api/scan/:id", (req, res) => res.redirect(301, `/api/scans/${req.params.id}`));

// ── DB + Start ────────────────────────────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/reposentinel")
  .then(() => {
    console.log("MongoDB connected");
    app.listen(PORT, () => console.log(`RepoSentinel API listening on :${PORT}`));
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });
