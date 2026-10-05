require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");

// Worker deps
const { Worker } = require("bullmq");
const axios = require("axios");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFile } = require("child_process");
const { promisify } = require("util");

const Scan = require("./models/Scan");
const { scanQueue } = require("./queue");

const execFileAsync = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 4000;
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";

app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "512kb" }));

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many scan requests. Please wait a minute." },
});

// ── Redis connection config (shared by queue + worker) ────────────────────────
const redisConnection = {
  host: process.env.REDIS_HOST || "localhost",
  port: parseInt(process.env.REDIS_PORT || "6379"),
  password: process.env.REDIS_PASSWORD || undefined,
  tls: process.env.REDIS_HOST?.includes("upstash.io") ? {} : undefined,
};

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

// ── Worker logic ──────────────────────────────────────────────────────────────

function calculateSecurityScore(findings) {
  const PENALTY = { CRITICAL: 25, HIGH: 15, MEDIUM: 7, LOW: 2, INFO: 0 };
  const total = findings.reduce((acc, f) => acc + (PENALTY[f.severity] || 0), 0);
  return Math.max(0, 100 - total);
}

function buildSummary(findings) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
  findings.forEach(f => { const k = f.severity.toLowerCase(); if (k in s) s[k]++; });
  return s;
}

function makeTempDir(scanId) {
  const dir = path.join(os.tmpdir(), `reposentinel-${scanId}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanupDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); }
  catch (e) { console.warn(`Cleanup failed for ${dir}:`, e.message); }
}

async function cloneRepo(repoUrl, targetDir) {
  await execFileAsync(
    "git",
    ["clone", "--depth", "1", "--single-branch", repoUrl, targetDir],
    { timeout: 90_000 }
  );
}

async function processJob(job) {
  const { scanId, inputType, repositoryUrl, code } = job.data;
  const startedAt = new Date();
  let tempDir = null;

  await Scan.findOneAndUpdate({ scanId }, { status: "processing", startedAt });

  try {
    let payload;

    if (inputType === "repo") {
      if (!repositoryUrl || !repositoryUrl.startsWith("https://github.com/")) {
        throw new Error("Invalid repository URL.");
      }
      tempDir = makeTempDir(scanId);
      console.log(`[${scanId}] Cloning ${repositoryUrl}`);
      await cloneRepo(repositoryUrl, tempDir);
      console.log(`[${scanId}] Clone complete`);
      payload = { repositoryPath: tempDir, inputType: "repo" };
    } else {
      payload = { code, inputType: "snippet" };
    }

    const response = await axios.post(`${ML_SERVICE_URL}/analyze`, payload, { timeout: 120_000 });
    const { findings, filesScanned, totalFiles, languageSummary, repoInsights } = response.data;

    const securityScore = calculateSecurityScore(findings);
    const summary = buildSummary(findings);
    const completedAt = new Date();

    await Scan.findOneAndUpdate({ scanId }, {
      status: "completed",
      completedAt,
      duration: completedAt - startedAt,
      findings,
      securityScore,
      summary,
      filesScanned: filesScanned || 0,
      totalFiles: totalFiles || 0,
      languageSummary: languageSummary || {},
      ...(repoInsights && { repoInsights }),
      error: null,
    });

    console.log(`[${scanId}] Done — score: ${securityScore}, findings: ${findings.length}`);
  } finally {
    if (tempDir) cleanupDir(tempDir);
  }
}

// ── Start BullMQ worker in-process ────────────────────────────────────────────
function startWorker() {
  const worker = new Worker("scan-jobs", processJob, {
    connection: redisConnection,
    concurrency: 2,
  });

  worker.on("failed", async (job, err) => {
    console.error(`[${job?.data?.scanId}] Job failed: ${err.message}`);
    if (job?.data?.scanId) {
      await Scan.findOneAndUpdate(
        { scanId: job.data.scanId },
        { status: "failed", error: err.message }
      ).catch(() => {});
    }
  });

  worker.on("completed", (job) => {
    console.log(`[${job.data.scanId}] Job ${job.id} completed`);
  });

  process.on("SIGTERM", async () => {
    console.log("Shutting down worker...");
    await worker.close();
    process.exit(0);
  });

  console.log("BullMQ worker started (in-process)");
  return worker;
}

// ── API Routes ────────────────────────────────────────────────────────────────

app.post("/api/scans", scanLimiter, async (req, res) => {
  try {
    const { repositoryUrl, code } = req.body;
    if (!repositoryUrl && !code)
      return res.status(400).json({ error: "Provide 'repositoryUrl' or 'code'." });

    let repoInfo = null;
    let inputType = "snippet";

    if (repositoryUrl) {
      repoInfo = parseGitHubUrl(repositoryUrl);
      if (!repoInfo)
        return res.status(400).json({ error: "Invalid GitHub URL. Expected: https://github.com/owner/repo" });
      inputType = "repo";
    }

    if (code && typeof code !== "string")
      return res.status(400).json({ error: "'code' must be a string." });
    if (code && !code.trim())
      return res.status(400).json({ error: "'code' must not be empty." });

    const scanId = uuidv4();
    await Scan.create({
      scanId, inputType, status: "pending",
      ...(repoInfo && { repositoryUrl: repositoryUrl.trim(), repositoryName: repoInfo.name }),
    });
    await scanQueue.add(
      "analyze",
      { scanId, inputType, repositoryUrl: repositoryUrl?.trim(), code },
      { attempts: 2, backoff: { type: "fixed", delay: 5000 } }
    );
    return res.status(202).json({ scanId, status: "pending" });
  } catch (err) {
    console.error("POST /api/scans:", err.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/api/scans/:id", async (req, res) => {
  try {
    const scan = await Scan.findOne({ scanId: req.params.id }).lean();
    if (!scan) return res.status(404).json({ error: "Scan not found." });
    return res.json(scan);
  } catch (err) {
    return res.status(500).json({ error: "Internal server error." });
  }
});

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
      }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      Scan.countDocuments(),
    ]);
    return res.json({ scans, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/api/scans/:id/findings", async (req, res) => {
  try {
    const scan = await Scan.findOne({ scanId: req.params.id }, { findings: 1 }).lean();
    if (!scan) return res.status(404).json({ error: "Scan not found." });
    let findings = scan.findings || [];
    const { severity, type, language, file } = req.query;
    if (severity) findings = findings.filter(f => f.severity === severity.toUpperCase());
    if (type)     findings = findings.filter(f => f.type.toLowerCase().includes(type.toLowerCase()));
    if (language) findings = findings.filter(f => f.language === language);
    if (file)     findings = findings.filter(f => f.file?.includes(file));
    return res.json({ findings, total: findings.length });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/api/repositories/:owner/:repo/history", async (req, res) => {
  try {
    const repoName = `${req.params.owner}/${req.params.repo}`;
    const scans = await Scan.find(
      { repositoryName: repoName, status: "completed" },
      { scanId: 1, securityScore: 1, summary: 1, createdAt: 1, filesScanned: 1 }
    ).sort({ createdAt: -1 }).limit(20).lean();

    let trend = "stable";
    if (scans.length >= 2) {
      const diff = scans[0].securityScore - scans[1].securityScore;
      if (diff > 3) trend = "improving";
      else if (diff < -3) trend = "degrading";
    }
    return res.json({ repository: repoName, scans: scans.reverse(), trend });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true, service: "reposentinel-api" }));

// ── DB connect → start API + worker ──────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/reposentinel")
  .then(() => {
    console.log("MongoDB connected");
    startWorker();
    app.listen(PORT, () => console.log(`RepoSentinel listening on :${PORT}`));
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });
