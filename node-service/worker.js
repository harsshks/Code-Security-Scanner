/**
 * RepoSentinel — BullMQ Worker (separate process)
 * Responsibilities:
 *   1. Pick up scan job from Redis queue
 *   2. Clone public GitHub repo into /tmp
 *   3. POST repo path to Python analysis engine
 *   4. Persist findings + score to MongoDB
 *   5. Clean up temp directory
 */
require("dotenv").config();
const { Worker } = require("bullmq");
const axios = require("axios");
const mongoose = require("mongoose");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFile } = require("child_process");
const { promisify } = require("util");

const Scan = require("./models/Scan");

const execFileAsync = promisify(execFile);

const connection = {
  host: process.env.REDIS_HOST || "localhost",
  port: parseInt(process.env.REDIS_PORT || "6379"),
  password: process.env.REDIS_PASSWORD || undefined,
};

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/reposentinel";

// ── Score calculation (deterministic, documented) ─────────────────────────────
// Penalty per finding severity:
//   CRITICAL: 25   HIGH: 15   MEDIUM: 7   LOW: 2   INFO: 0
// Score = max(0, 100 - total_penalty), capped at 100
function calculateSecurityScore(findings) {
  const PENALTY = { CRITICAL: 25, HIGH: 15, MEDIUM: 7, LOW: 2, INFO: 0 };
  const total = findings.reduce((acc, f) => acc + (PENALTY[f.severity] || 0), 0);
  return Math.max(0, 100 - total);
}

function buildSummary(findings) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
  findings.forEach(f => {
    const key = f.severity.toLowerCase();
    if (key in s) s[key]++;
  });
  return s;
}

// ── Temp directory helpers ────────────────────────────────────────────────────
function makeTempDir(scanId) {
  const dir = path.join(os.tmpdir(), `reposentinel-${scanId}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanupDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    console.warn(`Cleanup failed for ${dir}:`, e.message);
  }
}

// ── Clone repository ──────────────────────────────────────────────────────────
async function cloneRepo(repoUrl, targetDir) {
  // Shallow clone (depth 1) — we only need latest snapshot, not full history
  // Timeout: 90s for large repos
  await execFileAsync(
    "git",
    ["clone", "--depth", "1", "--single-branch", repoUrl, targetDir],
    { timeout: 90_000 }
  );
}

// ── Job processor ─────────────────────────────────────────────────────────────
async function processJob(job) {
  const { scanId, inputType, repositoryUrl, code } = job.data;
  const startedAt = new Date();
  let tempDir = null;

  await Scan.findOneAndUpdate({ scanId }, { status: "processing", startedAt });

  try {
    let analysisPayload;

    if (inputType === "repo") {
      // Validate URL shape one more time
      if (!repositoryUrl || !repositoryUrl.startsWith("https://github.com/")) {
        throw new Error("Invalid repository URL.");
      }

      tempDir = makeTempDir(scanId);
      console.log(`[${scanId}] Cloning ${repositoryUrl} → ${tempDir}`);
      await cloneRepo(repositoryUrl, tempDir);
      console.log(`[${scanId}] Clone complete`);

      analysisPayload = { repositoryPath: tempDir, inputType: "repo" };
    } else {
      // Quick snippet scan
      analysisPayload = { code, inputType: "snippet" };
    }

    // Call Python static analysis engine
    const response = await axios.post(
      `${ML_SERVICE_URL}/analyze`,
      analysisPayload,
      { timeout: 120_000 }
    );

    const { findings, filesScanned, totalFiles, languageSummary } = response.data;

    const securityScore = calculateSecurityScore(findings);
    const summary = buildSummary(findings);
    const completedAt = new Date();

    await Scan.findOneAndUpdate(
      { scanId },
      {
        status: "completed",
        completedAt,
        duration: completedAt - startedAt,
        findings,
        securityScore,
        summary,
        filesScanned: filesScanned || 0,
        totalFiles: totalFiles || 0,
        languageSummary: languageSummary || {},
        error: null,
      }
    );

    console.log(
      `[${scanId}] Completed — score: ${securityScore}, findings: ${findings.length}`
    );
  } finally {
    // Always clean up temp directory
    if (tempDir) cleanupDir(tempDir);
  }
}

// ── Worker ────────────────────────────────────────────────────────────────────
const worker = new Worker("scan-jobs", processJob, {
  connection,
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
  console.log(`[${job.data.scanId}] Job ${job.id} completed successfully`);
});

// ── DB connect + start ────────────────────────────────────────────────────────
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("Worker: MongoDB connected"))
  .catch((err) => { console.error("Worker: MongoDB failed:", err.message); process.exit(1); });

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("Worker shutting down...");
  await worker.close();
  process.exit(0);
});
