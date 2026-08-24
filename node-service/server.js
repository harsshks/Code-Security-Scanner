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
app.use(express.json({ limit: "2mb" }));

// Max 20 scan requests per IP per minute
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many scan requests. Please wait a minute." },
});

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * POST /api/scan
 * Body: { code: string } | { repoUrl: string }
 * Returns: { scanId, status: "pending" }
 */
app.post("/api/scan", scanLimiter, async (req, res) => {
  try {
    const { code, repoUrl } = req.body;

    if (!code && !repoUrl) {
      return res
        .status(400)
        .json({ error: "Provide either a 'code' snippet or a 'repoUrl'." });
    }

    // Reject repo URLs — feature coming soon
    if (repoUrl && !code) {
      return res.status(422).json({
        error: "Git repo scanning is not yet supported. Please paste your code directly.",
      });
    }

    if (typeof code !== "string" || code.trim().length === 0) {
      return res.status(400).json({ error: "'code' must be a non-empty string." });
    }

    const scanId = uuidv4();
    await Scan.create({ scanId, input: code, inputType: "code", status: "pending" });
    await scanQueue.add("analyze", { scanId, code, inputType: "code" });

    return res.status(202).json({ scanId, status: "pending" });
  } catch (err) {
    console.error("POST /api/scan error:", err.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

/**
 * GET /api/scan/:id
 * Returns the scan record (status + report)
 */
app.get("/api/scan/:id", async (req, res) => {
  try {
    const scan = await Scan.findOne({ scanId: req.params.id }).lean();
    if (!scan) return res.status(404).json({ error: "Scan not found." });
    return res.json(scan);
  } catch (err) {
    console.error("GET /api/scan/:id error:", err.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => res.json({ ok: true }));

// ── DB + Start ────────────────────────────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/scanner")
  .then(() => {
    console.log("MongoDB connected");
    app.listen(PORT, () => console.log(`Node service listening on :${PORT}`));
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });
