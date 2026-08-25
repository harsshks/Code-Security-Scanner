const mongoose = require("mongoose");

const FindingSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    type: { type: String, required: true },
    severity: {
      type: String,
      enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
      required: true,
    },
    confidence: { type: Number, default: 0.5 }, // 0-1
    cwe: { type: String, default: null },
    file: { type: String, default: null },
    line: { type: Number, default: null },
    codeSnippet: { type: String, default: "" },
    description: { type: String, required: true },
    impact: { type: String, default: "" },
    recommendation: { type: String, default: "" },
    language: { type: String, default: null },
  },
  { _id: false }
);

const ScanSchema = new mongoose.Schema(
  {
    scanId: { type: String, required: true, unique: true, index: true },
    // repo scan fields
    repositoryUrl: { type: String, default: null },
    repositoryName: { type: String, default: null },
    branch: { type: String, default: "main" },
    // quick scan fields
    inputType: { type: String, enum: ["repo", "snippet"], default: "repo" },
    // status
    status: {
      type: String,
      enum: ["pending", "processing", "completed", "failed"],
      default: "pending",
      index: true,
    },
    startedAt: { type: Date, default: null },
    completedAt: { type: Date, default: null },
    duration: { type: Number, default: null }, // ms
    // results
    securityScore: { type: Number, default: null }, // 0-100
    findings: { type: [FindingSchema], default: [] },
    summary: {
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      info: { type: Number, default: 0 },
      total: { type: Number, default: 0 },
    },
    filesScanned: { type: Number, default: 0 },
    totalFiles: { type: Number, default: 0 },
    languageSummary: { type: Map, of: Number, default: {} },
    error: { type: String, default: null },
    // Tier 1 insights — only populated for repo scans
    repoInsights: {
      dependencyAudit: {
        depFiles:          { type: [String], default: [] },
        totalDependencies: { type: Number, default: 0 },
        unpinnedCount:     { type: Number, default: 0 },
        unpinnedDeps:      { type: [String], default: [] },
        dependencies:      { type: mongoose.Schema.Types.Mixed, default: [] },
      },
      repoHealth: {
        score:   { type: Number, default: null },
        passed:  { type: Number, default: 0 },
        total:   { type: Number, default: 0 },
        checks:  { type: mongoose.Schema.Types.Mixed, default: [] },
      },
      sensitiveFiles: {
        flaggedFiles: { type: mongoose.Schema.Types.Mixed, default: [] },
        count:        { type: Number, default: 0 },
        hasCritical:  { type: Boolean, default: false },
      },
      techStack: { type: [String], default: [] },
    },
  },
  { timestamps: true }
);

// Index for repo history queries
ScanSchema.index({ repositoryName: 1, createdAt: -1 });

module.exports = mongoose.model("Scan", ScanSchema);
