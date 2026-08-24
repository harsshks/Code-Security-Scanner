const mongoose = require("mongoose");

const VulnerabilitySchema = new mongoose.Schema(
  {
    type: { type: String, required: true },
    severity: { type: String, enum: ["Low", "Medium", "High"], required: true },
    line: { type: Number, default: null },
    description: { type: String, required: true },
    suggestedFix: { type: String, default: "" },
    snippet: { type: String, default: "" },
  },
  { _id: false }
);

const ScanSchema = new mongoose.Schema(
  {
    scanId: { type: String, required: true, unique: true, index: true },
    status: {
      type: String,
      enum: ["pending", "processing", "completed", "failed"],
      default: "pending",
    },
    input: { type: String, required: true },
    inputType: { type: String, enum: ["code", "repo"], default: "code" },
    vulnerabilities: { type: [VulnerabilitySchema], default: [] },
    riskScore: { type: Number, default: null },
    error: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Scan", ScanSchema);
