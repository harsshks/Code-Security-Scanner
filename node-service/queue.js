const { Queue, Worker } = require("bullmq");
const axios = require("axios");
const Scan = require("./models/Scan");

const connection = {
  host: process.env.REDIS_HOST || "localhost",
  port: parseInt(process.env.REDIS_PORT || "6379"),
};

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";

// Queue that API routes push jobs onto
const scanQueue = new Queue("scan-jobs", { connection });

// Worker that processes jobs off the queue
const scanWorker = new Worker(
  "scan-jobs",
  async (job) => {
    const { scanId, code, inputType } = job.data;

    // Mark as processing
    await Scan.findOneAndUpdate({ scanId }, { status: "processing" });

    // Call Python ML microservice
    const response = await axios.post(
      `${ML_SERVICE_URL}/analyze`,
      { code, inputType },
      { timeout: 60000 }
    );

    const { vulnerabilities, riskScore } = response.data;

    // Persist results
    await Scan.findOneAndUpdate(
      { scanId },
      {
        status: "completed",
        vulnerabilities,
        riskScore,
        error: null,
      }
    );
  },
  { connection }
);

scanWorker.on("failed", async (job, err) => {
  console.error(`Job ${job?.id} failed:`, err.message);
  if (job?.data?.scanId) {
    await Scan.findOneAndUpdate(
      { scanId: job.data.scanId },
      { status: "failed", error: err.message }
    ).catch(() => {});
  }
});

scanWorker.on("completed", (job) => {
  console.log(`Job ${job.id} completed for scanId: ${job.data.scanId}`);
});

module.exports = { scanQueue };
