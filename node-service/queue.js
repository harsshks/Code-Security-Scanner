/**
 * Queue module — only exposes the Queue instance for the API to push jobs.
 * The Worker lives in worker.js (separate process).
 */
const { Queue } = require("bullmq");

const connection = {
  host: process.env.REDIS_HOST || "localhost",
  port: parseInt(process.env.REDIS_PORT || "6379"),
  password: process.env.REDIS_PASSWORD || undefined,
};

const scanQueue = new Queue("scan-jobs", { connection });

module.exports = { scanQueue };
