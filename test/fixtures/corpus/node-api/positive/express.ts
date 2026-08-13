import express from "express";
import { documentRouter } from "./routes/documents.js";
import { requireSession } from "./security/session.js";

const app = express();

app.post("/admin/reload", async (_req, res) => {
  return res.json({ queued: true });
});
app.post("/admin/export", requireSession, async (_req, res) => {
  return res.json({ queued: true });
});
app.use("/api", documentRouter);
