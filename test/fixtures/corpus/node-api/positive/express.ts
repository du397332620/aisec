import express from "express";
import { documentRouter } from "./routes/documents.js";

const app = express();

app.post("/admin/export", async (_req, res) => {
  return res.json({ queued: true });
});
app.use("/api", documentRouter);
