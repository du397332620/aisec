import express from "express";

const app = express();

function authenticate(req: any, res: any, next: any) {
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  next();
}

app.post("/admin/export", async (_req, res) => {
  return res.json({ queued: true });
});

app.post("/document/detail", authenticate, async (req, res) => {
  const document = await db.documents.findById(req.body.document_id);
  return res.json({ data: { id: document.id, user_id: document.user_id } });
});
