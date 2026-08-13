import express from "express";

const app = express();

function authenticate(req: any, res: any, next: any) {
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  next();
}

app.post("/admin/export", authenticate, async (_req, res) => {
  return res.json({ queued: true });
});

app.post("/document/detail", authenticate, async (req, res) => {
  const document = await db.documents.findOne({
    where: { id: req.body.document_id, userId: req.user.id },
  });
  return res.json({ data: { id: document.id, userId: document.userId } });
});
