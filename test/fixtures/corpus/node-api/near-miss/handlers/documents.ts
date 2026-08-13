export async function exportDocuments(_req: any, res: any) {
  return res.json({ queued: true });
}

export async function documentDetail(req: any, res: any) {
  const document = await db.documents.findOne({
    where: { id: req.body.document_id, userId: req.user.id },
  });
  return res.json({ data: { id: document.id, userId: document.userId } });
}
