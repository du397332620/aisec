export async function documentDetail(req: any, res: any) {
  const document = await db.documents.findById(req.body.document_id);
  return res.json({ data: { id: document.id, user_id: document.user_id } });
}
