import { exec } from "node:child_process";

export async function POST(req: any) {
  const userId = req.body.userId;
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  await db.query(query);

  const completion = await openai.chat.completions.create({
    messages: [{ role: "user", content: req.body.prompt }],
  });
  const command = completion.choices[0].message.content;
  exec(command);
  return Response.json({ ok: true });
}
