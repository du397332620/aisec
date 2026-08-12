export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session || session.user.role !== "admin") {
    return new Response("Forbidden", { status: 403 });
  }
  const body = await req.json();
  const userId = validateUuid(body.userId);
  const user = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
  return Response.json(user);
}
