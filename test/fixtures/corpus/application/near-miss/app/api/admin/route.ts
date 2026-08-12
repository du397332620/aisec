export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session || session.user.role !== "admin") return new Response("Forbidden", { status: 403 });
  console.info("admin update", { requestId: request.headers.get("x-request-id") });
  return Response.json({ updated: true });
}
