export async function POST(request: Request) {
  const { accessToken } = await request.json();
  console.log(accessToken);
  return Response.json({ updated: true });
}
