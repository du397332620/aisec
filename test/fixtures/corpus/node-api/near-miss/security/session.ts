export function requireSession(req: any, res: any, next: any) {
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  next();
}
