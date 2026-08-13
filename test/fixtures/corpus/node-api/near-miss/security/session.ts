export function requireSession(req: any, res: any, next: any) {
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  next();
}

export function requireAdmin(req: any, res: any, next: any) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "forbidden" });
  next();
}
