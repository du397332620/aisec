import { Router } from "express";
import { documentDetail, exportDocuments } from "../handlers/documents.js";
import { requireAdmin, requireSession } from "../security/session.js";

export const documentRouter = Router();

documentRouter.use(requireSession);
documentRouter.post("/admin/export", requireAdmin, exportDocuments);
documentRouter.post("/document/detail", documentDetail);
