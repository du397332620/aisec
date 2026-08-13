import { Router } from "express";
import { documentDetail, exportDocuments } from "../handlers/documents.js";
import { requireSession } from "../security/session.js";

export const documentRouter = Router();

documentRouter.use(requireSession);
documentRouter.post("/admin/export", exportDocuments);
documentRouter.post("/document/detail", documentDetail);
