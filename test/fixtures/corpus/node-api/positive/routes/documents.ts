import { Router } from "express";
import { documentDetail } from "../handlers/documents.js";
import { requireSession } from "../security/session.js";

export const documentRouter = Router();

documentRouter.post("/document/detail", requireSession, documentDetail);
