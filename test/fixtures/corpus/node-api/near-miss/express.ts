import express from "express";
import { documentRouter } from "./routes/documents.js";

const app = express();

app.use("/api", documentRouter);
