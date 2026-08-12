import type { AssetGraph, ProjectProfile, ScanOptions } from "../schema.js";
import type { FileInventory } from "./files.js";

export interface ScanContext {
  root: string;
  inventory: FileInventory;
  profile: ProjectProfile;
  assetGraph: AssetGraph;
  options: ScanOptions;
}
