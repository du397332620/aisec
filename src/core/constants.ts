export const TOOL_VERSION = "0.1.0";

export const DEFAULT_EXCLUDES = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "vendor",
  "Pods",
  ".dart_tool",
  ".gradle",
  ".next",
  ".nuxt",
  "dist",
  "build",
  "coverage",
  ".cache",
  ".idea",
  ".vscode",
]);

export const TEXT_EXTENSIONS = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
  ".json", ".jsonc", ".yaml", ".yml", ".toml", ".env", ".sql",
  ".dart", ".java", ".kt", ".kts", ".swift", ".m", ".mm", ".xml",
  ".plist", ".gradle", ".properties", ".html", ".css", ".scss", ".md",
  ".py", ".go", ".rb", ".php", ".cs", ".rs", ".sh", ".graphql",
  ".rules",
]);

export const MANIFEST_NAMES = new Set([
  "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
  "pubspec.yaml", "pubspec.lock", "Podfile", "Podfile.lock", "Gemfile",
  "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml",
  "build.gradle", "build.gradle.kts", "AndroidManifest.xml", "Info.plist",
  "firebase.json", ".firebaserc", "app.json", "app.config.js", "app.config.ts",
]);

export const SEVERITY_RANK = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const;
