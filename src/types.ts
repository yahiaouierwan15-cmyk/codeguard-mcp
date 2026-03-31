export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  category: string;
  file_path: string;
  line: number;
  code_snippet: string;
  cwe: string;
  owasp: string;
  confidence: "high" | "medium" | "low";
}

export interface ScanResult {
  findings: Finding[];
  files_scanned: number;
  duration_ms: number;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  cwe: string;
  owasp: string;
  languages: string[];
  patterns: RegExp[];
  negative_patterns?: RegExp[];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const LANG_EXTENSIONS: Record<string, string[]> = {
  js: [".js", ".mjs", ".cjs"],
  ts: [".ts", ".mts", ".cts"],
  jsx: [".jsx"],
  tsx: [".tsx"],
  py: [".py"],
  php: [".php"],
  rb: [".rb"],
  java: [".java"],
  cs: [".cs"],
  go: [".go"],
  yaml: [".yaml", ".yml"],
  json: [".json"],
  env: [".env"],
  html: [".html", ".htm"],
};
