import * as fs from "fs";
import * as path from "path";
import { RULES } from "./rules.js";
import type { Finding, ScanResult, Rule, Severity } from "./types.js";
import { SEVERITY_ORDER, LANG_EXTENSIONS } from "./types.js";

const MAX_LINE_LENGTH = 2000;

const EXT_TO_LANG: Record<string, string> = {};
for (const [lang, exts] of Object.entries(LANG_EXTENSIONS)) {
  for (const ext of exts) EXT_TO_LANG[ext] = lang;
}

const LANGUAGE_ALIASES: Record<string, string> = {
  javascript: "js",
  typescript: "ts",
  python: "py",
  ruby: "rb",
  csharp: "cs",
  golang: "go",
  yml: "yaml",
  htm: "html",
};

function resolveLanguage(input: string): string {
  const lower = input.toLowerCase().trim();
  return LANGUAGE_ALIASES[lower] ?? lower;
}

function matchRule(rule: Rule, line: string, language: string): boolean {
  if (!rule.languages.includes(language)) return false;
  const matched = rule.patterns.some((p) => p.test(line));
  if (!matched) return false;
  if (rule.negative_patterns?.some((np) => np.test(line))) return false;
  return true;
}

function resetRegexes(rule: Rule): void {
  rule.patterns.forEach((p) => { p.lastIndex = 0; });
  rule.negative_patterns?.forEach((p) => { p.lastIndex = 0; });
}

function assessConfidence(rule: Rule, line: string): "high" | "medium" | "low" {
  if (rule.category === "secrets" && /AKIA|ghp_|sk_live|-----BEGIN/.test(line)) return "high";
  if (rule.id === "sql-injection" && /SELECT|INSERT|DELETE|UPDATE/i.test(line)) return "high";
  if (rule.severity === "critical" || rule.severity === "high") return "medium";
  return "low";
}

function scanLines(
  lines: string[],
  language: string,
  filePath: string,
  severityThreshold: Severity = "info",
): Finding[] {
  const findings: Finding[] = [];
  const threshold = SEVERITY_ORDER[severityThreshold];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > MAX_LINE_LENGTH) continue;

    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;
    if (i > 0 && lines[i - 1]?.includes("codeguard-ignore")) continue;
    if (line.includes("codeguard-ignore")) continue;

    for (const rule of RULES) {
      if (SEVERITY_ORDER[rule.severity] > threshold) continue;
      if (!matchRule(rule, line, language)) continue;
      resetRegexes(rule);

      findings.push({
        rule_id: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: rule.category,
        file_path: filePath,
        line: i + 1,
        code_snippet: trimmed.slice(0, 200),
        cwe: rule.cwe,
        owasp: rule.owasp,
        confidence: assessConfidence(rule, line),
      });
    }
  }

  return dedup(findings);
}

function dedup(findings: Finding[]): Finding[] {
  findings.sort((a, b) => {
    const s = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (s !== 0) return s;
    const f = a.file_path.localeCompare(b.file_path);
    if (f !== 0) return f;
    return a.line - b.line;
  });

  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.rule_id}:${f.file_path}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function scanCode(code: string, language: string): ScanResult {
  const start = Date.now();
  const lang = resolveLanguage(language);
  const lines = code.split("\n");
  const findings = scanLines(lines, lang, "<snippet>", "info");

  return {
    findings,
    files_scanned: 1,
    duration_ms: Date.now() - start,
  };
}

export function scanFile(filePath: string): ScanResult {
  const start = Date.now();
  const abs = path.resolve(filePath);

  if (!fs.existsSync(abs)) {
    throw new Error(`File not found: ${abs}`);
  }

  const ext = path.extname(abs).toLowerCase();
  const lang = EXT_TO_LANG[ext];
  if (!lang) {
    return { findings: [], files_scanned: 1, duration_ms: Date.now() - start };
  }

  const content = fs.readFileSync(abs, "utf-8");
  const lines = content.split("\n");
  const findings = scanLines(lines, lang, filePath, "info");

  return {
    findings,
    files_scanned: 1,
    duration_ms: Date.now() - start,
  };
}
