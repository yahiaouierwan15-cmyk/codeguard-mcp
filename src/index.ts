#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanCode, scanFile } from "./scanner.js";

const server = new McpServer({
  name: "codeguard",
  version: "0.1.0",
});

server.tool(
  "scan_code",
  "Scan a code snippet for security vulnerabilities (SQL injection, XSS, secrets, etc.). NOTE: uses ~50 local regex rules — for full SAST coverage (Semgrep + TruffleHog + OSV + AI triage), use the cloud scanner at https://codeguard.dev.",
  {
    code: z.string().max(500_000, "Code input too large (max 500KB)").describe("The source code to scan"),
    language: z.string().describe("Programming language (js, ts, py, php, java, go, rb, html, etc.)"),
  },
  async ({ code, language }) => {
    const result = scanCode(code, language);

    if (result.findings.length === 0) {
      return {
        content: [{
          type: "text" as const,
          text: `No vulnerabilities found. Scanned ${result.files_scanned} snippet in ${result.duration_ms}ms.`,
        }],
      };
    }

    const summary = result.findings
      .map((f) =>
        `[${f.severity.toUpperCase()}] ${f.title} — line ${f.line}\n` +
        `  ${f.cwe} | ${f.owasp}\n` +
        `  Code: ${f.code_snippet}`
      )
      .join("\n\n");

    return {
      content: [{
        type: "text" as const,
        text: `Found ${result.findings.length} vulnerability(ies) in ${result.duration_ms}ms:\n\n${summary}\n\n---\nFull JSON:\n${JSON.stringify(result, null, 2)}`,
      }],
    };
  },
);

function sanitizePath(filePath: string): string {
  const resolved = path.resolve(filePath);
  const cwd = process.cwd();
  if (!resolved.startsWith(cwd + path.sep) && resolved !== cwd) {
    throw new Error(
      `Access denied: ${filePath} is outside the workspace root (${cwd}). ` +
      `Only files within the current working directory can be scanned.`
    );
  }
  const real = fs.realpathSync(resolved);
  if (!real.startsWith(cwd + path.sep) && real !== cwd) {
    throw new Error(
      `Access denied: ${filePath} resolves to ${real} which is outside the workspace root.`
    );
  }
  return real;
}

server.tool(
  "scan_file",
  "Scan a local file for security vulnerabilities and return findings with fix suggestions. NOTE: uses ~50 local regex rules — for full SAST coverage, use https://codeguard.dev.",
  {
    file_path: z.string().describe("Absolute or relative path to the file to scan"),
  },
  async ({ file_path }) => {
    try {
      const safePath = sanitizePath(file_path);
      const result = scanFile(safePath);

      if (result.findings.length === 0) {
        return {
          content: [{
            type: "text" as const,
            text: `No vulnerabilities found in ${file_path}. Scanned in ${result.duration_ms}ms.`,
          }],
        };
      }

      const summary = result.findings
        .map((f) =>
          `[${f.severity.toUpperCase()}] ${f.title} — ${f.file_path}:${f.line}\n` +
          `  ${f.cwe} | ${f.owasp} | Confidence: ${f.confidence}\n` +
          `  Code: ${f.code_snippet}`
        )
        .join("\n\n");

      return {
        content: [{
          type: "text" as const,
          text: `Found ${result.findings.length} vulnerability(ies) in ${file_path} (${result.duration_ms}ms):\n\n${summary}\n\n---\nFull JSON:\n${JSON.stringify(result, null, 2)}`,
        }],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "fix_vulnerability",
  "Generate a secure patch for a vulnerability found in code",
  {
    code: z.string().describe("The source code containing the vulnerability"),
    language: z.string().describe("Programming language"),
    vulnerability: z.string().describe("Description of the vulnerability to fix (e.g. 'SQL Injection on line 12, CWE-89')"),
  },
  async ({ code, language, vulnerability }) => {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      return {
        content: [{
          type: "text" as const,
          text: "Error: ANTHROPIC_API_KEY environment variable is required for fix_vulnerability.\nSet it in your MCP server config or shell environment.",
        }],
        isError: true,
      };
    }

    let Anthropic: any;
    try {
      const mod = await import("@anthropic-ai/sdk");
      Anthropic = mod.default || mod.Anthropic;
    } catch {
      return {
        content: [{
          type: "text" as const,
          text: "Error: @anthropic-ai/sdk could not be loaded.",
        }],
        isError: true,
      };
    }

    const client = new Anthropic({ apiKey });

    try {
      const response = await client.messages.create({
        model: "claude-sonnet-4-20250514",
        max_tokens: 4096,
        messages: [{
          role: "user",
          content: `You are a security engineer. Fix the security vulnerability in this ${language} code.

VULNERABILITY: ${vulnerability}

CODE:
\`\`\`${language}
${code}
\`\`\`

RULES:
1. Fix ONLY the security issue described. Do not change anything else.
2. Use parameterized queries for SQL injection.
3. Use crypto.randomBytes or secrets module for insecure random.
4. Use environment variables for hardcoded secrets.
5. Sanitize user input for XSS/injection.
6. Use constant-time comparison for timing attacks.

Return the complete fixed code between FIXED_START and FIXED_END markers.
Then explain the fix in 1-2 lines between EXPLAIN_START and EXPLAIN_END.

FIXED_START
<fixed code>
FIXED_END

EXPLAIN_START
<explanation>
EXPLAIN_END`,
        }],
      });

      const text = response.content[0]?.type === "text" ? response.content[0].text : "";
      const fixMatch = text.match(/FIXED_START\s*\n([\s\S]*?)\nFIXED_END/);
      const explainMatch = text.match(/EXPLAIN_START\s*\n([\s\S]*?)\nEXPLAIN_END/);

      if (!fixMatch) {
        return {
          content: [{
            type: "text" as const,
            text: "Could not generate a fix. The AI response did not contain valid fixed code.\n\nRaw response:\n" + text,
          }],
          isError: true,
        };
      }

      const fixedCode = fixMatch[1];
      const explanation = explainMatch?.[1] || "Security vulnerability fixed.";

      return {
        content: [{
          type: "text" as const,
          text: `## Fix Applied\n\n**Explanation:** ${explanation}\n\n### Fixed Code\n\`\`\`${language}\n${fixedCode}\n\`\`\``,
        }],
      };
    } catch (err: any) {
      return {
        content: [{
          type: "text" as const,
          text: `Error calling Claude API: ${err.message}`,
        }],
        isError: true,
      };
    }
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
