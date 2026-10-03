#!/usr/bin/env node
// repo-security-scan-mcp: lets Claude (or any MCP client) triage an AI-built web app for the classic
// vibe-coding security problems. Local only: it reads a folder you point it at, never opens network
// connections and never probes live sites. Secrets are redacted (first 4 chars) by the scanner.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCANNER = join(HERE, "scan_repo.py");
const PYTHON = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
const SEV = ["HIGH", "MEDIUM", "LOW", "INFO"];
const SCAN_TIMEOUT_MS = 60_000;

function runScan(path, maxMb) {
  const abs = resolve(path);
  if (!existsSync(abs) || !statSync(abs).isDirectory()) throw new Error(`Not a directory: ${abs}`);
  const dir = mkdtempSync(join(tmpdir(), "rss-"));
  const out = join(dir, "findings.json");
  try {
    const r = spawnSync(PYTHON, [SCANNER, abs, "--md", join(dir, "report.md"), "--json", out, "--max-mb", String(maxMb)], {
      encoding: "utf8",
      timeout: SCAN_TIMEOUT_MS,
    });
    if (r.error) throw new Error(`Could not run ${PYTHON}: ${r.error.message}`);
    // exit code 1 just means "at least one HIGH finding"; anything else non-zero is a real failure
    if (r.status !== 0 && r.status !== 1) throw new Error(`Scanner failed (${r.status}): ${(r.stderr || "").slice(0, 400)}`);
    const findings = JSON.parse(readFileSync(out, "utf8"));
    const m = /files=(\d+)/.exec(r.stderr || "");
    return { abs, findings, files: m ? Number(m[1]) : null };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function summarize(findings) {
  const c = Object.fromEntries(SEV.map((s) => [s, 0]));
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

const DISCLAIMER =
  "Heuristic static scan, not a penetration test. It produces false positives and misses issues. Review each finding before acting; rotate any exposed secret immediately.";

const server = new McpServer({ name: "repo-security-scan", version: "0.1.0" });

server.registerTool(
  "scan_repo",
  {
    title: "Scan a local repo for AI-built-app security problems",
    description:
      "Scans a local project folder (Next.js, Vite, Express, Supabase, Firebase style) for leaked secrets, secrets exposed to the browser, " +
      "missing Supabase row-level security, wildcard CORS, open Firebase rules, dangerous code patterns and API routes without a visible auth check. " +
      "Returns counts plus findings ordered by severity. Secrets are redacted.",
    inputSchema: {
      path: z.string().describe("Absolute or relative path to the project folder"),
      min_severity: z.enum(SEV).default("LOW").describe("Hide findings below this severity"),
      limit: z.number().int().min(1).max(200).default(40).describe("Maximum findings to return"),
      max_mb: z.number().min(0.1).max(10).default(1.5).describe("Skip files larger than this many MB"),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  },
  async ({ path, min_severity, limit, max_mb }) => {
    try {
      const { abs, findings, files } = runScan(path, max_mb);
      const cutoff = SEV.indexOf(min_severity);
      const shown = findings
        .filter((f) => SEV.indexOf(f.severity) <= cutoff)
        .sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity))
        .slice(0, limit);
      const payload = { scanned: abs, files_scanned: files, counts: summarize(findings), shown: shown.length, findings: shown, note: DISCLAIMER };
      return { content: [{ type: "text", text: JSON.stringify(payload, null, 1) }], structuredContent: payload };
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: String(e.message || e) }] };
    }
  }
);

server.registerTool(
  "triage_summary",
  {
    title: "One-paragraph triage of a repo scan",
    description: "Runs the same scan and returns a short plain-English triage: what to fix first and why. Good for a quick go/no-go before deploying.",
    inputSchema: { path: z.string().describe("Path to the project folder") },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  },
  async ({ path }) => {
    try {
      const { abs, findings } = runScan(path, 1.5);
      const c = summarize(findings);
      const top = findings.filter((f) => f.severity === "HIGH").slice(0, 5);
      const lines = [
        `Scanned ${abs}: ${c.HIGH} high, ${c.MEDIUM} medium, ${c.LOW} low, ${c.INFO} info.`,
        c.HIGH
          ? "Do not deploy until the HIGH items are fixed. Fix first:"
          : "No HIGH findings from the heuristics. Still check auth and data access by hand before launch.",
        ...top.map((f) => `- [${f.rule}] ${f.title} (${f.path}:${f.line}). Fix: ${f.fix}`),
        DISCLAIMER,
      ];
      return { content: [{ type: "text", text: lines.join("\n") }] };
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: String(e.message || e) }] };
    }
  }
);

await server.connect(new StdioServerTransport());
