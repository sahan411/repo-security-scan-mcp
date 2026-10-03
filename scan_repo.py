#!/usr/bin/env python3
"""scan_repo.py - fast, dependency-free heuristic scanner for AI-built (vibe-coded) web apps.

What it is: a triage tool that finds the classic problems in Next.js / Vite / Express / Supabase / Firebase
style projects: leaked secrets, secrets exposed to the browser, missing row-level security, wildcard CORS,
open Firebase rules, dangerous code patterns and API routes with no visible auth check.

What it is NOT: a penetration test or a guarantee. Static heuristics produce false positives AND miss things.
Every finding needs a human/Claude review before it goes into a client report.

usage: python scan_repo.py <path> [--md report.md] [--json findings.json] [--max-mb 1.5]
Secrets are always redacted in output (first 4 characters only).
"""
import argparse, base64, json, os, re, sys
from collections import Counter, defaultdict

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "out", ".venv", "venv", "__pycache__", ".turbo",
             ".cache", "coverage", ".parcel-cache", ".svelte-kit", ".nuxt", "vendor", "target", ".idea", ".vscode"}
TEXT_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".py", ".rb", ".php", ".go", ".java", ".env", ".yml", ".yaml",
            ".toml", ".sql", ".rules", ".html", ".htm", ".vue", ".svelte", ".md", ".txt", ".sh", ".ini", ".cfg", ".conf", ".prisma"}
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

# ---- secret patterns: (rule id, name, regex, severity) ----
SECRET_RULES = [
    ("SEC-AWS", "AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "HIGH"),
    ("SEC-GOOGLE", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "MEDIUM"),
    ("SEC-STRIPE", "Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "HIGH"),
    ("SEC-STRIPE-R", "Stripe restricted key", re.compile(r"\brk_live_[0-9a-zA-Z]{20,}\b"), "HIGH"),
    ("SEC-GITHUB", "GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "HIGH"),
    ("SEC-OPENAI", "OpenAI-style secret key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), "HIGH"),
    ("SEC-ANTHROPIC", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{30,}\b"), "HIGH"),
    ("SEC-SLACK", "Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "HIGH"),
    ("SEC-SENDGRID", "SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}\b"), "HIGH"),
    ("SEC-PRIVKEY", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "HIGH"),
    ("SEC-DBURL", "Database URL with embedded password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@'\"]+:[^\s@'\"]{3,}@"), "HIGH"),
]
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
GENERIC_SECRET_RE = re.compile(r"""(?ix)\b(api[_-]?key|secret|passwd|password|token|private[_-]?key)\b\s*[:=]\s*(['"])([^'"\s]{12,})\2""")
PLACEHOLDER_HINTS = ("example", "your", "xxxx", "changeme", "placeholder", "<", "process.env", "env.", "os.environ", "dummy", "sample", "test", "todo", "****", "....")

PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_", "NUXT_PUBLIC_")
SECRET_WORDS = ("SECRET", "SERVICE_ROLE", "PRIVATE", "PASSWORD", "ADMIN_KEY", "DATABASE_URL", "STRIPE_SECRET", "OPENAI", "ANTHROPIC")


def redact(s):
    s = s.strip()
    return (s[:4] + "****") if len(s) > 4 else "****"


class Finding:
    def __init__(self, rule, severity, title, path, line, evidence, why, fix):
        self.rule, self.severity, self.title, self.path, self.line = rule, severity, title, path, line
        self.evidence, self.why, self.fix = evidence, why, fix

    def as_dict(self):
        return self.__dict__


def is_text(path):
    ext = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).lower()
    return ext in TEXT_EXT or name.startswith(".env") or name in ("dockerfile", ".gitignore", "firestore.rules", "storage.rules")


def walk(root, max_bytes):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            p = os.path.join(dp, fn)
            try:
                if os.path.getsize(p) > max_bytes or not is_text(p):
                    continue
            except OSError:
                continue
            yield p


def read_lines(p):
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def jwt_role(tok):
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode())).get("role")
    except Exception:
        return None


def scan(root, max_mb=1.5):
    root = os.path.abspath(root)
    max_bytes = int(max_mb * 1024 * 1024)
    F = []
    files = list(walk(root, max_bytes))
    rel = lambda p: os.path.relpath(p, root).replace("\\", "/")
    gitignore = "\n".join(read_lines(os.path.join(root, ".gitignore")))
    env_ignored = bool(re.search(r"(^|\n)\s*\.env(\.\*|\*)?\s*($|\n)|(^|\n)\s*\.env\*", gitignore))
    sql_tables, sql_rls = {}, set()
    has_lock = any(os.path.exists(os.path.join(root, n)) for n in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "poetry.lock", "Pipfile.lock", "requirements.txt"))

    for p in files:
        r = rel(p)
        base = os.path.basename(p).lower()
        lines = read_lines(p)
        ext = os.path.splitext(p)[1].lower()
        is_client = bool(re.search(r"(^|/)(src|app|components|pages|public|client|frontend|lib)/", r)) and not re.search(r"(^|/)(api|server)/", r)
        is_doc = ext in (".md", ".txt")

        # committed env files
        if re.match(r"\.env(\..+)?$", base) and not base.endswith((".example", ".sample", ".template")):
            body = [l for l in lines if l.strip() and not l.strip().startswith("#") and "=" in l]
            if body:
                F.append(Finding("ENV-COMMITTED", "HIGH" if not env_ignored else "MEDIUM", "Environment file present in project folder", r, 1,
                                 f"{len(body)} variable(s) defined; values not shown",
                                 "Env files hold live credentials. If this folder is a git repo and the file is tracked or was ever committed, treat every value as leaked.",
                                 "Add .env* to .gitignore, remove from git history (git filter-repo), and ROTATE every key in it."))

        for i, line in enumerate(lines, 1):
            s = line.strip()
            if len(s) > 2000:
                continue
            low = s.lower()
            # secrets
            if not is_doc:
                for rid, name, rx, sev0 in SECRET_RULES:
                    sev = sev0
                    m = rx.search(line)
                    if m and not any(h in m.group(0).lower() for h in ("example", "xxxx", "your_", "<your")):
                        if rid == "SEC-DBURL" and ("localhost" in low or "127.0.0.1" in low):
                            sev = "LOW"  # local development database
                        F.append(Finding(rid, sev, f"Hard-coded secret: {name}", r, i, redact(m.group(0)),
                                         "Secrets in source are readable by anyone with repo access and by browsers if bundled into client code.",
                                         "Move to environment variables / a secret manager, rotate the key, and purge it from git history."))
                for m in JWT_RE.finditer(line):
                    role = jwt_role(m.group(0))
                    if role == "service_role":
                        F.append(Finding("SEC-SUPABASE-SR", "HIGH", "Supabase service_role key in source", r, i, redact(m.group(0)),
                                         "The service_role key bypasses row-level security. If it ships to the browser, anyone can read and write your entire database.",
                                         "Use it only in server-side code with env vars; rotate the key in the Supabase dashboard now."))
                g = GENERIC_SECRET_RE.search(line)
                if g and not any(h in g.group(3).lower() for h in PLACEHOLDER_HINTS) and not re.search(r"(?i)(process\.env|os\.environ|getenv)", line):
                    F.append(Finding("SEC-GENERIC", "MEDIUM", f"Possible hard-coded credential ({g.group(1)})", r, i, redact(g.group(3)),
                                     "Literal credential-like value assigned in code.", "Verify. If real: env var + rotate. If a test value: rename clearly."))
            # secrets exposed to browser via public env prefixes
            pm = re.search(r"\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)[A-Z0-9_]+)\b", line)
            if pm:
                nm = pm.group(1)
                tail = nm.split("_", 2)[-1] if nm.count("_") >= 2 else nm
                if any(w in nm for w in SECRET_WORDS) and not any(ok in nm for ok in ("ANON", "PUBLISHABLE", "PUBLIC_KEY", "SITE_KEY", "CLIENT_ID")):
                    F.append(Finding("PUB-SECRET", "HIGH", "Secret-looking variable exposed to the browser", r, i, nm,
                                     "Variables with these prefixes are compiled into client bundles and visible to every visitor.",
                                     "Rename without the public prefix and read it only in server code; rotate the value."))
            if re.search(r"service_role|SERVICE_ROLE", line) and is_client and not is_doc and "process.env" in line + "".join(lines[max(0, i - 3):i + 3]):
                F.append(Finding("SB-SR-CLIENT", "HIGH", "service_role referenced in client-side code", r, i, s[:100],
                                 "Client-side files are shipped to browsers.", "Move the call behind a server route/edge function."))
            # dangerous patterns
            if not is_doc:
                if re.search(r"\beval\s*\(", line) or re.search(r"new\s+Function\s*\(", line):
                    F.append(Finding("DANGER-EVAL", "MEDIUM", "eval / new Function", r, i, s[:100], "Executes strings as code; classic injection vector.", "Replace with a safe parser or lookup table."))
                if "dangerouslySetInnerHTML" in line or re.search(r"\.innerHTML\s*=", line):
                    F.append(Finding("XSS-HTML", "MEDIUM", "Raw HTML injection (XSS risk)", r, i, s[:100], "Unsanitised HTML can run attacker scripts.", "Sanitise with DOMPurify or render text."))
                if re.search(r"(?i)(execute|query|raw|exec)\s*\(\s*(f['\"]|['\"].*(select|insert|update|delete).*['\"]\s*\+|`.*(select|insert|update|delete).*\$\{)", line):
                    F.append(Finding("SQLI", "HIGH", "SQL built from string concatenation/interpolation", r, i, s[:100], "User input in SQL text enables SQL injection.", "Use parameterised queries / the ORM query builder."))
                if re.search(r"\bexec(Sync)?\(\s*(`|[^)]*\+)|shell\s*:\s*true|subprocess\.(call|run|Popen)\(.*shell\s*=\s*True|os\.system\(", line):
                    F.append(Finding("CMD-INJ", "MEDIUM", "Shell command execution", r, i, s[:100], "Commands built from user input allow remote code execution.", "Avoid shell; pass argument arrays and validate input."))
                if re.search(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", line):
                    F.append(Finding("TLS-OFF", "MEDIUM", "TLS certificate verification disabled", r, i, s[:100], "Allows man-in-the-middle attacks.", "Remove; fix the certificate instead."))
                if re.search(r"(?i)algorithm['\"]?\s*[:=]\s*['\"]none['\"]|jwt\.decode\([^)]*\)(?!.*verify)", line) and "verify" not in low:
                    F.append(Finding("JWT-WEAK", "MEDIUM", "JWT accepted without verification / alg none", r, i, s[:100], "Tokens can be forged.", "Use jwt.verify with a strong secret and fixed algorithm."))
                if re.search(r"(?i)\b(md5|sha1)\b.*\bpassword|password.*\b(md5|sha1)\b", line):
                    F.append(Finding("PWD-HASH", "MEDIUM", "Weak password hashing", r, i, s[:100], "MD5/SHA1 are fast to brute-force.", "Use bcrypt/argon2."))
                if re.search(r"(?i)^\s*DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True", line):
                    F.append(Finding("DEBUG-ON", "MEDIUM", "Debug mode enabled", r, i, s[:100], "Debug servers leak stack traces and can allow code execution.", "Disable debug in production."))
                # CORS
                if re.search(r"(?i)access-control-allow-origin['\"]?\s*[:,]\s*['\"]?\*", line) or re.search(r"(?i)origin\s*:\s*['\"]\*['\"]", line):
                    F.append(Finding("CORS-WILD", "MEDIUM", "Wildcard CORS origin", r, i, s[:100], "Any website can call this API from a visitor's browser (dangerous with cookies/credentials).", "Allow-list your real origins."))
            # firebase rules
            if ext == ".rules" or base in ("firestore.rules", "storage.rules"):
                if re.search(r"allow\s+[a-z, ]*(read|write)[a-z, ]*\s*:\s*if\s+true", line):
                    F.append(Finding("FB-OPEN", "HIGH", "Firebase rules allow everyone", r, i, s[:100], "Anyone on the internet can read/write this data.", "Require request.auth and ownership checks."))
                if re.search(r"request\.time\s*<\s*timestamp\.date", line):
                    F.append(Finding("FB-TEMP", "MEDIUM", "Firebase test-mode rule (time-limited open access)", r, i, s[:100], "Default test rules expire and are open until then.", "Replace with auth-based rules."))
            # sql
            if ext == ".sql":
                mt = re.search(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?([\w\.\"]+)", line)
                if mt:
                    sql_tables.setdefault(mt.group(1).replace('"', "").split(".")[-1].lower(), (r, i))
                mr = re.search(r"(?i)alter\s+table\s+([\w\.\"]+)\s+enable\s+row\s+level\s+security", line)
                if mr:
                    sql_rls.add(mr.group(1).replace('"', "").split(".")[-1].lower())
                if re.search(r"(?i)using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)", line):
                    F.append(Finding("RLS-TRUE", "HIGH", "Row-level-security policy that allows everything (true)", r, i, s[:100], "A policy of true means no restriction.", "Scope policies to auth.uid() ownership or roles."))

        # API route with no visible auth
        if re.search(r"(^|/)(app/api/.+/route|pages/api/.+|api/.+|routes/.+|server/.+)\.(ts|js|mjs|py)$", r):
            text = "\n".join(lines)
            if re.search(r"(?i)\b(POST|PUT|PATCH|DELETE)\b|req\.body|request\.json|request\.form", text) and not re.search(
                    r"(?i)(auth|session|getuser|getserversession|currentuser|verify|jwt|middleware|clerk|nextauth|supabase\.auth|bearer|apikey|api_key|login_required|permission)", text):
                F.append(Finding("AUTH-NONE", "MEDIUM", "State-changing API route with no visible auth check", r, 1, "no auth/session keyword found in file",
                                 "AI-generated endpoints often skip authorisation; anyone who finds the URL can call it.",
                                 "Verify the caller server-side and check the resource belongs to them (avoids broken object-level authorisation)."))

    for t, (r, i) in sql_tables.items():
        if t not in sql_rls:
            F.append(Finding("RLS-MISSING", "HIGH", f"Table '{t}' created without row-level security", r, i, f"create table {t}",
                             "On Supabase/Postgres exposed through an API, tables without RLS are readable and writable by anyone holding the public anon key.",
                             f"alter table {t} enable row level security; then add owner-scoped policies."))
    if not has_lock:
        F.append(Finding("DEP-LOCK", "LOW", "No lockfile found", ".", 0, "package-lock/yarn.lock/pnpm-lock/requirements not found",
                         "Without a lockfile, builds are not reproducible and dependencies can change under you.", "Commit the lockfile."))
    pj = os.path.join(root, "package.json")
    if os.path.exists(pj):
        try:
            data = json.load(open(pj, encoding="utf-8", errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            loose = [k for k, v in deps.items() if str(v).strip() in ("*", "latest", "")]
            if loose:
                F.append(Finding("DEP-LOOSE", "LOW", "Unpinned dependencies ('*' or 'latest')", "package.json", 1, ", ".join(loose[:6]),
                                 "Any release, including a compromised one, is installed automatically.", "Pin versions."))
            if "test" not in (data.get("scripts") or {}):
                F.append(Finding("QA-NOTEST", "INFO", "No test script", "package.json", 1, "scripts.test missing", "AI-generated code changes often; no tests means regressions go unnoticed.", "Add tests for auth and payment flows first."))
        except Exception:
            pass
    F.sort(key=lambda f: (SEV_ORDER[f.severity], f.path, f.line))
    return F, len(files)


def to_markdown(findings, nfiles, root):
    cnt = Counter(f.severity for f in findings)
    out = [f"# Automated security triage: `{os.path.basename(os.path.abspath(root))}`", "",
           f"Files scanned: **{nfiles}**  |  Findings: **{len(findings)}**  (HIGH {cnt['HIGH']}, MEDIUM {cnt['MEDIUM']}, LOW {cnt['LOW']}, INFO {cnt['INFO']})", "",
           "> Static heuristic scan. It finds common problems quickly but is **not a penetration test** and is not a guarantee of security. "
           "Findings can be false positives and important issues can be missed. Secret values are redacted.", ""]
    by = defaultdict(list)
    for f in findings:
        by[f.severity].append(f)
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        if not by[sev]:
            continue
        out.append(f"## {sev}")
        for f in by[sev]:
            out += [f"### [{f.rule}] {f.title}", f"- **Where:** `{f.path}:{f.line}`", f"- **Evidence:** `{f.evidence}`",
                    f"- **Why it matters:** {f.why}", f"- **Fix:** {f.fix}", ""]
    if not findings:
        out.append("No findings from the automated checks. This does not mean the app is secure.")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--md")
    ap.add_argument("--json")
    ap.add_argument("--max-mb", type=float, default=1.5)
    a = ap.parse_args()
    if not os.path.isdir(a.path):
        sys.exit(f"not a directory: {a.path}")
    findings, n = scan(a.path, a.max_mb)
    md = to_markdown(findings, n, a.path)
    if a.md:
        open(a.md, "w", encoding="utf-8").write(md)
    if a.json:
        json.dump([f.as_dict() for f in findings], open(a.json, "w", encoding="utf-8"), indent=1)
    if not a.md:
        print(md)
    c = Counter(f.severity for f in findings)
    print(f"\nSUMMARY files={n} HIGH={c['HIGH']} MEDIUM={c['MEDIUM']} LOW={c['LOW']} INFO={c['INFO']}", file=sys.stderr)
    sys.exit(1 if c["HIGH"] else 0)


if __name__ == "__main__":
    main()
