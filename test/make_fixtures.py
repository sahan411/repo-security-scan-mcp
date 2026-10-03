"""Creates two fixture apps for testing scan_repo.py.
All 'secrets' below are FAKE strings made to match patterns. Marker characters are stripped when files are written, so this source never contains a literal token pattern."""
import base64, json, os, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("FIXTURE_ROOT") or os.path.join(HERE, "fixtures")


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")


FAKE_SR_JWT = f'{b64({"alg": "HS256", "typ": "JWT"})}.{b64({"iss": "supabase", "ref": "fakeprojectref", "role": "service_role", "iat": 1700000000, "exp": 2000000000})}.fakeSignatureFakeSignature1234567890'
FAKE_ANON_JWT = f'{b64({"alg": "HS256", "typ": "JWT"})}.{b64({"iss": "supabase", "ref": "fakeprojectref", "role": "anon", "iat": 1700000000, "exp": 2000000000})}.fakeSignatureFakeSignature1234567890'


def w(base, rel, text):
    p = os.path.join(base, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(text.replace("§", ""))


def vulnerable():
    b = os.path.join(ROOT, "vulnerable-app")
    w(b, ".env", "STRIPE_SECRET_KEY=s§k_live_abcdefghijklmnopqrstuvwx\nDATABASE_URL=postgres://admin:hunter2pass@db.example.internal:5432/app\nOPENAI_API_KEY=s§k-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD\n")
    w(b, ".gitignore", "node_modules\n.next\n")
    w(b, "package.json", json.dumps({"name": "vuln-app", "dependencies": {"next": "latest", "express": "*", "react": "18.2.0"}, "scripts": {"dev": "next dev"}}, indent=2))
    w(b, "src/lib/supabase.ts", f'import {{ createClient }} from "@supabase/supabase-js";\nconst ADMIN = "{FAKE_SR_JWT}";\nexport const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, ADMIN);\n')
    w(b, "src/config.ts", 'export const cfg = { key: process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY, aws: "A§KIAABCDEFGHIJKLMNOP" };\n')
    w(b, "supabase/migrations/001_init.sql",
      "create table profiles (id uuid primary key, email text);\n"
      "create table orders (id serial primary key, user_id uuid, total numeric);\n"
      "create table notes (id serial primary key, body text);\n"
      "alter table notes enable row level security;\n"
      "create policy \"all\" on notes for select using (true);\n")
    w(b, "firestore.rules", "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n")
    w(b, "app/api/orders/route.ts",
      'import { db } from "@/lib/db";\nexport async function POST(request: Request) {\n  const body = await request.json();\n'
      '  const rows = await db.query("SELECT * FROM orders WHERE user_id = \'" + body.userId + "\'");\n  return Response.json(rows);\n}\n')
    w(b, "server.js",
      "const express = require('express');\nconst jwt = require('jsonwebtoken');\nconst cors = require('cors');\nconst app = express();\n"
      "app.use(cors({ origin: '*', credentials: true }));\n"
      "app.post('/calc', (req, res) => { res.json({ r: eval(req.body.expr) }); });\n"
      "const t = jwt.sign({ id: 1 }, 'secret', { algorithm: 'none' });\n"
      "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\napp.listen(3000);\n")
    w(b, "src/components/Post.tsx", 'export default function Post({ html }: { html: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n')
    w(b, "lib/db.py", "import requests\nDEBUG = True\n\ndef get_user(cursor, user_id):\n    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\nrequests.get('https://api.example.com', verify=False)\n")
    w(b, "README.md", "Example key format in docs is ignored: s§k_live_abcdefghijklmnopqrstuvwx\n")


def clean():
    b = os.path.join(ROOT, "clean-app")
    w(b, ".gitignore", "node_modules\n.next\n.env\n.env.*\n!.env.example\n")
    w(b, ".env.example", "STRIPE_SECRET_KEY=\nNEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    w(b, "package.json", json.dumps({"name": "clean-app", "dependencies": {"next": "15.0.0", "react": "18.2.0"}, "scripts": {"dev": "next dev", "test": "vitest"}}, indent=2))
    w(b, "package-lock.json", "{}")
    w(b, "src/lib/supabase.ts", 'import { createClient } from "@supabase/supabase-js";\nexport const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n')
    w(b, "supabase/migrations/001_init.sql",
      "create table profiles (id uuid primary key references auth.users, email text);\nalter table profiles enable row level security;\n"
      "create policy \"own profile\" on profiles for select using (auth.uid() = id);\n")
    w(b, "app/api/orders/route.ts",
      'import { getUser } from "@/lib/auth";\nimport { db } from "@/lib/db";\nexport async function POST(request: Request) {\n  const user = await getUser(request);\n  if (!user) return new Response("unauthorized", { status: 401 });\n'
      '  const body = await request.json();\n  const rows = await db.query("SELECT * FROM orders WHERE user_id = $1 AND id = $2", [user.id, body.id]);\n  return Response.json(rows);\n}\n')
    w(b, "src/components/Post.tsx", 'export default function Post({ text }: { text: string }) {\n  return <p>{text}</p>;\n}\n')


if __name__ == "__main__":
    if os.path.isdir(ROOT):
        shutil.rmtree(ROOT)
    vulnerable(); clean()
    print("fixtures written to", ROOT)
