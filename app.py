from __future__ import annotations

import csv
import io
import os
import secrets
import sqlite3
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timedelta
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from flask import (
    Flask, Response, abort, jsonify, redirect, render_template_string,
    request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

APP_NAME = "SafeLab Online 3.0"

def app_directory() -> Path:
    # Keep the database beside the executable when packaged, otherwise beside this file.
    base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    return base

DATA_DIR = Path(os.environ.get("SAFELAB_DATA_DIR", str(app_directory())))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "safelab_online.db"

app = Flask(__name__)
app.secret_key = os.environ.get("SAFELAB_SECRET_KEY") or "development-only-change-me"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SAFELAB_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

db_lock = threading.RLock()
rate_lock = threading.Lock()
login_attempts: dict[str, list[float]] = {}
task_threads: set[threading.Thread] = set()

def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")

@contextmanager
def connect_db():
    c = sqlite3.connect(DB_PATH, timeout=20)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA journal_mode=WAL")
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

def init_db():
    with db_lock, connect_db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
            created_at TEXT NOT NULL
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS tasks(
            id TEXT PRIMARY KEY, type TEXT NOT NULL, status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0, target TEXT NOT NULL,
            result TEXT, owner_id INTEGER, owner_name TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(id DESC)")
        # Create the initial admin only once. Change this password immediately.
        if not c.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            admin_password = os.environ.get("SAFELAB_ADMIN_PASSWORD", "ChangeMe-Admin-2026!")
            c.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                ("admin", generate_password_hash(admin_password), "admin", now())
            )

def audit(action: str, detail: str = "", username: str | None = None):
    with db_lock, connect_db() as c:
        c.execute(
            "INSERT INTO logs(username,action,detail,created_at) VALUES(?,?,?,?)",
            (username or session.get("username", "system"), action, detail[:300], now())
        )

def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

@app.before_request
def protect_mutations():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(str(supplied), str(expected)):
            if request.path.startswith("/api/"):
                return jsonify(error="CSRF token không hợp lệ. Hãy tải lại trang."), 400
            abort(400, description="CSRF token không hợp lệ.")

def logged_in(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify(error="Vui lòng đăng nhập."), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_only(fn):
    @wraps(fn)
    @logged_in
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify(error="Chỉ quản trị viên mới được phép."), 403
        return fn(*args, **kwargs)
    return wrapper

def valid_username(value: str) -> bool:
    return 3 <= len(value) <= 32 and value.replace("_", "").isalnum()

def login_limited(ip: str) -> bool:
    cutoff = time.time() - 300
    with rate_lock:
        attempts = [t for t in login_attempts.get(ip, []) if t > cutoff]
        login_attempts[ip] = attempts
        return len(attempts) >= 10

def record_login_failure(ip: str):
    with rate_lock:
        login_attempts.setdefault(ip, []).append(time.time())

def dashboard_template():
    return PAGE

LOGIN_PAGE = r"""
<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Đăng nhập · SafeLab</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#08111f;color:#edf4ff;font:15px system-ui}
.card{width:min(94vw,430px);padding:30px;background:#14233a;border:1px solid #2c405f;border-radius:20px;box-shadow:0 20px 60px #0005}
h1{margin:0;font-size:26px}p{color:#a8bad2}.brand{color:#72e0bf}label{display:block;margin:15px 0 6px}
input{width:100%;padding:12px;background:#0b1527;color:white;border:1px solid #3b4e6c;border-radius:9px}
button,.btn{display:inline-block;width:100%;padding:12px;margin-top:18px;border:0;border-radius:9px;background:linear-gradient(100deg,#7baeff,#5be0b6);color:#071323;font-weight:800;text-decoration:none;text-align:center;cursor:pointer}
a{color:#8dbbff}.error{color:#ffb5bd}.hint{font-size:12px;color:#9aadc7}
</style></head><body><main class="card"><h1>◈ <span class="brand">SafeLab</span> Online 3.0</h1>
<p>{{subtitle}}</p>{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
<label>Tên đăng nhập</label><input name="username" required minlength="3" maxlength="32" autocomplete="username">
<label>Mật khẩu</label><input name="password" type="password" required autocomplete="current-password">
<button>{{button_text}}</button></form>
<p class="hint">{{footer|safe}}</p></main></body></html>
"""

PAGE = r"""
<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeLab Online 3.0</title><style>
:root{color-scheme:dark;--bg:#08111f;--panel:#14233a;--line:#2c405f;--muted:#a1b2ca;--txt:#edf4ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0%,#20385c 0,transparent 42%),var(--bg);color:var(--txt);font:15px system-ui}
main{max-width:1200px;margin:auto;padding:24px 16px}h1{margin:0;font-size:26px}h2{font-size:17px;margin:0 0 7px}
.muted,.desc,small{color:var(--muted)}.desc{font-size:13px}.header,.head,.tools{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.pill{padding:7px 12px;border:1px solid #326353;border-radius:22px;color:#86efc8;background:#12342d;font-size:12px}
.notice{margin:16px 0;padding:13px;background:#332717;border:1px solid #75562d;border-radius:12px;color:#ffdfa8}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}.stat,.panel{padding:16px;border:1px solid var(--line);border-radius:15px;background:linear-gradient(160deg,#182943,#111c30)}
.stat strong{display:block;font-size:25px}.stat span{font-size:12px;color:var(--muted)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.full{grid-column:1/-1}
label{display:block;margin:11px 0 5px;font-size:13px}input,select{width:100%;padding:10px;background:#0b1527;color:white;border:1px solid #3b4e6c;border-radius:8px}
button,.btn{display:inline-block;margin-top:11px;padding:10px 13px;border:0;border-radius:8px;background:linear-gradient(100deg,#7baeff,#5be0b6);color:#071323;font-weight:800;text-decoration:none;cursor:pointer}
.secondary{background:#293d5a;color:#eaf2ff}.danger{background:#65323d;color:white}.tools{justify-content:flex-start}.tools button,.tools .btn{margin-top:0}
.task{padding:13px 0;border-top:1px solid var(--line)}.status{padding:4px 8px;border-radius:18px;background:#293a55;font-size:11px}.completed{background:#123b31;color:#8bf0c8}.running{background:#45351c;color:#ffcf7f}.failed{background:#542d37;color:#ffb5bd}
.track{height:8px;background:#091323;border-radius:20px;overflow:hidden;margin:8px 0}.fill{height:100%;background:linear-gradient(90deg,#78aaff,#5be0b6)}
.mono{font:12px ui-monospace,monospace;color:#a9bdd9;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{color:var(--muted)}
canvas{width:100%;height:200px}.tabs{display:flex;gap:8px;flex-wrap:wrap}.tabs a{color:#a9c8ff;text-decoration:none;padding:7px 10px;background:#203450;border-radius:8px}
@media(max-width:700px){.grid{grid-template-columns:1fr}.full{grid-column:auto}.stats{grid-template-columns:repeat(2,1fr)}main{padding:16px 12px}}
</style></head><body><main>
<header class="header"><div><h1>◈ SafeLab Online 3.0</h1><p class="desc">Nền tảng phòng thực hành mô phỏng an toàn</p></div>
<div class="tools"><span class="pill">● SAFE SIMULATION</span><span class="muted">{{username}} · {{role}}</span><a class="btn secondary" href="/logout">Đăng xuất</a></div></header>
<div class="notice"><b>Lưu ý:</b> SSH và ZIP hiện chỉ mô phỏng, không kết nối máy chủ hoặc xử lý tệp thật. Không nhập mật khẩu máy chủ thật.</div>
<div class="stats"><div class="stat"><strong id="total">0</strong><span>Tổng tác vụ</span></div><div class="stat"><strong id="running">0</strong><span>Đang chạy</span></div><div class="stat"><strong id="done">0</strong><span>Hoàn tất</span></div><div class="stat"><strong id="usercount">{{user_count}}</strong><span>Tài khoản</span></div></div>
<div class="grid">
<section class="panel"><h2>⌘ Mô phỏng SSH</h2><p class="desc">Tạo phiên thực hành giả lập.</p><label>Máy mẫu</label><input id="host" value="lab-server.local"><label>Người dùng mẫu</label><input id="sshuser" value="student"><button onclick="startTask('ssh')">▶ Chạy SSH giả lập</button></section>
<section class="panel"><h2>▣ Mô phỏng ZIP</h2><p class="desc">Tiến trình xử lý tệp giả.</p><label>Tên tệp mẫu</label><input id="zipname" value="baitap_demo.zip"><button onclick="startTask('zip')">▶ Chạy ZIP giả lập</button></section>
<section class="panel"><h2>Biểu đồ thống kê</h2><canvas id="chart" width="700" height="210"></canvas></section>
<section class="panel"><h2>Tài khoản & bảo mật</h2><p>Vai trò: <b>{{role}}</b></p><p class="desc">Đổi mật khẩu thường xuyên và không chia sẻ tài khoản.</p><form onsubmit="changePassword(event)"><label>Mật khẩu hiện tại</label><input id="oldpass" type="password" required><label>Mật khẩu mới (ít nhất 8 ký tự)</label><input id="newpass" type="password" minlength="8" required><button>Đổi mật khẩu</button></form><p id="pwmsg" class="mono"></p></section>
<section class="panel full"><div class="head"><div><h2>Giám sát tác vụ</h2><p class="desc">Tự động cập nhật mỗi 2,5 giây. Người dùng chỉ xem tác vụ của mình.</p></div><a class="btn" href="/export/tasks.csv">Xuất CSV</a></div><div id="tasks">Chưa có tác vụ.</div></section>
{% if role == 'admin' %}<section class="panel"><h2>Quản lý tài khoản</h2><p class="desc">Tài khoản tự đăng ký mặc định có vai trò User.</p><div id="users"></div></section>
<section class="panel"><h2>Quản trị hệ thống</h2><p class="desc">Nhật ký hoạt động gần đây.</p><a class="btn" href="/export/logs.csv">Xuất nhật ký CSV</a><div id="logs"></div></section>{% endif %}
</div></main>
<script>
const ADMIN={{'true' if role=='admin' else 'false'}};
const CSRF={{csrf_token()|tojson}};
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function api(u,o={}){o.headers={...(o.headers||{}),'X-CSRF-Token':CSRF};let r=await fetch(u,o),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||'Yêu cầu thất bại');return d}
async function startTask(k){let d=k==='ssh'?{host:document.getElementById('host').value.trim(),username:document.getElementById('sshuser').value.trim()}:{filename:document.getElementById('zipname').value.trim()};try{await api('/api/tasks/'+k,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});refresh()}catch(e){alert(e.message)}}
function chart(a){let c=document.getElementById('chart'),x=c.getContext('2d'),h=c.height;x.clearRect(0,0,c.width,h);let v=[a.length,a.filter(t=>['pending','running'].includes(t.status)).length,a.filter(t=>t.status==='completed').length],m=Math.max(1,...v),labs=['Tổng','Đang chạy','Hoàn tất'];v.forEach((n,i)=>{let px=65+i*215,bh=n/m*130;x.fillStyle=['#78aaff','#ffcf7f','#5be0b6'][i];x.fillRect(px,h-38-bh,105,bh);x.fillStyle='#edf4ff';x.fillText(n,px+48,h-45-bh);x.fillStyle='#a1b2ca';x.fillText(labs[i],px+22,h-12)})}
async function refresh(){try{let d=await api('/api/tasks'),a=Object.values(d);document.getElementById('total').textContent=a.length;document.getElementById('running').textContent=a.filter(t=>['pending','running'].includes(t.status)).length;document.getElementById('done').textContent=a.filter(t=>t.status==='completed').length;document.getElementById('tasks').innerHTML=a.length?Object.entries(d).map(([id,t])=>`<article class="task"><div class="head"><b>${esc(t.type.toUpperCase())} · ${esc(id)}</b><span class="status ${esc(t.status)}">${esc(t.status)}</span></div><small>${t.progress}% · ${esc(t.owner)} · ${esc(t.created_at)}</small><div class="track"><div class="fill" style="width:${Number(t.progress)}%"></div></div><p class="mono">${esc(t.message||'Đang mô phỏng…')} · ${esc(t.target)}</p></article>`).join(''):'Chưa có tác vụ.';chart(a)}catch(e){}}
async function changePassword(e){e.preventDefault();let msg=document.getElementById('pwmsg');try{await api('/api/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_password:document.getElementById('oldpass').value,new_password:document.getElementById('newpass').value})});msg.textContent='Đổi mật khẩu thành công.';e.target.reset()}catch(err){msg.textContent=err.message}}
async function loadUsers(){if(!ADMIN)return;try{let a=await api('/api/users');document.getElementById('usercount').textContent=a.length;document.getElementById('users').innerHTML='<table><tr><th>Tài khoản</th><th>Vai trò</th><th>Thao tác</th></tr>'+a.map(v=>`<tr><td>${esc(v.username)}</td><td>${esc(v.role)}</td><td>${v.username==='admin'?'—':`<button class="danger" onclick="delUser(${v.id},'${esc(v.username)}')">Xóa</button>`}</td></tr>`).join('')+'</table>'}catch(e){}}
async function delUser(id,n){if(!confirm('Xóa tài khoản '+n+'?'))return;try{await api('/api/users/'+id,{method:'DELETE'});loadUsers()}catch(e){alert(e.message)}}
async function loadLogs(){if(!ADMIN)return;try{let a=await api('/api/logs');document.getElementById('logs').innerHTML='<table><tr><th>Thời gian</th><th>Tài khoản</th><th>Hoạt động</th></tr>'+a.slice(0,12).map(v=>`<tr><td>${esc(v.created_at)}</td><td>${esc(v.username)}</td><td>${esc(v.action)}</td></tr>`).join('')+'</table>'}catch(e){}}
refresh();loadUsers();loadLogs();setInterval(refresh,2500);setInterval(loadLogs,10000);
</script></body></html>
"""

@app.get("/")
@logged_in
def index():
    with connect_db() as c:
        count = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return render_template_string(PAGE, username=session["username"], role=session["role"], user_count=count)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if login_limited(ip):
            return render_template_string(LOGIN_PAGE, subtitle="Đăng nhập bảng điều khiển", error="Quá nhiều lần đăng nhập sai. Hãy thử lại sau 5 phút.", button_text="Đăng nhập", footer='Chưa có tài khoản? <a href="/register">Đăng ký</a>'), 429
        name = request.form.get("username", "").strip()
        with connect_db() as c:
            user = c.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            with rate_lock:
                login_attempts.pop(ip, None)
            session.clear()
            session.permanent = True
            session.update(user_id=user["id"], username=user["username"], role=user["role"], _csrf=secrets.token_urlsafe(32))
            audit("Đăng nhập thành công", username=user["username"])
            return redirect(url_for("index"))
        record_login_failure(ip)
        audit("Đăng nhập thất bại", name, "unknown")
        return render_template_string(LOGIN_PAGE, subtitle="Đăng nhập bảng điều khiển", error="Sai tài khoản hoặc mật khẩu.", button_text="Đăng nhập", footer='Chưa có tài khoản? <a href="/register">Đăng ký</a>'), 401
    return render_template_string(LOGIN_PAGE, subtitle="Đăng nhập bảng điều khiển", error=None, button_text="Đăng nhập", footer='Chưa có tài khoản? <a href="/register">Đăng ký miễn phí</a>')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not valid_username(username):
            return render_template_string(LOGIN_PAGE, subtitle="Tạo tài khoản SafeLab miễn phí", error="Tên đăng nhập phải có 3–32 ký tự chữ, số hoặc dấu gạch dưới.", button_text="Tạo tài khoản", footer='Đã có tài khoản? <a href="/login">Đăng nhập</a>'), 400
        if len(password) < 8:
            return render_template_string(LOGIN_PAGE, subtitle="Tạo tài khoản SafeLab miễn phí", error="Mật khẩu phải có ít nhất 8 ký tự.", button_text="Tạo tài khoản", footer='Đã có tài khoản? <a href="/login">Đăng nhập</a>'), 400
        try:
            with db_lock, connect_db() as c:
                c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                          (username, generate_password_hash(password), "user", now()))
                uid = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        except sqlite3.IntegrityError:
            return render_template_string(LOGIN_PAGE, subtitle="Tạo tài khoản SafeLab miễn phí", error="Tên đăng nhập đã tồn tại.", button_text="Tạo tài khoản", footer='Đã có tài khoản? <a href="/login">Đăng nhập</a>'), 409
        audit("Đăng ký tài khoản", username, username)
        session.clear()
        session.permanent = True
        session.update(user_id=uid, username=username, role="user", _csrf=secrets.token_urlsafe(32))
        return redirect(url_for("index"))
    return render_template_string(LOGIN_PAGE, subtitle="Tạo tài khoản SafeLab miễn phí", error=None, button_text="Đăng ký", footer='Đã có tài khoản? <a href="/login">Đăng nhập</a>')

@app.get("/logout")
def logout():
    if session.get("user_id"):
        audit("Đăng xuất")
    session.clear()
    return redirect(url_for("login"))

def update_task(task_id: str, **fields):
    fields["updated_at"] = now()
    query = ", ".join(f"{key}=?" for key in fields)
    with db_lock, connect_db() as c:
        c.execute(f"UPDATE tasks SET {query} WHERE id=?", (*fields.values(), task_id))

def simulate_task(task_id: str):
    try:
        update_task(task_id, status="running", progress=0)
        for progress in (8, 22, 39, 57, 76, 91, 100):
            time.sleep(0.35)
            update_task(task_id, progress=progress)
        update_task(task_id, status="completed", result="Mô phỏng hoàn tất; không kết nối SSH hoặc xử lý ZIP thật.")
    except Exception as exc:
        update_task(task_id, status="failed", result=str(exc)[:150])

def create_task(kind: str, target: str):
    task_id = "lab_" + uuid.uuid4().hex[:10]
    stamp = now()
    with db_lock, connect_db() as c:
        c.execute("""INSERT INTO tasks(id,type,status,progress,target,result,owner_id,owner_name,created_at,updated_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?)""",
                  (task_id, kind, "pending", 0, target, None, session["user_id"], session["username"], stamp, stamp))
    thread = threading.Thread(target=simulate_task, args=(task_id,), daemon=True)
    task_threads.add(thread)
    thread.start()
    audit("Tạo tác vụ", f"{kind} · {target}")
    return task_id

@app.get("/api/tasks")
@logged_in
def get_tasks():
    with connect_db() as c:
        if session["role"] == "admin":
            rows = c.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 500").fetchall()
        else:
            rows = c.execute("SELECT * FROM tasks WHERE owner_id=? ORDER BY created_at DESC LIMIT 200", (session["user_id"],)).fetchall()
    return jsonify({r["id"]: {"type": r["type"], "status": r["status"], "progress": r["progress"],
        "target": r["target"], "owner": r["owner_name"], "created_at": r["created_at"], "message": r["result"]} for r in rows})

@app.post("/api/tasks/ssh")
@logged_in
def ssh_task():
    data = request.get_json(silent=True) or {}
    host = str(data.get("host", "")).strip()[:100]
    username = str(data.get("username", "")).strip()[:64]
    if not host or not username:
        return jsonify(error="Nhập máy và người dùng mẫu."), 400
    return jsonify(task_id=create_task("ssh", username + "@" + host), mode="simulation_only"), 202

@app.post("/api/tasks/zip")
@logged_in
def zip_task():
    data = request.get_json(silent=True) or {}
    filename = str(data.get("filename", "")).strip()[:120]
    if not filename:
        return jsonify(error="Nhập tên tệp mẫu."), 400
    return jsonify(task_id=create_task("zip", filename), mode="simulation_only"), 202

@app.post("/api/password")
@logged_in
def change_password():
    data = request.get_json(silent=True) or {}
    old_password = str(data.get("old_password", ""))
    new_password = str(data.get("new_password", ""))
    if len(new_password) < 8:
        return jsonify(error="Mật khẩu mới phải có ít nhất 8 ký tự."), 400
    with db_lock, connect_db() as c:
        user = c.execute("SELECT password_hash FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or not check_password_hash(user["password_hash"], old_password):
            return jsonify(error="Mật khẩu hiện tại không chính xác."), 400
        c.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new_password), session["user_id"]))
    audit("Đổi mật khẩu")
    return jsonify(ok=True)

@app.get("/api/users")
@admin_only
def get_users():
    with connect_db() as c:
        rows = c.execute("SELECT id,username,role,created_at FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])

@app.delete("/api/users/<int:user_id>")
@admin_only
def delete_user(user_id: int):
    if user_id == session["user_id"]:
        return jsonify(error="Không thể xóa chính mình."), 400
    with db_lock, connect_db() as c:
        user = c.execute("SELECT username,role FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return jsonify(error="Không tìm thấy tài khoản."), 404
        if user["username"].lower() == "admin":
            return jsonify(error="Không thể xóa tài khoản admin mặc định."), 400
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
    audit("Xóa tài khoản", user["username"])
    return jsonify(ok=True)

@app.get("/api/logs")
@admin_only
def get_logs():
    with connect_db() as c:
        rows = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

def csv_response(rows, filename, headers):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(list(row))
    data = "\ufeff" + output.getvalue()
    return Response(data, mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.get("/export/tasks.csv")
@logged_in
def export_tasks():
    with connect_db() as c:
        if session["role"] == "admin":
            rows = c.execute("SELECT id,type,status,progress,target,owner_name,created_at,updated_at,result FROM tasks ORDER BY created_at DESC").fetchall()
        else:
            rows = c.execute("SELECT id,type,status,progress,target,owner_name,created_at,updated_at,result FROM tasks WHERE owner_id=? ORDER BY created_at DESC", (session["user_id"],)).fetchall()
    return csv_response(rows, "safelab_tasks.csv", ["ID","Loại","Trạng thái","Tiến trình","Mục tiêu","Người tạo","Tạo lúc","Cập nhật","Kết quả"])

@app.get("/export/logs.csv")
@admin_only
def export_logs():
    with connect_db() as c:
        rows = c.execute("SELECT created_at,username,action,detail FROM logs ORDER BY id DESC").fetchall()
    return csv_response(rows, "safelab_logs.csv", ["Thời gian","Người dùng","Hoạt động","Chi tiết"])

@app.get("/health")
def health():
    return jsonify(status="ok", app=APP_NAME, mode="simulation_only")

def main():
    init_db()
    host = os.environ.get("SAFELAB_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", os.environ.get("SAFELAB_PORT", "5000")))
    if getattr(sys, "frozen", False) and host in ("127.0.0.1", "localhost"):
        threading.Timer(1.2, lambda: webbrowser.open(f"http://{host}:{port}")).start()
    if app.secret_key == "development-only-change-me":
        print("WARNING: Set SAFELAB_SECRET_KEY to a long random value before public deployment.")
    if not os.environ.get("SAFELAB_ADMIN_PASSWORD"):
        print("WARNING: Default admin password is ChangeMe-Admin-2026! — change it before deployment.")
    print(f"{APP_NAME}: http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)

# Initialize the database when imported by Gunicorn on Render.
init_db()

if __name__ == "__main__":
    main()
