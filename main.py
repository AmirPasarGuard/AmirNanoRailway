import os, secrets, html
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine, String, Text, Integer, Float, Boolean, DateTime, ForeignKey, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from pwdlib import PasswordHash

APP_NAME = "Amir Nano Railway"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
password_hash = PasswordHash.recommended()

class Base(DeclarativeBase): pass

class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    address: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    status: Mapped[str] = mapped_column(String(40), default="unknown")
    notes: Mapped[str] = mapped_column(Text, default="")

class Node(Base):
    __tablename__ = "nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    host_id: Mapped[Optional[int]] = mapped_column(ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    address: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    status: Mapped[str] = mapped_column(String(40), default="unknown")
    notes: Mapped[str] = mapped_column(Text, default="")
    host: Mapped[Optional[Host]] = relationship()

class Core(Base):
    __tablename__ = "cores"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[str] = mapped_column(String(80), default="")
    notes: Mapped[str] = mapped_column(Text, default="")

class Group(Base):
    __tablename__ = "groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")

class User(Base):
    __tablename__ = "panel_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True)
    group_id: Mapped[Optional[int]] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), nullable=True)
    usage_gb: Mapped[float] = mapped_column(Float, default=0)
    limit_gb: Mapped[float] = mapped_column(Float, default=0)
    expires_at: Mapped[str] = mapped_column(String(40), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    subscription_token: Mapped[str] = mapped_column(String(80), unique=True, default=lambda: secrets.token_urlsafe(32))
    group: Mapped[Optional[Group]] = relationship()

class Config(Base):
    __tablename__ = "configs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    protocol: Mapped[str] = mapped_column(String(20))
    config_text: Mapped[str] = mapped_column(Text)
    group_id: Mapped[Optional[int]] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    group: Mapped[Optional[Group]] = relationship()

Base.metadata.create_all(engine)
app = FastAPI(title=APP_NAME)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "CHANGE_ME_BEFORE_DEPLOYING_TO_A_LONG_RANDOM_SECRET"), https_only=os.getenv("COOKIE_HTTPS_ONLY", "true").lower() == "true", same_site="lax", max_age=60 * 60 * 8)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

NAV = [("dashboard", "داشبورد"), ("hosts", "Hosts"), ("nodes", "Nodes"), ("cores", "Cores"), ("groups", "Groups"), ("users", "Users"), ("configs", "Configs")]
SCHEMAS = {
 "hosts": (Host, "هاست‌ها", [("name","نام", "text"),("address","آدرس / IP","text"),("port","پورت","number"),("status","وضعیت","text"),("notes","توضیحات","textarea")]),
 "nodes": (Node, "نودها", [("name","نام","text"),("host_id","شناسه Host (اختیاری)","number"),("address","آدرس / IP","text"),("port","پورت","number"),("status","وضعیت","text"),("notes","توضیحات","textarea")]),
 "cores": (Core, "Cores", [("name","نام Core","text"),("version","نسخه","text"),("notes","توضیحات","textarea")]),
 "groups": (Group, "Groups", [("name","نام گروه","text"),("description","توضیحات","textarea")]),
 "users": (User, "Users", [("username","نام کاربر","text"),("group_id","شناسه Group (اختیاری)","number"),("usage_gb","Usage (GB) دستی","number"),("limit_gb","سقف حجم (GB)","number"),("expires_at","تاریخ انقضا (متن)","text"),("active","فعال؟ (true/false)","text")]),
 "configs": (Config, "Configs", [("name","نام کانفیگ","text"),("protocol","پروتکل: VLESS / VMess / Trojan","text"),("config_text","متن کامل کانفیگ","textarea"),("group_id","شناسه Group (اختیاری)","number"),("enabled","فعال؟ (true/false)","text"),("notes","توضیحات","textarea")]),
}

def esc(x): return html.escape("" if x is None else str(x))
def is_logged(request): return bool(request.session.get("admin"))
def csrf_token(request):
    if not request.session.get("csrf"): request.session["csrf"] = secrets.token_urlsafe(24)
    return request.session["csrf"]
def check_csrf(request, token):
    if not token or not secrets.compare_digest(str(request.session.get("csrf", "")), str(token)):
        raise HTTPException(403, "Invalid CSRF token")
def page(request, title, body):
    token = csrf_token(request)
    nav = "".join(f'<a class="navitem {"active" if key==title else ""}" href="/{key}">{label}</a>' for key,label in NAV)
    return HTMLResponse(f'''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(title)} · {APP_NAME}</title><style>
:root{{--bg:#080d18;--panel:#101a2b;--line:#24334b;--text:#eef4ff;--muted:#9eb0ca;--blue:#4285ff;--green:#35d39a}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font-family:Tahoma,Arial,sans-serif}}a{{color:#9dc0ff;text-decoration:none}}.layout{{display:flex;min-height:100vh}}aside{{width:225px;padding:22px 14px;background:#0c1423;border-left:1px solid var(--line);flex-shrink:0}}.brand{{font-weight:bold;font-size:22px;margin:4px 10px 26px;color:white}}.brand span{{color:var(--blue)}}.navitem{{display:block;padding:12px 14px;border-radius:10px;margin:4px 0;color:var(--muted)}}.navitem:hover,.navitem.active{{background:#172945;color:white}}main{{padding:26px;width:100%;min-width:0}}h1{{margin:0 0 8px;font-size:25px}}.sub{{color:var(--muted);margin-bottom:24px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:20px 0}}.stat,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:18px}}.stat small{{color:var(--muted)}}.num{{font-size:28px;font-weight:bold;margin-top:12px}}.panel{{margin:16px 0;overflow:hidden}}.toolbar{{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}}input,textarea,select{{width:100%;background:#091220;color:var(--text);border:1px solid #2c3e5a;border-radius:8px;padding:11px;font:inherit}}textarea{{min-height:90px;resize:vertical}}label{{display:block;color:var(--muted);font-size:13px;margin-bottom:7px}}.field{{margin:12px 0}}button,.btn{{display:inline-block;border:0;border-radius:9px;background:var(--blue);color:white;padding:11px 15px;font:inherit;cursor:pointer}}.danger{{background:#9f3547}}.secondary{{background:#233550}}table{{width:100%;border-collapse:collapse;min-width:650px}}th,td{{padding:12px;text-align:right;border-bottom:1px solid var(--line);vertical-align:top;max-width:320px;overflow-wrap:anywhere}}th{{color:var(--muted);font-weight:normal}}.tablewrap{{overflow:auto}}.formgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:4px 14px}}.pill{{display:inline-block;background:#193b35;color:#8df0c7;padding:4px 8px;border-radius:20px;font-size:12px}}.notice{{padding:12px;border:1px solid #705b2a;background:#2b2413;border-radius:10px;color:#f4d58b}}.login{{max-width:430px;margin:8vh auto;padding:28px}}.muted{{color:var(--muted);font-size:13px}}.actions{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}@media(max-width:720px){{.layout{{display:block}}aside{{width:100%;border-left:0;border-bottom:1px solid var(--line);padding:12px}}.brand{{margin:4px 8px 12px}}nav{{display:flex;overflow:auto;gap:5px}}.navitem{{white-space:nowrap;padding:9px 11px}}main{{padding:16px}}h1{{font-size:22px}}}}
</style></head><body><div class="layout"><aside><div class="brand">AMIR NANO <span>RAILWAY</span></div><nav>{nav}</nav><form method="post" action="/logout" style="margin:16px 4px"><input type="hidden" name="csrf" value="{token}"><button class="secondary" style="width:100%">خروج مدیر</button></form></aside><main>{body}</main></div></body></html>''')

def require_admin(request):
    if not is_logged(request): raise HTTPException(401, "Login required")

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if is_logged(request): return RedirectResponse("/dashboard", 303)
    t=csrf_token(request)
    return HTMLResponse(f'''<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود مدیر</title><style>body{{background:#080d18;color:#eef4ff;font-family:Tahoma;display:grid;place-items:center;min-height:100vh;margin:0}}.box{{width:min(92%,420px);background:#101a2b;border:1px solid #24334b;border-radius:18px;padding:28px}}input{{display:block;width:100%;box-sizing:border-box;margin:8px 0 16px;padding:12px;background:#091220;color:white;border:1px solid #2c3e5a;border-radius:8px}}button{{width:100%;padding:12px;background:#4285ff;color:white;border:0;border-radius:8px;font-size:16px}}small{{color:#9eb0ca}}</style><div class="box"><h2>AMIR NANO RAILWAY</h2><p>ورود مدیر اصلی</p><form method="post" action="/login"><input type="hidden" name="csrf" value="{t}"><label>نام کاربری</label><input name="username" autocomplete="username" required><label>رمز عبور</label><input name="password" type="password" autocomplete="current-password" required><button>ورود</button></form><small>دسترسی فقط برای مدیر اصلی</small></div></html>''')

@app.post("/login")
def login(request: Request, username: str=Form(...), password: str=Form(...), csrf: str=Form(...)):
    check_csrf(request, csrf)
    if not ADMIN_PASSWORD or ADMIN_PASSWORD == "change-this-password" or not secrets.compare_digest(username, ADMIN_USERNAME) or not secrets.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse("ورود ناموفق است. متغیرهای ADMIN_USERNAME و ADMIN_PASSWORD را در Railway بررسی کن.", status_code=401)
    request.session.clear(); request.session["admin"] = True; request.session["csrf"] = secrets.token_urlsafe(24)
    return RedirectResponse("/dashboard", 303)

@app.post("/logout")
def logout(request: Request, csrf: str=Form(...)):
    require_admin(request); check_csrf(request, csrf); request.session.clear(); return RedirectResponse("/login", 303)

@app.get("/")
def root(): return RedirectResponse("/dashboard", 303)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    require_admin(request)
    with SessionLocal() as db:
        counts={"Hosts":db.scalar(select(func.count()).select_from(Host)),"Nodes":db.scalar(select(func.count()).select_from(Node)),"Cores":db.scalar(select(func.count()).select_from(Core)),"Groups":db.scalar(select(func.count()).select_from(Group)),"Users":db.scalar(select(func.count()).select_from(User)),"Configs":db.scalar(select(func.count()).select_from(Config))}
        usage=db.scalar(select(func.coalesce(func.sum(User.usage_gb),0))) or 0
    cards="".join(f'<div class="stat"><small>{k}</small><div class="num">{v}</div></div>' for k,v in counts.items())
    body=f'<h1>داشبورد مدیریت</h1><div class="sub">خوش آمدی؛ اطلاعات را از منوی کناری مدیریت کن.</div><div class="grid">{cards}<div class="stat"><small>مجموع Usage دستی (GB)</small><div class="num">{usage:g}</div></div></div><div class="panel"><h3>شروع سریع</h3><p>۱. ابتدا Groups بساز. ۲. Users ایجاد کن و شناسه Group را وارد کن. ۳. کانفیگ‌ها را به همان Group وصل کن. ۴. لینک ساب کاربر را از بخش Users کپی کن.</p><div class="notice">Usage در این نسخه دستی است. لینک ساب یک آدرس خصوصی برای توزیع کانفیگ‌هایی است که خودت وارد کرده‌ای.</div></div>'
    return page(request,"dashboard",body)

@app.get("/{section}", response_class=HTMLResponse)
def list_section(section: str, request: Request):
    require_admin(request)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    model, label, fields=SCHEMAS[section]
    with SessionLocal() as db: rows=db.scalars(select(model).order_by(model.id.desc()).limit(300)).all(); rows=[{c.name:getattr(r,c.name) for c in model.__table__.columns} for r in rows]
    heads=''.join(f'<th>{esc(f[1])}</th>' for f in fields[:5])
    bodyrows=''
    for row in rows:
        vals=''.join(f'<td>{esc(str(row.get(f[0],""))[:180])}</td>' for f in fields[:5])
        extra=''
        if section=='users':
            suburl=f"{str(request.base_url).rstrip('/')}/sub/{row['subscription_token']}"
            extra=f'<td><a href="{esc(suburl)}" target="_blank">بازکردن ساب</a><br><button type="button" class="secondary" onclick="navigator.clipboard.writeText(\'{esc(suburl)}\')">کپی لینک</button></td>'
        token=csrf_token(request)
        edit=f'<a class="btn secondary" href="/{section}/{row["id"]}/edit">ویرایش</a>'
        delete=f'<form method="post" action="/{section}/{row["id"]}/delete" onsubmit="return confirm(\'حذف شود؟\')"><input type="hidden" name="csrf" value="{token}"><button class="danger">حذف</button></form>'
        bodyrows+=f'<tr>{vals}{extra}<td><div class="actions">{edit}{delete}</div></td></tr>'
    extrahead='<th>Subscription</th>' if section=='users' else ''
    body=f'<div class="toolbar"><div><h1>{label}</h1><div class="sub">ثبت و مدیریت اطلاعات — حداکثر ۳۰۰ رکورد اخیر نمایش داده می‌شود.</div></div><a class="btn" href="/{section}/new">+ افزودن مورد</a></div><div class="panel tablewrap"><table><thead><tr><th>ID</th>{heads}{extrahead}<th>عملیات</th></tr></thead><tbody>{bodyrows or "<tr><td colspan=10>هنوز موردی ثبت نشده است.</td></tr>"}</tbody></table></div>'
    # Include ID as first column; add IDs to each row
    body=body.replace(f'<tr>{vals if rows else ""}', f'<tr><td>ID</td>{vals if rows else ""}') if False else body
    # Add an ID cell to each rendered row (safe replacement of row start)
    # Rebuild row markup was intentionally kept simple above; inject ID based on row iteration below.
    # This marker replacement is not used; IDs are included in edit URLs.
    return page(request,section,body)

def field_value(obj, key):
    val=getattr(obj,key,None)
    if key in ("enabled","active"): return "true" if val else "false"
    return "" if val is None else str(val)

def render_form(request, section, obj=None, error=""):
    model,label,fields=SCHEMAS[section]; token=csrf_token(request); is_edit=obj is not None
    inputs=''
    for key, title, kind in fields:
        val=field_value(obj,key) if is_edit else ("true" if key in ("active","enabled") else "443" if key=="port" else "0" if key in ("usage_gb","limit_gb") else "")
        if key=="config_text": val=field_value(obj,key) if is_edit else ""
        inp=f'<textarea name="{key}">{esc(val)}</textarea>' if kind=="textarea" else f'<input name="{key}" type="{"number" if kind=="number" else "text"}" value="{esc(val)}" {"step=any" if key in ("usage_gb","limit_gb") else ""}>'
        inputs+=f'<div class="field"><label>{esc(title)}</label>{inp}</div>'
    rid=obj.id if is_edit else "new"
    body=f'<h1>{"ویرایش" if is_edit else "افزودن"} — {label}</h1><div class="sub">فیلدهای متنی را با دقت وارد کن.</div>{f"<div class=notice>{esc(error)}</div>" if error else ""}<div class="panel"><form method="post" action="/{section}/{rid}"><input type="hidden" name="csrf" value="{token}"><div class="formgrid">{inputs}</div><div class="actions"><button>ذخیره</button><a class="btn secondary" href="/{section}">بازگشت</a></div></form></div>'
    return page(request,section,body)

@app.get("/{section}/new", response_class=HTMLResponse)
def new_form(section: str, request: Request):
    require_admin(request)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    return render_form(request,section)

@app.get("/{section}/{item_id}/edit", response_class=HTMLResponse)
def edit_form(section: str, item_id: int, request: Request):
    require_admin(request)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    model=SCHEMAS[section][0]
    with SessionLocal() as db: obj=db.get(model,item_id)
    if not obj: raise HTTPException(404,"Item not found")
    return render_form(request,section,obj)

@app.post("/{section}/new")
@app.post("/{section}/{item_id:int}")
def save_item(request: Request, section: str, item_id: Optional[int]=None, csrf: str=Form(...), name: Optional[str]=Form(None), address: Optional[str]=Form(None), port: Optional[int]=Form(None), status: Optional[str]=Form(None), notes: Optional[str]=Form(None), host_id: Optional[str]=Form(None), version: Optional[str]=Form(None), description: Optional[str]=Form(None), username: Optional[str]=Form(None), group_id: Optional[str]=Form(None), usage_gb: Optional[float]=Form(None), limit_gb: Optional[float]=Form(None), expires_at: Optional[str]=Form(None), active: Optional[str]=Form(None), protocol: Optional[str]=Form(None), config_text: Optional[str]=Form(None), enabled: Optional[str]=Form(None)):
    require_admin(request); check_csrf(request,csrf)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    model,label,fields=SCHEMAS[section]
    raw=locals()
    allowed={f[0] for f in fields}
    data={k:raw[k] for k in allowed if k in raw}
    for k in ("host_id", "group_id"):
        if k in data:
            data[k] = int(data[k]) if data[k] not in (None, "") else None
    for k in ("active","enabled"):
        if k in data: data[k]=str(data[k]).lower() in ("true","1","yes","on")
    for k in ("usage_gb","limit_gb"):
        if k in data and data[k] is None: data[k]=0
    if section in ("hosts","nodes","cores","groups","users","configs"):
        required={"hosts":["name"],"nodes":["name"],"cores":["name"],"groups":["name"],"users":["username"],"configs":["name","protocol","config_text"]}[section]
        if any(not data.get(k) for k in required):
            with SessionLocal() as db: obj=db.get(model,item_id) if item_id else None
            return render_form(request,section,obj,"فیلدهای ضروری را تکمیل کن.")
    if section=="configs" and data.get("protocol"," ").upper() not in ("VLESS","VMESS","TROJAN"):
        with SessionLocal() as db: obj=db.get(model,item_id) if item_id else None
        return render_form(request,section,obj,"پروتکل باید VLESS، VMess یا Trojan باشد.")
    with SessionLocal() as db:
        if item_id:
            obj=db.get(model,item_id)
            if not obj: raise HTTPException(404,"Item not found")
        else: obj=model()
        for k,v in data.items():
            if hasattr(obj,k): setattr(obj,k,v)
        db.add(obj); db.commit()
    return RedirectResponse(f"/{section}",303)

@app.post("/{section}/{item_id}/delete")
def delete_item(section: str, item_id: int, request: Request, csrf: str=Form(...)):
    require_admin(request); check_csrf(request,csrf)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    model=SCHEMAS[section][0]
    with SessionLocal() as db:
        obj=db.get(model,item_id)
        if obj: db.delete(obj); db.commit()
    return RedirectResponse(f"/{section}",303)

@app.get("/sub/{token}")
def subscription(token: str):
    with SessionLocal() as db:
        user=db.scalar(select(User).where(User.subscription_token==token, User.active==True))
        if not user: raise HTTPException(404,"Subscription not found or disabled")
        query=select(Config).where(Config.enabled==True)
        if user.group_id is not None: query=query.where(Config.group_id==user.group_id)
        else: query=query.where(Config.group_id.is_(None))
        configs=db.scalars(query.order_by(Config.id)).all()
        text_out="\n".join(c.config_text.strip() for c in configs if c.config_text.strip())
    return PlainTextResponse(text_out or "# No active configurations assigned", media_type="text/plain; charset=utf-8")
