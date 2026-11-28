"""CLOUD JARVIS (his ask, 2026-11-18: "make the mobile Jarvis on the cloud, not on my computer, since I want to access it
even when my computer is off"). Builds the Control Room page's data and puts it, LOCKED, on a GitHub page:
    https://ugc-editor.github.io/jarvis/#k=<key>
The page and its data sit in the public repo ugc-editor/jarvis, but the data is AES-256-GCM scrambled with a random key
that only lives in his bookmark link (the part after # never leaves the phone) and in GitHub secret JARVIS_KEY.

Two writers, same page:
  --pc     the video app, after each monitor look (src/jarvis_push.py): the PC's full monitor (every tool) + live sales
           and ad numbers. Also leaves pc.json (the PC's look, locked) for the cloud run.
  (cloud)  GitHub Actions in the page's own repo (its .github/workflows/jarvis.yml, copied from
           cloud/jarvis_site_workflow.yml by the PC; pushes with that run's own token, no deploy key) while the PC is off: the PC's last look + LIVE online jobs,
           Claude routine check-ins, sales (Shopify) and ad numbers (Meta, READ ONLY - GET requests only, never a write).
Read-only everywhere: it never starts, stops or changes a job, an order or an ad."""
import base64
import datetime
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))
PAGE = HERE / "jarvis_page.html"
SITE_REPO = "ugc-editor/jarvis"
SITE_URL = "https://ugc-editor.github.io/jarvis/"
PC_STALE_MIN = 75  # the PC's monitor looks every 30 min while the video app runs; older = the PC is off
RANK = {"ok": 0, "late": 1, "down": 2}
WIN = sys.platform == "win32"
NOWIN = 0x08000000 if WIN else 0
UA = {"User-Agent": "jarvis-cloud"}


# ------------------------------------------------------------------ the lock (AES-256-GCM, WebCrypto on the page)
def new_key():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def _raw(key):
    return base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))


def seal(key, obj):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = secrets.token_bytes(12)
    ct = AESGCM(_raw(key)).encrypt(iv, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), b"jarvis1")
    return json.dumps({"v": 1, "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}).encode()


def unseal(key, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    d = json.loads(blob)
    return json.loads(AESGCM(_raw(key)).decrypt(base64.b64decode(d["iv"]), base64.b64decode(d["ct"]), b"jarvis1"))


# ------------------------------------------------------------------ small web helpers
def _get(url, headers=None, data=None, form=None, timeout=30, raw=False):
    body = None
    head = dict(UA, **(headers or {}))
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        head["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        body = json.dumps(data).encode()
        head["Content-Type"] = "application/json"
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=head), timeout=timeout) as r:
        return r.read().decode("utf-8", "replace") if raw else json.load(r)


def _clean(e, n=140):
    t = re.sub(r"(access_token|token|secret)=[^&\s]+", r"\1=…", str(e))
    return re.sub(r"x-access-token:[^@\s]+@", "x-access-token:…@", t)[:n]


# ------------------------------------------------------------------ sales (Shopify, read only)
def shopify(store, client_id, client_secret, version="2026-07", now=None):
    """Orders and sales for the last 7 days, by the store's own days. Returns (biz, tz)."""
    now = now or time.time()
    tok = _get(f"https://{store}/admin/oauth/access_token",
               form={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret})
    head = {"X-Shopify-Access-Token": tok["access_token"]}
    url = f"https://{store}/admin/api/{version}/graphql.json"

    def gql(q, v=None):
        d = _get(url, head, {"query": q, "variables": v or {}})
        if d.get("errors") and not d.get("data"):
            raise RuntimeError("Shopify: " + str(d["errors"])[:200])
        return d["data"]
    shop = gql("{ shop { currencyCode ianaTimezone } }")["shop"]
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(shop["ianaTimezone"])
    today = datetime.datetime.fromtimestamp(now, tz).date()
    start = datetime.datetime.combine(today - datetime.timedelta(days=6), datetime.time(), tz)
    days = {(today - datetime.timedelta(days=i)).isoformat(): {"orders": 0, "sales": 0.0} for i in range(7)}
    q = """query($q:String!,$after:String){ orders(first:250, after:$after, query:$q, sortKey:CREATED_AT) {
             pageInfo { hasNextPage endCursor }
             nodes { createdAt test cancelledAt currentTotalPriceSet { shopMoney { amount } } } } }"""
    after, pages = None, 0
    while pages < 12:
        o = gql(q, {"q": f"created_at:>='{start.isoformat()}'", "after": after})["orders"]
        for n in o["nodes"]:
            if n.get("test") or n.get("cancelledAt"):
                continue
            day = datetime.datetime.fromisoformat(n["createdAt"].replace("Z", "+00:00")).astimezone(tz).date().isoformat()
            if day in days:
                days[day]["orders"] += 1
                days[day]["sales"] += float(n["currentTotalPriceSet"]["shopMoney"]["amount"])
        pages += 1
        if not o["pageInfo"]["hasNextPage"]:
            break
        after = o["pageInfo"]["endCursor"]
    rows = [{"day": d, "orders": v["orders"], "sales": round(v["sales"], 2)} for d, v in sorted(days.items())]
    hour = datetime.datetime.fromtimestamp(now, tz)
    return {"currency": shop["currencyCode"], "days": rows, "at": now,
            "hour": round(hour.hour + hour.minute / 60, 2)}, shop["ianaTimezone"]


# ------------------------------------------------------------------ ads (Meta, READ ONLY: GET requests only)
META = "https://graph.facebook.com/v25.0/"


def _purchase_value(row):
    vals = {a.get("action_type"): float(a.get("value") or 0) for a in row.get("action_values") or []}
    return vals.get("omni_purchase") or vals.get("purchase") or vals.get("offsite_conversion.fb_pixel_purchase") or 0.0


def _purchases(row):
    vals = {a.get("action_type"): float(a.get("value") or 0) for a in row.get("actions") or []}
    return vals.get("omni_purchase") or vals.get("purchase") or vals.get("offsite_conversion.fb_pixel_purchase") or 0.0


def meta(token, account):
    """Spend and Meta-reported sales per campaign, today and yesterday (the ad account's own days)."""
    act = account if str(account).startswith("act_") else "act_" + str(account)
    acc = _get(META + act + "?" + urllib.parse.urlencode({"fields": "currency,timezone_name", "access_token": token}))
    out = {"currency": acc.get("currency"), "tz": acc.get("timezone_name")}
    for preset in ("today", "yesterday"):
        q = {"level": "campaign", "date_preset": preset, "limit": 100, "access_token": token,
             "fields": "campaign_name,spend,action_values,actions"}
        rows = _get(META + act + "/insights?" + urllib.parse.urlencode(q)).get("data") or []
        camps = []
        for r in rows:
            spend, value = float(r.get("spend") or 0), _purchase_value(r)
            if spend <= 0 and value <= 0:
                continue
            camps.append({"name": r.get("campaign_name"), "spend": round(spend, 2), "value": round(value, 2),
                          "buys": int(_purchases(r)), "roas": round(value / spend, 2) if spend else None})
        camps.sort(key=lambda c: -c["spend"])
        spend = sum(c["spend"] for c in camps)
        value = sum(c["value"] for c in camps)
        out[preset] = {"spend": round(spend, 2), "value": round(value, 2), "buys": sum(c["buys"] for c in camps),
                       "roas": round(value / spend, 2) if spend else None, "campaigns": camps}
    out["at"] = time.time()
    return out


# ------------------------------------------------------------------ what each tool did today (same as Jarvis on the PC)
def _stamp(value):
    if not value:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        try:
            return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None


def _spoken(text):
    t = re.sub(r"\(([+-])(\d+)%\)", lambda m: f"({'up' if m.group(1) == '+' else 'down'} {m.group(2)}%)", text)
    t = re.sub(r"<1d", "under 1 day", t)
    t = re.sub(r"(\d+)d\b", r"\1 days", t)
    return t.replace("Typical views: ", "typical views ").replace(" · ", ", ").replace(" / ", " and ")


def today_lines(card, start):
    out = []
    sec = next((s for s in card.get("sections") or [] if str(s.get("title", "")).lower() == "today"), None)
    ran = [p for p in card.get("parts") or [] if (_stamp(p.get("last")) or 0) >= start]
    if sec and sec.get("say"):
        out.append(sec["say"])
    elif ran and card.get("summary"):
        out.append(_spoken(card["summary"]))
    for p in ran:
        said = str(p.get("said") or "")
        if re.match(r"last (ran|checked in|looked)", said):
            when = re.sub(r"^last (ran|checked in|looked) ", "", said)
            out.append(f"{p.get('name')} ran {when} - {p.get('what') or ''}".rstrip(" -"))
        else:
            out.append(f"{p.get('name')}: {said}")
    return out


def _midnight(now, tz):
    from zoneinfo import ZoneInfo
    d = datetime.datetime.fromtimestamp(now, ZoneInfo(tz)) if tz else datetime.datetime.fromtimestamp(now)
    return d.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


# ------------------------------------------------------------------ the online jobs, live (cloud run only)
# Every GitHub job and Claude routine leaves a one-line check-in ("key: detail") on his hidden "-health" ntfy
# channel; the PC's monitor reads the same ones. Limits copied from src/monitor.py (WORKFLOWS, ROUTINES).
# (check-in key, job name as on the PC, late after h, down after h)
JOBS = (
    ("gh-ad-monitor", "Ad monitor (online)", 14, 24),
    ("gh-store-check", "Store check (online)", 16, 26),
    ("gh-replies", "Comment replier (online)", 12, 24),
    ("gh-pc-check", "PC check (online)", 26, 40),
    ("support-drafts", "Support drafts (Claude)", 5, 9),
    ("site-check", "Site check (Claude)", 26, 50),
    ("3-day-report", "3-day report (Claude)", 76, 100),
)
SUPPORT_HOURS = (1, 3, 11, 13, 15, 17, 19, 21, 23)  # the support routine's UTC run hours (its cron)


def _missed_support(last, now):
    t = datetime.datetime.fromtimestamp(last, datetime.timezone.utc).replace(minute=0, second=0, microsecond=0)
    t += datetime.timedelta(hours=1)
    n = 0
    while t.timestamp() <= now - 25 * 60:
        n += t.hour in SUPPORT_HOURS
        t += datetime.timedelta(hours=1)
    return n


def read_checkins(topic, seen):
    """Newest check-in per key from ntfy's last 12 hours (older ones stay remembered in seen)."""
    for channel in ("-health", ""):
        raw = _get(f"https://ntfy.sh/{topic}{channel}/json?poll=1&since=12h", raw=True)
        for line in raw.splitlines():
            if not line.strip():
                continue
            m = json.loads(line)
            at = float(m.get("time") or 0)
            if channel:
                text = str(m.get("message") or "")
                key = text.split(":")[0].strip().lower()
            else:  # the 3-day report lands on the main channel itself
                text = str(m.get("title") or "")
                key = "3-day-report" if text.lower().startswith("3-day report") else ""
            if key and at > float((seen.get(key) or {}).get("at") or 0):
                seen[key] = {"at": at, "line": text[:160]}
    return seen


def _judge(key, name, late_h, down_h, at, line, now):
    age = now - at
    detail = line.split(":", 1)[1].strip() if ":" in line else ""
    if key.startswith("gh-"):
        if detail and detail.lower() not in ("success", "skipped", "cancelled"):
            return {"name": name, "state": "down", "said": f"the last run ended: {detail} ({_ago(age)})", "last": at}
        st = "down" if age > down_h * 3600 else "late" if age > late_h * 3600 else "ok"
        said = f"last ran {_ago(age)}" if st == "ok" else f"hasn't run since {_ago(age)}"
        return {"name": name, "state": st, "said": said, "last": at}
    st = "down" if age > down_h * 3600 else "late" if age > late_h * 3600 else "ok"
    if key == "support-drafts":
        missed = _missed_support(at, now)
        st = "down" if missed >= 3 else "late" if missed else "ok"
    # 2026-11-23: the support routine now says "<N> drafts, <T> checked, <W> waiting, search ok|CHECK" (as in
    # src/monitor.py support_trouble): a run that ran but may have missed customer mail shows as late, not fine
    m = re.search(r"(\d+) checked, (\d+) waiting, search (\w+)", detail, re.I) if key == "support-drafts" else None
    if st == "ok" and m and (int(m.group(2)) or not int(m.group(1)) or m.group(3).lower() != "ok"):
        why = (f"{m.group(2)} customer email(s) still without a draft" if int(m.group(2)) else
               "it found no emails at all to check" if not int(m.group(1)) else "its inbox search looked incomplete")
        return {"name": name, "state": "late", "said": f"its last run ({_ago(age)}) said: {why}", "last": at}
    if st == "ok":
        if m:
            detail = f"{detail.split(',')[0].strip()}, {m.group(1)} emails checked"
        extra = f" ({re.sub(r'^1 drafts', '1 draft', detail)})" if detail and key != "3-day-report" else ""
        said = f"last checked in {_ago(age)}{extra}"
    else:
        said = f"no check-in since {_ago(age)} (it may have hit the plan's usage limit)"
    return {"name": name, "state": st, "said": said, "last": at}


def live_rows(cards, seen, now):
    """Each online job judged from its newest sign of life. When the PC looked later than any check-in we have,
    the PC's own judgement stays (only re-aged)."""
    pc_last = {p.get("name"): _stamp(p.get("last")) or 0 for c in cards for p in c.get("parts") or []}
    rows = []
    for key, name, late_h, down_h in JOBS:
        got = seen.get(key) or {}
        at = float(got.get("at") or 0)
        if at and at > pc_last.get(name, 0):
            rows.append(_judge(key, name, late_h, down_h, at, got.get("line") or "", now))
    return rows


def overlay(cards, rows):
    """Puts the live rows into the PC's cards, by job name; a card whose jobs changed is judged again."""
    live = {r["name"]: r for r in rows}
    for c in cards:
        parts, changed = [], False
        for p in c.get("parts") or []:
            r = live.get(p.get("name"))
            if r and (r.get("state") != p.get("state") or r.get("said") != p.get("said") or r.get("last") != p.get("last")):
                p = dict(p, **{k: r[k] for k in ("state", "said", "last") if k in r})
                changed = True
            parts.append(p)
        c["parts"] = parts
        if not changed:
            continue
        worst = max((p["state"] for p in parts), key=RANK.get, default="ok")
        bad = [p for p in parts if p["state"] != "ok"]
        if worst != c.get("state"):
            if bad:
                c["summary"] = f"{bad[0]['name']}: {bad[0]['said']}"
                c["say"] = c["summary"] + "."
            elif RANK.get(c.get("state"), 0) > 0:  # it was a job problem and every job is fine again
                c["summary"] = c["say"] = "All its jobs are fine again: " + "; ".join(
                    f"{p['name']} {p['said']}" for p in parts)[:200]
            c["state"] = worst


# ------------------------------------------------------------------ the page data
def build(snapshot, now, tz, biz=None, ads=None, pc_mode=False, notes=None):
    cards = [dict(c) for c in snapshot.get("cards") or []]
    checked = float(snapshot.get("checked") or 0)
    pc_off = not checked or now - checked > PC_STALE_MIN * 60
    for c in cards:
        if c.get("id") == "app":
            c["name"], c["what"] = "Apps on this PC", "the video app (runs most of these) and the profit tracker"
            if pc_off:
                c["parts"] = [dict(p, said=f"PC off - last seen {_ago(now - checked)}; its jobs pick up when it's on")
                              if p.get("name") == "Video app" else p for p in c.get("parts") or []]
                c["summary"] = f"PC off - last seen {_ago(now - checked)}; the tools on it show their last look"
    for c in cards:  # "last ran 3 h ago" was true when the PC looked; say it again from now
        c["parts"] = [_reaged(p, now) for p in c.get("parts") or []]
    start = _midnight(now, tz)
    for c in cards:
        c["today"] = today_lines(c, start)
    return {"built": now, "by": "pc" if pc_mode else "cloud", "checked": checked or None, "pc_off": pc_off,
            "cards": cards, "stock": snapshot.get("stock") or {}, "did": snapshot.get("did_text") or "",
            "biz": biz, "ads": ads, "notes": notes or [], "tz": tz,
            # 2026-11-21: the ads desk (his own ad rules, read-only) + the video learner, worked out on the PC
            "desk": snapshot.get("desk"), "learner": snapshot.get("learner")}


def _reaged(p, now):
    last = _stamp(p.get("last"))
    said = str(p.get("said") or "")
    m = re.match(r"^(last (?:ran|checked in|looked)) (just now|\d+ (?:min|h|days) ago)", said)
    if last and m:
        return dict(p, said=f"{m.group(1)} {_ago(now - last)}" + said[m.end():])
    return p


def _ago(sec):
    m = sec / 60
    return "just now" if m < 1 else f"{m:.0f} min ago" if m < 60 else f"{m / 60:.0f} h ago" if m < 36 * 60 \
        else f"{m / 1440:.0f} days ago"


# ------------------------------------------------------------------ publishing
def _git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=120, creationflags=NOWIN)


def publish(files, remote, fresh=False, tries=3):
    """Puts files into the page's repo; every other file there stays. fresh=True (the PC): one new commit replaces
    the history so old numbers don't pile up. The cloud just adds a commit. If the other writer pushed in between,
    the push is refused and it tries again on top of theirs."""
    err = ""
    for _ in range(tries):
        with tempfile.TemporaryDirectory() as tmp:
            r = _git(["clone", "--depth", "1", remote, "site"], tmp)
            if r.returncode != 0:
                raise RuntimeError("can't reach the page's repo: " + _clean(r.stderr, 200))
            site = Path(tmp) / "site"
            head = _git(["rev-parse", "HEAD"], site).stdout.strip()
            if fresh:
                _git(["checkout", "-q", "--orphan", "fresh"], site)
            for name, data in files.items():
                (site / name).parent.mkdir(parents=True, exist_ok=True)
                (site / name).write_bytes(data)
            _git(["add", "-A"], site)
            _git(["-c", "user.name=Jarvis", "-c", "user.email=jarvis@users.noreply.github.com", "commit", "-qm",
                  "Jarvis page"], site)
            if fresh:
                lease = f"--force-with-lease=main:{head}" if head else "--force"
                r = _git(["push", "-q", lease, "origin", "fresh:main"], site)
            else:
                r = _git(["push", "-q", "origin", "HEAD:main"], site)
            if r.returncode == 0:
                return True
            err = r.stderr
        time.sleep(3)
    raise RuntimeError("push refused: " + _clean(err, 200))


WORKFLOW = HERE / "jarvis_site_workflow.yml"  # the cloud job, copied into the page's repo by the PC


def site_files(key, data, snapshot=None, state=None):
    files = {"data.json": seal(key, data)}
    if snapshot is not None:  # the PC: also the page, this script and its cloud job (no secrets in any of them)
        files.update({"pc.json": seal(key, snapshot), "index.html": PAGE.read_bytes(), ".nojekyll": b"",
                      "robots.txt": b"User-agent: *\nDisallow: /\n", "jarvis_cloud.py": Path(__file__).read_bytes(),
                      ".github/workflows/jarvis.yml": WORKFLOW.read_bytes()})
    if state is not None:
        files["state.json"] = seal(key, state)
    return files


# ------------------------------------------------------------------ the two ways to run
TRACKER = Path.home() / "profit-tracker" / "src"


def tracker_settings():
    """The profit tracker's Shopify + Meta settings, secrets unlocked (they're Windows-locked on disk)."""
    sys.path.insert(0, str(TRACKER))
    import config as tracker_config
    return tracker_config.load()


def tracker_extras():
    """The ads desk + the video learner from the profit tracker (its own python runs src/cloud_extras.py, which only
    reads and prints). {} if it can't."""
    py = TRACKER.parent / ".venv" / "Scripts" / "python.exe"
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        r = subprocess.run([str(py), "-X", "utf8", str(TRACKER / "cloud_extras.py")], cwd=str(TRACKER.parent),
                           capture_output=True, text=True, encoding="utf-8", timeout=90, env=env, creationflags=NOWIN)
        return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


def run_pc(dry=False):
    """On the PC, after the monitor's look (src/jarvis_push.py runs this in the background)."""
    cache = ROOT / "cache"
    key = (cache / "jarvis_key.txt").read_text("utf-8").strip()
    now = time.time()
    mon = json.loads((cache / "monitor.json").read_text("utf-8"))
    stock = {}
    try:
        st = json.loads((cache / "stock.json").read_text("utf-8"))
        stock = {"products": st.get("products") or [], "sheet": st.get("sheet_mtime"), "lines": st.get("lines") or []}
    except (OSError, ValueError):
        pass
    snapshot = {"checked": mon.get("checked"), "cards": mon.get("cards") or [], "did_text": mon.get("did_text") or "",
                "stock": stock, "checkins": mon.get("checkins") or {}}
    extras = tracker_extras()  # kept in pc.json too, so the cloud run shows the PC's last desk + learner
    snapshot["desk"], snapshot["learner"] = extras.get("desk"), extras.get("learner")
    pt = tracker_settings()
    biz, ads, tz, notes = None, None, None, []
    try:
        s = pt["shopify"]
        biz, tz = shopify(s["store"], s["client_id"], s["client_secret"], s.get("api_version") or "2026-07", now)
    except Exception as e:
        notes.append(f"Sales couldn't be read: {_clean(e)}")
    try:
        ads = meta(pt["meta"]["token"], pt["meta"]["ad_account_id"])
    except Exception as e:
        notes.append(f"Ad numbers couldn't be read: {_clean(e)}")
    data = build(snapshot, now, tz, biz, ads, pc_mode=True, notes=notes)
    files = site_files(key, data, snapshot)
    if dry:  # a look on the PC only: cache/jarvis_site/, nothing goes online
        out = cache / "jarvis_site"
        for name, blob in files.items():
            (out / name).parent.mkdir(parents=True, exist_ok=True)
            (out / name).write_bytes(blob)
        return data
    publish(files, f"https://github.com/{SITE_REPO}.git", fresh=True)
    (cache / "jarvis_push.json").write_text(json.dumps({"at": now, "ok": True}), "utf-8")
    return data


def run_cloud():
    """On GitHub Actions inside the page's own public repo (free minutes; it pushes with the run's own token).
    Secrets there: JARVIS_KEY, SHOPIFY_STORE, SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, META_ACCESS_TOKEN (ads_read
    only) + META_AD_ACCOUNT_ID, NTFY_TOPIC. The log says one line: the numbers stay private."""
    env = os.environ
    key = env["JARVIS_KEY"].strip()
    now = time.time()
    here = Path.cwd()
    snapshot = unseal(key, (here / "pc.json").read_bytes()) if (here / "pc.json").exists() else {}
    if snapshot.get("checked") and now - float(snapshot["checked"]) < 35 * 60:
        print("The PC is on and keeps the page fresh.")
        return None
    state = unseal(key, (here / "state.json").read_bytes()) if (here / "state.json").exists() else {}
    notes, biz, ads, tz = [], None, None, None
    try:
        biz, tz = shopify(env["SHOPIFY_STORE"], env["SHOPIFY_CLIENT_ID"], env["SHOPIFY_CLIENT_SECRET"], now=now)
    except Exception as e:
        notes.append(f"Sales couldn't be read: {_clean(e)}")
    try:
        ads = meta(env["META_ACCESS_TOKEN"], env["META_AD_ACCOUNT_ID"])
    except Exception as e:
        notes.append(f"Ad numbers couldn't be read: {_clean(e)}")
    cards = snapshot.get("cards") or []
    seen = state.setdefault("checkins", {})  # ntfy keeps check-ins 12 h, so each one seen is remembered
    for k, v in (snapshot.get("checkins") or {}).items():
        if float(v.get("at") or 0) > float((seen.get(k) or {}).get("at") or 0):
            seen[k] = v
    try:
        if env.get("NTFY_TOPIC", "").strip():
            read_checkins(env["NTFY_TOPIC"].strip(), seen)
    except Exception as e:
        notes.append(f"The online jobs' check-ins couldn't be read: {_clean(e)}")
    overlay(cards, live_rows(cards, seen, now))
    snapshot["cards"] = cards
    data = build(snapshot, now, tz, biz, ads, notes=notes)
    remote = f"https://x-access-token:{env['GITHUB_TOKEN']}@github.com/{SITE_REPO}.git"
    publish(site_files(key, data, state=state), remote)
    print("Jarvis page updated.")
    return data


if __name__ == "__main__":
    if "--pc" in sys.argv:
        run_pc(dry="--dry" in sys.argv)
    else:
        run_cloud()
