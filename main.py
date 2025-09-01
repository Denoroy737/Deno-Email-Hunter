import asyncio
import hashlib
import io
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx
from dotenv import load_dotenv
from telegram import Update, constants
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters
from urllib.parse import quote as urlquote

# Optional free search (DuckDuckGo)
try:
    from duckduckgo_search import AsyncDDGS  # preferred if available
    HAVE_ASYNC_DDG = True
except Exception:
    HAVE_ASYNC_DDG = False
    try:
        from duckduckgo_search import DDGS  # fallback (sync)
    except Exception:
        DDGS = None

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
HOLEHE_PATH = os.getenv("HOLEHE_PATH", "holehe")    # pip install holehe
MAIGRET_PATH = os.getenv("MAIGRET_PATH", "maigret") # pip install maigret

# Configure behavior
ENABLE_DDG = os.getenv("ENABLE_DDG", "1") not in ("0", "false", "False")
MAX_USERNAMES = int(os.getenv("MAX_USERNAMES", "3"))  # limit Maigret scans to avoid long runs
MAIGRET_TIMEOUT = int(os.getenv("MAIGRET_TIMEOUT", "240"))  # seconds per username

HIBP_ENABLED = os.getenv("ENABLE_HIBP", "0") not in ("0", "false", "False")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
HIBP_UA = os.getenv("HIBP_UA", "EmailOSINTBot/0.1 (+https://github.com/your-repo)")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email: str) -> str:
    return email.strip().lower()


async def fetch_gravatar(email: str) -> Dict[str, Any]:
    """
    Free gravatar discovery:
      - basic profile (displayName, aboutMe, profileUrl)
      - avatar URL
      - linked accounts (may include usernames and URLs)
    """
    result = {"found": False}
    norm = normalize_email(email)
    md5sum = hashlib.md5(norm.encode("utf-8")).hexdigest()
    json_url = f"https://en.gravatar.com/{md5sum}.json"
    avatar_url = f"https://www.gravatar.com/avatar/{md5sum}?s=240&d=404"

    timeout = httpx.Timeout(12.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(json_url)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and data.get("entry"):
                entry = data["entry"][0]
                result["found"] = True
                result["hash"] = md5sum
                result["avatar"] = avatar_url
                result["displayName"] = entry.get("displayName")
                result["profileUrl"] = entry.get("profileUrl")
                result["aboutMe"] = entry.get("aboutMe")
                accounts = entry.get("accounts") or []
                cleaned = []
                for acc in accounts:
                    cleaned.append({
                        "shortname": acc.get("shortname"),
                        "url": acc.get("url"),
                        "username": acc.get("username"),
                        "domain": acc.get("domain"),
                        "verified": acc.get("verified"),
                    })
                result["accounts"] = cleaned
        else:
            result["found"] = False
    return result


def generate_usernames(email: str, gravatar: Dict[str, Any]) -> List[str]:
    """
    Heuristically generate candidate usernames from email local-part
    and Gravatar-linked accounts. Keep it small for speed.
    """
    local = email.split("@", 1)[0]
    local = local.split("+", 1)[0]  # drop tags
    parts = re.split(r"[._\-]+", local)
    base = re.sub(r"[^\w]", "", local)

    cands = set()
    if len(base) >= 3:
        cands.add(base)

    joined = "".join(parts)
    if len(joined) >= 3:
        cands.add(joined)

    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        if first and last:
            cands.update({
                f"{first}{last}",
                f"{first}_{last}",
                f"{first}.{last}",
            })
            if len(first) >= 1:
                cands.add(f"{first[0]}{last}")
            if len(last) >= 1:
                cands.add(f"{first}{last[0]}")

    # Gravatar usernames
    for acc in (gravatar.get("accounts") or []):
        u = acc.get("username")
        if u and len(u) >= 3 and re.match(r"^[A-Za-z0-9_.-]+$", u):
            cands.add(u)

    # Return a small, diverse set
    ordered = sorted(cands, key=lambda s: (len(s), s.lower()))
    return ordered[:MAX_USERNAMES]


async def ddg_email_search(email: str, count: int = 8) -> List[Dict[str, str]]:
    """
    Free search via DuckDuckGo. No API key. May be rate-limited sometimes.
    """
    if not ENABLE_DDG:
        return []
    results: List[Dict[str, str]] = []

    try:
        if HAVE_ASYNC_DDG:
            async with AsyncDDGS() as ddgs:
                async for r in ddgs.text(f"\"{email}\"", max_results=count):
                    results.append({
                        "name": r.get("title"),
                        "url": r.get("href"),
                        "snippet": r.get("body"),
                    })
        else:
            if DDGS is None:
                return []
            loop = asyncio.get_running_loop()

            def _work():
                out = []
                with DDGS() as ddgs:
                    for r in ddgs.text(f"\"{email}\"", max_results=count):
                        out.append({
                            "name": r.get("title"),
                            "url": r.get("href"),
                            "snippet": r.get("body"),
                        })
                return out

            results = await loop.run_in_executor(None, _work)
    except Exception:
        # Be quiet on search errors; this is optional
        return []
    return results


async def run_holehe(email: str, timeout_s: int = 120) -> Dict[str, Any]:
    """
    Free email existence scan across many sites using holehe CLI.
    pip install holehe
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            HOLEHE_PATH,
            email,
            "--only-used",
            "--no-ansi",
            "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {"available": False, "error": "holehe not found. Install: pip install holehe"}

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        return {"available": False, "error": "holehe timed out"}

    out = stdout.decode("utf-8", errors="ignore")
    err = stderr.decode("utf-8", errors="ignore")

    exists_count = 0
    sites = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                site = obj.get("site") or obj.get("name") or obj.get("url") or "unknown"
                exists = obj.get("exists")
                if exists is True:
                    exists_count += 1
                    sites.append(str(site))
        except json.JSONDecodeError:
            pass

    return {
        "available": True,
        "exists_count": exists_count,
        "sites": sites[:50],
        "raw": out,
        "stderr": err,
    }


def _extract_profiles_from_maigret_json(obj: Any) -> List[Dict[str, str]]:
    """
    Try to extract {site, url} from Maigret JSON, tolerant to version changes.
    """
    found = []

    def walk(x):
        if isinstance(x, dict):
            # Common Maigret fields
            if x.get("exists") is True and (x.get("url_user") or x.get("profile") or x.get("url")):
                url = x.get("url_user") or x.get("profile") or x.get("url")
                site = x.get("platform") or x.get("site") or x.get("name") or x.get("label") or "site"
                if url:
                    found.append({"site": str(site), "url": str(url)})
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)

    walk(obj)

    # dedupe by URL
    dedup = {}
    for f in found:
        dedup[f["url"]] = f
    return list(dedup.values())


async def run_maigret(username: str, timeout_s: int) -> Dict[str, Any]:
    """
    Free username scan across 500+ sites using Maigret CLI.
    pip install maigret
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            MAIGRET_PATH,
            username,
            "-a",
            "-j",  # JSON to stdout (supported by modern Maigret)
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {"available": False, "error": "maigret not found. Install: pip install maigret", "username": username}

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        return {"available": False, "error": "maigret timed out", "username": username}

    out = stdout.decode("utf-8", errors="ignore")
    err = stderr.decode("utf-8", errors="ignore")

    profiles: List[Dict[str, str]] = []
    try:
        data = json.loads(out)
        profiles = _extract_profiles_from_maigret_json(data)
    except json.JSONDecodeError:
        # Fallback: very rough URL sniff
        for line in out.splitlines():
            if "http" in line:
                m = re.search(r"https?://\S+", line)
                if m:
                    profiles.append({"site": "site", "url": m.group(0)})

    return {
        "available": True,
        "username": username,
        "profiles": profiles,
        "raw": out,
        "stderr": err,
    }


async def run_maigret_on_candidates(candidates: List[str], timeout_s: int) -> Dict[str, Any]:
    """
    Run Maigret for a few candidate usernames; merge results.
    """
    results = []
    for u in candidates:
        res = await run_maigret(u, timeout_s)
        results.append(res)

    # Merge found profiles
    merged_profiles = {}
    for r in results:
        for p in r.get("profiles", []):
            merged_profiles[p["url"]] = {"site": p.get("site", "site"), "url": p["url"]}

    return {
        "available": any(r.get("available") for r in results),
        "usernames": [r.get("username") for r in results],
        "profiles": list(merged_profiles.values()),
        "raw_runs": results,  # keep individual outputs for the report
    }
    
async def hibp_lookup(email: str, timeout_s: int = 20) -> Dict[str, Any]:
    """
    Optional HIBP breach & paste lookup for an email.
    Requires HIBP API key (paid). Disabled by default to keep project free.
    """
    if not HIBP_ENABLED or not HIBP_API_KEY:
        return {"available": False, "disabled": True, "reason": "disabled or no key"}

    base = "https://haveibeenpwned.com/api/v3"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": HIBP_UA,
        "accept": "application/json",
    }
    breaches: List[Dict[str, Any]] = []
    pastes: List[Dict[str, Any]] = []
    errors = []

    timeout = httpx.Timeout(timeout_s)
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        # Breached account lookup
        try:
            r = await client.get(
                f"{base}/breachedaccount/{urlquote(email)}",
                params={"truncateResponse": "false", "includeUnverified": "true"},
            )
            if r.status_code == 200:
                breaches = r.json() or []
            elif r.status_code == 404:
                breaches = []
            else:
                errors.append(f"breachedaccount status {r.status_code}")
        except Exception as e:
            errors.append(f"breachedaccount error: {e}")

        # Paste lookup (optional)
        try:
            r = await client.get(f"{base}/pasteaccount/{urlquote(email)}")
            if r.status_code == 200:
                pastes = r.json() or []
            elif r.status_code == 404:
                pastes = []
            else:
                errors.append(f"pasteaccount status {r.status_code}")
        except Exception as e:
            errors.append(f"pasteaccount error: {e}")

    # Light cleanup for summary
    breaches_summary = []
    for b in breaches:
        breaches_summary.append({
            "Name": b.get("Name"),
            "Title": b.get("Title"),
            "Domain": b.get("Domain"),
            "BreachDate": b.get("BreachDate"),
            "PwnCount": b.get("PwnCount"),
            "DataClasses": b.get("DataClasses"),
            "IsVerified": b.get("IsVerified"),
        })

    pastes_summary = []
    for p in pastes:
        pastes_summary.append({
            "Source": p.get("Source"),
            "Id": p.get("Id"),
            "Title": p.get("Title"),
            "Date": p.get("Date"),
            "EmailCount": p.get("EmailCount"),
        })

    return {
        "available": True,
        "breaches_count": len(breaches_summary),
        "pastes_count": len(pastes_summary),
        "breaches": breaches_summary,  # for summary + report
        "pastes": pastes_summary,      # for summary + report
        "raw": {"breaches": breaches, "pastes": pastes},
        "errors": errors,
    }


def format_summary(email: str,
                   gravatar: Dict[str, Any],
                   holehe: Dict[str, Any],
                   maigret_res: Dict[str, Any],
                   webhits: List[Dict[str, str]]) -> str:
    lines = []
    lines.append(f"🔎 Results for: {email}\n")

    # Gravatar
    if gravatar.get("found"):
        lines.append("🟢 Gravatar profile found:")
        if gravatar.get("displayName"): lines.append(f" • Name: {gravatar['displayName']}")
        if gravatar.get("profileUrl"): lines.append(f" • Profile: {gravatar['profileUrl']}")
        if gravatar.get("avatar"): lines.append(f" • Avatar: {gravatar['avatar']}")
        accounts = gravatar.get("accounts") or []
        if accounts:
            lines.append(f" • Linked accounts ({len(accounts)}):")
            for acc in accounts[:8]:
                label = acc.get("shortname") or acc.get("domain") or "account"
                url = acc.get("url")
                if url:
                    lines.append(f"   - {label}: {url}")
    else:
        lines.append("⚪ No public Gravatar profile detected.")

    lines.append("")

    # holehe
    if holehe.get("available"):
        cnt = holehe.get("exists_count", 0)
        lines.append(f"🟡 Email appears registered on ≈ {cnt} site(s) (holehe).")
        if holehe.get("sites"):
            s = ", ".join(holehe["sites"])
            lines.append(f" • Examples: {s}")
        lines.append(" • Full raw holehe output included in JSON report.")
    else:
        lines.append("⚪ holehe scan unavailable.")
        if holehe.get("error"):
            lines.append(f"   - {holehe['error']}")

    lines.append("")

    # Maigret username pivot
    if maigret_res.get("available"):
        profs = maigret_res.get("profiles", [])
        lines.append(f"🟣 Username pivot via Maigret: {len(profs)} profile(s) found across 500+ sites.")
        if profs:
            for p in profs[:12]:
                lines.append(f" • {p.get('site', 'site')}: {p['url']}")
        used = [u for u in (maigret_res.get("usernames") or []) if u]
        if used:
            lines.append(f" • Usernames checked: {', '.join(used)}")
        lines.append(" • Full Maigret outputs included in JSON report.")
    else:
        lines.append("⚪ Maigret scan unavailable.")
        err = ""
        for r in (maigret_res.get("raw_runs") or []):
            if r.get("error"):
                err = r["error"]; break
        if err:
            lines.append(f"   - {err}")

    lines.append("")

    # Web search
    if webhits:
        lines.append(f"🔗 DuckDuckGo mentions ({len(webhits)}):")
        for h in webhits[:6]:
            name = h.get("name") or "(result)"
            url = h.get("url")
            lines.append(f" • {name}: {url}")
    else:
        lines.append("⚪ No web search hits (or search disabled).")

    lines.append("")
    
    def format_summary(email: str,
                   gravatar: Dict[str, Any],
                   holehe: Dict[str, Any],
                   maigret_res: Dict[str, Any],
                   webhits: List[Dict[str, str]],
                   hibp: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"🔎 Results for: {email}\n")

    # HIBP (optional)
    lines.append("")
    if hibp.get("available"):
        bc = hibp.get("breaches_count", 0)
        pc = hibp.get("pastes_count", 0)
        if bc or pc:
            lines.append(f"🔴 HIBP: {bc} breach(es), {pc} paste(s) for this email.")
            # Show a few breach titles/domains
            for b in (hibp.get("breaches") or [])[:6]:
                title = b.get("Title") or b.get("Name") or "Breach"
                dom = b.get("Domain") or ""
                date = b.get("BreachDate") or ""
                lines.append(f" • {title} {f'({dom})' if dom else ''} {f'— {date}' if date else ''}")
            lines.append(" • Full HIBP details included in JSON report.")
        else:
            lines.append("🟢 HIBP: No breaches or pastes found for this email.")
        if hibp.get("errors"):
            lines.append(f" • HIBP notes: {', '.join(hibp['errors'])}")
    else:
        if hibp.get("disabled"):
            lines.append("⚪ HIBP: disabled (keeps project 100% free).")
        else:
            lines.append("⚪ HIBP: unavailable.")
            
       # ... existing Gravatar, holehe, Maigret sections ...

    lines.append("")
    lines.append("Note: Public OSINT only. Use with consent. Respect site ToS and local laws.")
    return "\n".join(lines)


# ---------------- Telegram Handlers ---------------- #

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "Hi! Send me an email address and I’ll run a free OSINT check.\n\n"
        "I use only free/open tools:\n"
        " • Gravatar profile + linked accounts\n"
        " • Email existence on many sites (holehe)\n"
        " • Username pivot → 500+ sites (Maigret)\n"
        " • Optional: DuckDuckGo web mentions (no API key)\n\n"
        "Send an email to begin."
    )
    await update.message.reply_text(msg, disable_web_page_preview=True)


async def handle_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    if not EMAIL_RE.match(text):
        await update.message.reply_text("Please send a valid email address, e.g. user@example.com")
        return

    email = normalize_email(text)
    await update.message.reply_chat_action(constants.ChatAction.TYPING)
    progress = await update.message.reply_text(f"Starting free OSINT scan for {email} … This can take a few minutes.")

    # Run base modules concurrently
    gravatar_task = asyncio.create_task(fetch_gravatar(email))
    holehe_task = asyncio.create_task(run_holehe(email))
    ddg_task = asyncio.create_task(ddg_email_search(email)) if ENABLE_DDG else asyncio.create_task(asyncio.sleep(0, result=[]))
    hibp_task = asyncio.create_task(hibp_lookup(email))  # returns "disabled" if off

    gravatar, holehe, webhits, hibp = await asyncio.gather(gravatar_task, holehe_task, ddg_task, hibp_task)

    # Username pivot (from email + gravatar)
    candidates = generate_usernames(email, gravatar)
    maigret_res = await run_maigret_on_candidates(candidates, MAIGRET_TIMEOUT)

    # Send summary
    summary = format_summary(email, gravatar, holehe, maigret_res, webhits, hibp)
    await progress.edit_text(summary, disable_web_page_preview=False)

    # Attach raw JSON report
    report = {
        "email": email,
        "gravatar": gravatar,
        "holehe": holehe,
        "username_candidates": candidates,
        "maigret": {
            "available": maigret_res.get("available"),
            "checked_usernames": maigret_res.get("usernames"),
            "profiles_found": maigret_res.get("profiles"),
            "raw_runs": maigret_res.get("raw_runs"),
        },
        "duckduckgo_hits": webhits,
        "hibp": hibp,  # include full HIBP details/raw
        "disclaimer": "Public OSINT only. Use with consent. Respect ToS and local laws.",
    }

    buf = io.BytesIO(json.dumps(report, indent=2).encode("utf-8"))
    buf.name = f"osint_{email.replace('@','_at_')}.json"
    await update.message.reply_document(document=buf, caption="Full JSON report (free tools + optional HIBP)")


def main():
    if not TELEGRAM_TOKEN:
        raise RuntimeError("Set TELEGRAM_TOKEN in .env")

    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_email))
    app.run_polling()


if __name__ == "__main__":
    main()