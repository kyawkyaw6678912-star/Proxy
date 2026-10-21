import logging
import asyncio
import math
import time
import io
import html
import json
import os
import string
import secrets
from datetime import datetime, timezone, timedelta
import aiohttp
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# ==================== SETTINGS ====================
BOT_TOKEN = "8955993670:AAGHkxHyG05Ut_VFev-vbVSk-QMUBhTAvRE"
CONCURRENCY = 200
PROXY_TIMEOUT = 2.0
# ==================================================

# ==================== ACCESS CONTROL ====================
ADMIN_ID = 6779617599

ACTIVE_KEYS = {}
USER_KEYS = {}
KEY_DURATIONS = {
    "1h": 60 * 60, "2h": 2 * 60 * 60, "6h": 6 * 60 * 60,
    "1d": 24 * 60 * 60, "3d": 3 * 24 * 60 * 60, "5d": 5 * 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60, "10d": 10 * 24 * 60 * 60, "15d": 15 * 24 * 60 * 60,
    "20d": 20 * 24 * 60 * 60, "30d": 30 * 24 * 60 * 60,
}
KEY_STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxycheck_keys.json")
BOT_USERS_FILE = "bot_users.json"
# =========================================================


logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

PROXY_SOURCE_CONCURRENCY = 30
PROXY_SOURCE_TIMEOUT_SECONDS = 5.0
PROXY_SOURCE_LIMIT = 45000
HTTP_CHECK_TIMEOUT_SECONDS = 3.0
SOCKS_CHECK_TIMEOUT_SECONDS = 3.0
PROXY_CHECK_HARD_TIMEOUT_SECONDS = 1.25
MAX_SINGLE_SCAN_CANDIDATES = 45000
MAX_ALL_SCAN_CANDIDATES = 45000
FAST_PROXY_TARGET = 200
FAST_PROXY_MAX_LATENCY_MS = 1500
SCAN_BATCH_SIZE = 300

ONLINE_WINDOW_SECONDS = 5 * 60
MM_TZ = timezone(timedelta(hours=6, minutes=30))


# ═══════════════════════════════════════════════════════════
# ★ aiohttp_socks availability check
# ═══════════════════════════════════════════════════════════
try:
    from aiohttp_socks import ProxyConnector
    AIOHTTP_SOCKS_AVAILABLE = True
    logger.info("✅ aiohttp_socks loaded — SOCKS4/SOCKS5 supported")
except ImportError:
    AIOHTTP_SOCKS_AVAILABLE = False
    logger.warning("⚠️ aiohttp_socks NOT installed — SOCKS4/SOCKS5 will be skipped")
    logger.warning("⚠️ Install with: pip install aiohttp-socks")


def now_mm_str() -> str:
    return datetime.now(MM_TZ).strftime("%Y-%m-%d %I:%M %p MMT")


def format_expiry_mm(expires_at) -> str:
    try:
        dt = datetime.fromtimestamp(float(expires_at), tz=MM_TZ)
        return dt.strftime("%Y-%m-%d %I:%M %p MMT")
    except Exception:
        return "Unknown"


def format_remaining_mm(expires_at) -> str:
    try:
        rem = int(float(expires_at) - time.time())
        if rem <= 0:
            return "Expired"
        days = rem // 86400
        hours = (rem % 86400) // 3600
        mins = (rem % 3600) // 60
        secs = rem % 60
        if days > 0:
            return f"{days}d {hours}h {mins}m"
        if hours > 0:
            return f"{hours}h {mins}m"
        if mins > 0:
            return f"{mins}m {secs}s"
        return f"{secs}s"
    except Exception:
        return "?"


# ═══════════════════════════════════════════════════════════
# ★ Bot Users Tracking
# ═══════════════════════════════════════════════════════════
def _load_json(path: str) -> dict:
    try:
        if not os.path.exists(path): return {}
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    except Exception: return {}

def _save_json(path: str, data: dict) -> None:
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception as e: print(f"[JSON] {path}: {e}")

def load_bot_users() -> dict:
    return _load_json(BOT_USERS_FILE)

def save_bot_users(data: dict) -> None:
    _save_json(BOT_USERS_FILE, data)

def track_bot_user(user) -> None:
    try:
        bot_users = load_bot_users()
        uid = str(user.id)
        info = bot_users.get(uid, {})
        info["id"] = user.id
        info["username"] = user.username or ""
        info["first_name"] = user.first_name or ""
        info["last_name"] = user.last_name or ""
        info["first_seen"] = info.get("first_seen", time.time())
        info["last_seen"] = time.time()
        info["seen_count"] = info.get("seen_count", 0) + 1
        bot_users[uid] = info
        save_bot_users(bot_users)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# ★ Country Code → Flag Emoji
# ═══════════════════════════════════════════════════════════
def country_code_to_flag(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "🏳️"
    code = code.upper()
    try:
        return chr(0x1F1E6 + ord(code[0]) - ord('A')) + chr(0x1F1E6 + ord(code[1]) - ord('A'))
    except Exception:
        return "🏳️"


# ═══════════════════════════════════════════════════════════
# ★ Global Stores
# ═══════════════════════════════════════════════════════════
scanning_jobs = {}
scan_tasks = {}
user_selected_type = {}
pending_delete = {}
user_contexts = {}


def is_admin(user_id: int) -> bool:
    return int(user_id) == int(ADMIN_ID) and int(ADMIN_ID) != 0


def generate_access_key(length=12) -> str:
    alphabet = string.ascii_uppercase + string.digits
    raw = ''.join(secrets.choice(alphabet) for _ in range(length))
    return '-'.join(raw[i:i+4] for i in range(0, length, 4))


# ═══════════════════════════════════════════════════════════
# ★ Access Key Store
# ═══════════════════════════════════════════════════════════
def save_key_store():
    payload = {
        "active_keys": ACTIVE_KEYS,
        "user_keys": {str(uid): key for uid, key in USER_KEYS.items()},
    }
    temporary_path = KEY_STORE_PATH + ".tmp"
    try:
        fd = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as store_file:
            json.dump(payload, store_file, ensure_ascii=False, indent=2)
            store_file.flush()
            os.fsync(store_file.fileno())
        os.replace(temporary_path, KEY_STORE_PATH)
        os.chmod(KEY_STORE_PATH, 0o600)
    except Exception:
        logger.exception("Unable to save access-key store")
        try:
            os.unlink(temporary_path)
        except OSError:
            pass


def expire_stale_keys(now=None):
    now = time.time() if now is None else now
    changed = False
    for key, info in list(ACTIVE_KEYS.items()):
        try:
            expires_at = float(info.get("expires_at", 0))
        except (AttributeError, TypeError, ValueError):
            expires_at = 0
        if expires_at <= now:
            user_id = info.get("user_id") if isinstance(info, dict) else None
            if user_id is not None and USER_KEYS.get(int(user_id)) == key:
                USER_KEYS.pop(int(user_id), None)
            ACTIVE_KEYS.pop(key, None)
            changed = True
    if changed:
        save_key_store()


def load_key_store():
    try:
        with open(KEY_STORE_PATH, "r", encoding="utf-8") as store_file:
            payload = json.load(store_file)
        keys = payload.get("active_keys", {})
        users = payload.get("user_keys", {})
        if isinstance(keys, dict):
            ACTIVE_KEYS.update(keys)
        if isinstance(users, dict):
            USER_KEYS.update({int(uid): key for uid, key in users.items()})
        os.chmod(KEY_STORE_PATH, 0o600)
    except FileNotFoundError:
        return
    except Exception:
        logger.exception("Unable to load access-key store")
        return
    expire_stale_keys()


def format_expiry(expires_at):
    return format_expiry_mm(expires_at)


load_key_store()


def is_authorized(user_id: int) -> bool:
    if is_admin(user_id):
        return True
    expire_stale_keys()
    key = USER_KEYS.get(int(user_id))
    info = ACTIVE_KEYS.get(key) if key else None
    return bool(info and float(info.get("expires_at", 0)) > time.time())


# ═══════════════════════════════════════════════════════════
# ★ Online Tracking
# ═══════════════════════════════════════════════════════════
def is_user_online(user_id) -> bool:
    try:
        bot_users = load_bot_users()
        info = bot_users.get(str(user_id))
        if not info: return False
        last_seen = info.get("last_seen", 0)
        return (time.time() - last_seen) < ONLINE_WINDOW_SECONDS
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════
# ★ Markups
# ═══════════════════════════════════════════════════════════
def access_denied_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔐  ENTER ACCESS KEY", callback_data="enter_key")],
    ])


def admin_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🎫  CREATE KEY", callback_data="admin_generate_key"),
         InlineKeyboardButton("🗝️  ACTIVE KEYS", callback_data="admin_list_keys")],
        [InlineKeyboardButton("👥  USERS", callback_data="admin_list_users"),
         InlineKeyboardButton("📊  BOT STATUS", callback_data="admin_bot_status")],
        [InlineKeyboardButton("🗑️  DELETE KEY", callback_data="admin_delete_key"),
         InlineKeyboardButton("📢  BROADCAST", callback_data="admin_broadcast")],
        [InlineKeyboardButton("🧹  CLEAR ALL KEYS", callback_data="admin_clear_all_keys")],
        [InlineKeyboardButton("🏠  MAIN MENU", callback_data="back_home")],
    ])


def clear_all_confirm_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅  YES, CLEAR ALL", callback_data="admin_clear_all_confirm"),
         InlineKeyboardButton("❌  CANCEL", callback_data="admin_back")],
    ])


def bot_status_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄  REFRESH", callback_data="admin_bot_status_refresh"),
         InlineKeyboardButton("↩️  BACK", callback_data="admin_back")],
    ])


def user_action_markup(user_id: int):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔙  USERS", callback_data="admin_list_users")],
    ])


def broadcast_confirm_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅  SEND NOW", callback_data="admin_broadcast_send"),
         InlineKeyboardButton("❌  CANCEL", callback_data="admin_broadcast_cancel")],
    ])


def key_duration_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⏰ 1 HOUR", callback_data="admin_duration_1h"),
         InlineKeyboardButton("⏰ 2 HOURS", callback_data="admin_duration_2h")],
        [InlineKeyboardButton("⏰ 6 HOURS", callback_data="admin_duration_6h"),
         InlineKeyboardButton("📅 1 DAY", callback_data="admin_duration_1d")],
        [InlineKeyboardButton("📅 3 DAYS", callback_data="admin_duration_3d"),
         InlineKeyboardButton("📅 5 DAYS", callback_data="admin_duration_5d")],
        [InlineKeyboardButton("📅 7 DAYS", callback_data="admin_duration_7d"),
         InlineKeyboardButton("📅 10 DAYS", callback_data="admin_duration_10d")],
        [InlineKeyboardButton("📅 15 DAYS", callback_data="admin_duration_15d"),
         InlineKeyboardButton("📅 20 DAYS", callback_data="admin_duration_20d")],
        [InlineKeyboardButton("📅 30 DAYS", callback_data="admin_duration_30d")],
        [InlineKeyboardButton("↩️  ADMIN PANEL", callback_data="admin_back")],
    ])


def delete_confirm_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅  DONE", callback_data="admin_delkey_confirm"),
         InlineKeyboardButton("❌  CANCEL", callback_data="admin_delkey_cancel")],
    ])


def main_menu_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐  HTTP", callback_data="select_http"),
         InlineKeyboardButton("🔒  HTTPS", callback_data="select_https")],
        [InlineKeyboardButton("🔵  SOCKS4", callback_data="select_socks4"),
         InlineKeyboardButton("🟣  SOCKS5", callback_data="select_socks5")],
        [InlineKeyboardButton("⚡  ALL PROTOCOLS", callback_data="select_all"),
         InlineKeyboardButton("🔗  MANUAL URL", callback_data="select_manual_url")],
        [InlineKeyboardButton("📖  HOW IT WORKS", callback_data="help")],
    ])


_PROXY_SCHEME_TO_TYPE = {
    "http": "http", "https": "https",
    "socks4": "socks4", "socks5": "socks5", "socks5h": "socks5",
}


def _normalize_proxy_candidate(raw_proxy, source_protocol, requested_protocol):
    proxy = raw_proxy.strip()
    if not proxy or proxy.startswith("#"):
        return None
    if source_protocol != "mixed" and requested_protocol not in ("all", source_protocol):
        return None
    if source_protocol == "https":
        if "://" in proxy:
            scheme, address = proxy.split("://", 1)
            if scheme.lower() not in ("http", "https") or ":" not in address:
                return None
            return f"http://{address}"
        if ":" not in proxy:
            return None
        return f"http://{proxy}"
    if "://" in proxy:
        scheme, address = proxy.split("://", 1)
        scheme = scheme.lower()
        detected_type = _PROXY_SCHEME_TO_TYPE.get(scheme)
        if detected_type is None or ":" not in address:
            return None
        if source_protocol == "mixed":
            if requested_protocol != "all" and detected_type != requested_protocol:
                return None
        else:
            accepted_schemes = {"socks5", "socks5h"} if source_protocol == "socks5" else {source_protocol}
            if scheme not in accepted_schemes:
                return None
        return f"{scheme}://{address}"
    if ":" not in proxy or source_protocol == "mixed":
        return None
    return f"{source_protocol}://{proxy}"


# ═══════════════════════════════════════════════════════════
# ★ Proxy Sources
# ═══════════════════════════════════════════════════════════
async def fetch_proxies_by_type(proxy_type, limit=100000):
    if limit <= 0:
        return []

    source_groups = {
        "http": [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=1000&country=all&ssl=all&anonymity=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=2000&country=all&ssl=all&anonymity=all",
            "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
            "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt",
            "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/http/data.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.txt",
            "https://www.proxy-list.download/api/v1/get?type=http",
        ],
        "https": [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=1000&country=all&ssl=yes&anonymity=all",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
            "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/https.txt",
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTPS.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/https/data.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/http/data.txt",
            "https://www.proxy-list.download/api/v1/get?type=https",
            "https://api.openproxylist.xyz/https.txt",
        ],
        "socks4": [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=1000&country=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=2000&country=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks4.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
            "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks4.txt",
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt",
            "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks4/data.txt",
            "https://www.proxy-list.download/api/v1/get?type=socks4",
            "https://api.openproxylist.xyz/socks4.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
        ],
        "socks5": [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=2000&country=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
            "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt",
            "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
            "https://raw.githubusercontent.com/xyzs996/free-proxy-health-list/main/proxies/protocols/socks5/data.txt",
            "https://raw.githubusercontent.com/stormsia/proxy-list/main/socks5.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/us/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/de/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/gb/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/fr/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/in/socks5/data.txt",
            "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/jp/socks5/data.txt",
            "https://www.proxy-list.download/api/v1/get?type=socks5",
            "https://api.openproxylist.xyz/socks5.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
        ],
    }
    mixed_sources = [
        "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
        "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
        "https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/all/data.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/all.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/all.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/all.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/ALL.txt",
    ]
    if proxy_type == "all":
        selected_groups = tuple(source_groups)
    else:
        selected_groups = (proxy_type,)
    sources = [
        (url, protocol)
        for protocol in selected_groups
        for url in source_groups.get(protocol, [])
    ]
    if proxy_type != "https":
        sources.extend((url, "mixed") for url in mixed_sources)

    source_limit = min(limit, PROXY_SOURCE_LIMIT)
    source_gate = asyncio.Semaphore(PROXY_SOURCE_CONCURRENCY)
    source_timeout = aiohttp.ClientTimeout(total=PROXY_SOURCE_TIMEOUT_SECONDS, connect=3.0)

    async def fetch_source(session, url, protocol):
        async with source_gate:
            try:
                async with session.get(url) as res:
                    if res.status != 200:
                        return []
                    text = await res.text()
                result = []
                for line in text.splitlines():
                    proxy = _normalize_proxy_candidate(line, protocol, proxy_type)
                    if proxy is not None:
                        result.append(proxy)
                        if len(result) >= source_limit:
                            break
                return result
            except Exception as exc:
                logger.warning("Proxy source unavailable (%s): %s", url, type(exc).__name__)
                return []

    connector = aiohttp.TCPConnector(limit=PROXY_SOURCE_CONCURRENCY, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector, timeout=source_timeout) as session:
        source_results = await asyncio.gather(
            *(fetch_source(session, url, protocol) for url, protocol in sources)
        )
    proxies = []
    seen = set()
    max_source_length = max((len(result) for result in source_results), default=0)
    for index in range(max_source_length):
        for source_result in source_results:
            if index >= len(source_result):
                continue
            proxy = source_result[index]
            if proxy in seen:
                continue
            seen.add(proxy)
            proxies.append(proxy)
            if len(proxies) >= limit:
                return proxies
    return proxies


# ═══════════════════════════════════════════════════════════
# ★ Manual URL (auto-detect protocol)
# ═══════════════════════════════════════════════════════════
async def fetch_proxies_from_manual_url(url):
    proxies = []
    seen = set()
    lower_url = url.lower()
    if "socks4" in lower_url:
        default_scheme = "socks4"
    elif "socks5" in lower_url:
        default_scheme = "socks5"
    else:
        default_scheme = "http"

    try:
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as res:
                if res.status != 200:
                    return []
                text = await res.text()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "://" in line:
                scheme = line.split("://", 1)[0].lower()
                if scheme in ("http", "https", "socks4", "socks5", "socks5h"):
                    if scheme == "socks5h":
                        p = "socks5://" + line.split("://", 1)[1]
                    elif scheme == "https":
                        p = "http://" + line.split("://", 1)[1]
                    else:
                        p = line
                    if p not in seen:
                        seen.add(p)
                        proxies.append(p)
                    continue
            if ":" in line and line.count(":") == 1:
                ip, port = line.split(":")
                if ip and port.isdigit():
                    p = f"{default_scheme}://{line}"
                    if p not in seen:
                        seen.add(p)
                        proxies.append(p)
    except Exception as e:
        logger.warning(f"Manual URL fetch error: {type(e).__name__}: {e}")
    return proxies


# ═══════════════════════════════════════════════════════════
# ★ Multi-API Verification
# ═══════════════════════════════════════════════════════════
async def verify_proxy_multi_api(proxy, proxy_type="socks5",
                                  min_passed=2, require_google=False,
                                  timeout_total=6.0):
    scheme = proxy.partition("://")[0].lower() if "://" in proxy else ""
    socks_scheme = scheme if scheme in ("socks4", "socks5", "socks5h") else ""
    if not socks_scheme and proxy_type in ("socks4", "socks5"):
        socks_scheme = proxy_type

    if socks_scheme:
        if not AIOHTTP_SOCKS_AVAILABLE:
            return False, 0, {"error": "aiohttp_socks_not_installed"}
        if scheme in ("socks4", "socks5"):
            proxy_url = proxy
        elif scheme == "socks5h":
            proxy_url = "socks5://" + proxy.split("://", 1)[1]
        elif scheme:
            proxy_url = f"{socks_scheme}://" + proxy.split("://", 1)[1]
        else:
            proxy_url = f"{socks_scheme}://{proxy}"
        try:
            connector = ProxyConnector.from_url(proxy_url)
        except Exception:
            return False, 0, {"error": "invalid_proxy"}
    else:
        proxy_url = proxy if scheme else f"http://{proxy}"
        connector = None

    ping_samples = []
    details = {
        "google": False, "amazon": False, "httpbin": False, "ipapi": False,
        "country": "?", "country_code": "?", "isp": "?",
        "is_proxy": False, "is_hosting": False,
    }
    detected_ips = []
    timeout = aiohttp.ClientTimeout(total=timeout_total, connect=3.0)

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as s:
            try:
                t0 = time.monotonic()
                kwargs = {} if connector else {"proxy": proxy_url}
                async with s.get("https://www.google.com/generate_204",
                                 ssl=False, **kwargs) as r:
                    if 200 <= r.status < 300:
                        details["google"] = True
                        ping_samples.append(math.ceil((time.monotonic() - t0) * 1000))
            except Exception:
                pass
            try:
                t0 = time.monotonic()
                kwargs = {} if connector else {"proxy": proxy_url}
                async with s.get("http://checkip.amazonaws.com/", **kwargs) as r:
                    if r.status == 200:
                        text = (await r.text()).strip()
                        if text and len(text.split(".")) == 4:
                            details["amazon"] = True
                            detected_ips.append(text)
                            ping_samples.append(math.ceil((time.monotonic() - t0) * 1000))
            except Exception:
                pass
            try:
                t0 = time.monotonic()
                kwargs = {} if connector else {"proxy": proxy_url}
                async with s.get("http://httpbin.org/ip", **kwargs) as r:
                    if r.status == 200:
                        data = await r.json()
                        origin = data.get("origin", "")
                        if origin:
                            details["httpbin"] = True
                            detected_ips.append(origin.split(",")[0].strip())
                            ping_samples.append(math.ceil((time.monotonic() - t0) * 1000))
            except Exception:
                pass
            try:
                t0 = time.monotonic()
                kwargs = {} if connector else {"proxy": proxy_url}
                async with s.get(
                    "http://ip-api.com/json/?fields=status,country,countryCode,isp,proxy,hosting,query",
                    **kwargs
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        if data.get("status") == "success":
                            details["ipapi"] = True
                            details["country"] = data.get("country", "?")
                            details["country_code"] = data.get("countryCode", "?")
                            details["isp"] = data.get("isp", "?")
                            details["is_proxy"] = data.get("proxy", False)
                            details["is_hosting"] = data.get("hosting", False)
                            q = data.get("query", "")
                            if q:
                                detected_ips.append(q)
                            ping_samples.append(math.ceil((time.monotonic() - t0) * 1000))
            except Exception:
                pass
    except Exception:
        pass

    passed = sum(1 for v in (details["google"], details["amazon"],
                             details["httpbin"], details["ipapi"]) if v)
    is_ok = passed >= min_passed
    if require_google and not details["google"]:
        is_ok = False

    avg_ping = math.ceil(sum(ping_samples) / len(ping_samples)) if ping_samples else 0

    unique_ips = set(ip for ip in detected_ips if ip)
    if len(unique_ips) > 1:
        details["ip_mismatch"] = True
        is_ok = False

    details["passed"] = f"{passed}/4"
    details["detected_ip"] = list(unique_ips)[0] if unique_ips else "?"
    return is_ok, avg_ping, details


async def verify_proxy_double_check(proxy, proxy_type="socks5",
                                     min_passed=2, require_google=False,
                                     timeout_total=6.0,
                                     gap_seconds=0.1):
    is_ok1, ping1, details1 = await verify_proxy_multi_api(
        proxy, proxy_type,
        min_passed=min_passed,
        require_google=require_google,
        timeout_total=timeout_total,
    )
    if not is_ok1 or ping1 <= 0:
        return False, 0, details1 or {}

    await asyncio.sleep(gap_seconds)

    is_ok2, ping2, details2 = await verify_proxy_multi_api(
        proxy, proxy_type,
        min_passed=min_passed,
        require_google=require_google,
        timeout_total=timeout_total,
    )
    if not is_ok2 or ping2 <= 0:
        return False, 0, details2 or details1 or {}

    return True, max(ping1, ping2), details2


# ═══════════════════════════════════════════════════════════
# ★ Manual URL Scan
# ═══════════════════════════════════════════════════════════
async def run_manual_url_scan(context, chat_id, user_id, url):
    stop_keyboard = InlineKeyboardMarkup(
        [[InlineKeyboardButton("⏹  STOP SCAN", callback_data="stop_scan")]]
    )
    try:
        msg = await context.bot.send_message(
            chat_id,
            "🔗 <b>MANUAL URL SCAN</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🌐 URL: <code>{html.escape(url[:60])}...</code>\n"
            "⏳ Downloading proxies from URL…",
            parse_mode=ParseMode.HTML,
            reply_markup=stop_keyboard,
        )
    except Exception:
        return

    proxies = await fetch_proxies_from_manual_url(url)

    if not scanning_jobs.get(chat_id, False):
        try:
            await msg.edit_text("🛑 Scan ရပ်လိုက်ပါပြီ။")
        except Exception:
            pass
        return

    if not proxies:
        try:
            await msg.edit_text(
                "⚠️ <b>NO PROXIES FOUND</b>\n\n"
                f"URL ကနေ proxy မရှာတွေ့ပါ။\n"
                f"<code>{html.escape(url)}</code>",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("⬅️ ပင်မမီနူး", callback_data="back_home")]]
                ),
            )
        except Exception:
            pass
        return

    total = len(proxies)
    if total > MAX_SINGLE_SCAN_CANDIDATES:
        proxies = proxies[:MAX_SINGLE_SCAN_CANDIDATES]
        total = len(proxies)

    try:
        await msg.edit_text(
            "🔗 <b>MANUAL URL SCAN</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📥 Found: <b>{total:,}</b> proxies\n"
            "🔍 Verifying (2/4 ×2)…\n"
            "📊 Progress: <b>0.00%</b>\n"
            "✅ Live: <b>0</b>\n"
            "<code>▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📥 <b>LIVE RESULTS</b>\n"
            "<i>Waiting…</i>",
            parse_mode=ParseMode.HTML,
            reply_markup=stop_keyboard,
        )
    except Exception:
        pass

    checked = 0
    found = 0
    retries = 0
    start_time = time.time()
    found_records = []
    formatted_items = []
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def worker(proxy, session):
        nonlocal checked, found, retries
        if not scanning_jobs.get(chat_id, False):
            return
        async with semaphore:
            if not scanning_jobs.get(chat_id, False):
                return
            ptype = proxy.split("://", 1)[0] if "://" in proxy else "http"
            try:
                is_ok, ping, details = await asyncio.wait_for(
                    verify_proxy_double_check(
                        proxy, ptype,
                        min_passed=2, require_google=False,
                        timeout_total=6.0,
                        gap_seconds=0.1,
                    ),
                    timeout=10.0,
                )
            except asyncio.TimeoutError:
                is_ok, ping, details = False, 0, {}
            except Exception:
                is_ok, ping, details = False, 0, {}

            checked += 1
            if is_ok and 0 < ping <= FAST_PROXY_MAX_LATENCY_MS:
                found += 1
                found_records.append((ping, proxy, details))
                cc = details.get("country_code", "?")
                flag = country_code_to_flag(cc)
                passed = details.get("passed", "?/4")
                line_text = (
                    f"• <code>{html.escape(proxy)}</code>  ·  "
                    f"<code>{ping} ms</code>  ·  {flag}  ·  {passed}"
                )
                formatted_items.append((ping, line_text))
            else:
                retries += 1

    batch_size = SCAN_BATCH_SIZE
    percent = 0.0
    is_stopped = False

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=CONCURRENCY, ttl_dns_cache=300)
    ) as session:
        for i in range(0, total, batch_size):
            if not scanning_jobs.get(chat_id, False):
                is_stopped = True
                break
            batch = proxies[i:i+batch_size]
            await asyncio.gather(*[worker(p, session) for p in batch])
            if not scanning_jobs.get(chat_id, False):
                is_stopped = True
                break

            elapsed = time.time() - start_time
            speed = int(checked / elapsed) if elapsed > 0 else 0
            percent = (checked / total) * 100
            filled = min(20, max(0, int(percent // 5)))
            bar = "▰" * filled + "▱" * (20 - filled)

            header = (
                "🔗 <b>MANUAL URL SCAN</b>\n"
                f"📦 Checked: <code>{checked:,} / {total:,}</code>\n"
                f"📊 Progress: <b>{percent:.2f}%</b>  ·  ⚡ <code>{speed:,}/s</code>\n"
                f"✅ Verified: <b>{found}</b>  ·  ❌ Excluded: <b>{retries}</b>\n"
                f"<code>{bar}</code>\n"
                "━━━━━━━━━━━━━━━━━━━━\n"
                f"📥 <b>VERIFIED · ≤{FAST_PROXY_MAX_LATENCY_MS}ms · 2/4 ×2</b>\n"
            )
            temp_lines = []
            clen = len(header)
            for _, item in sorted(formatted_items, key=lambda x: x[0])[:100]:
                ilen = len(item) + 2
                if clen + ilen < 3900:
                    temp_lines.append(item)
                    clen += ilen
                else:
                    break
            body = "\n".join(temp_lines) if temp_lines else "<i>Waiting…</i>"
            try:
                await msg.edit_text(header + body,
                                    parse_mode=ParseMode.HTML,
                                    reply_markup=stop_keyboard)
            except Exception:
                pass
            await asyncio.sleep(0.02)

    scanning_jobs[chat_id] = False
    found_records.sort(key=lambda x: x[0])
    formatted_items.sort(key=lambda x: x[0])

    final_text = (
        f"🔗 <b>MANUAL URL SCAN · {'STOPPED' if is_stopped else 'DONE'}</b>\n"
        f"📦 Checked: <code>{checked:,} / {total:,}</code>\n"
        f"✅ Qualified: <b>{found}</b>  ·  ❌ Excluded: <b>{retries}</b>\n"
        f"📊 Progress: <b>{percent:.2f}%</b>"
    )
    try:
        await msg.edit_text(
            final_text,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅️ ပင်မမီနူး", callback_data="back_home")]]
            ),
        )
    except Exception:
        pass

    if formatted_items:
        chunk = (
            f"🔗 <b>MANUAL URL · VERIFIED 2/4 ×2</b>\n"
            f"📥 ≤{FAST_PROXY_MAX_LATENCY_MS}ms\n\n"
        )
        for _, item in formatted_items[:100]:
            add = item + "\n\n"
            if len(chunk) + len(add) > 3900:
                try:
                    await context.bot.send_message(chat_id, chunk, parse_mode=ParseMode.HTML)
                except Exception:
                    pass
                chunk = f"🔗 <b>MANUAL URL · VERIFIED (cont.)</b>\n\n" + add
            else:
                chunk += add
        try:
            await context.bot.send_message(chat_id, chunk, parse_mode=ParseMode.HTML)
        except Exception:
            pass

    if found_records:
        content = "\n\n".join(p for _, p, _ in found_records)
        fb = io.BytesIO(content.encode("utf-8"))
        ts = datetime.now(MM_TZ).strftime("%Y%m%d_%H%M%S")
        fb.name = f"manual_url_{ts}_under_{FAST_PROXY_MAX_LATENCY_MS}ms.txt"
        try:
            await context.bot.send_document(
                chat_id,
                document=fb,
                caption=(
                    f"📁 <code>{fb.name}</code>\n"
                    f"✅ Live proxies: <b>{len(found_records)}</b> · "
                    f"≤{FAST_PROXY_MAX_LATENCY_MS}ms · 2/4 ×2 verified"
                ),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            logger.exception("Manual URL file send failed")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    try:
        track_bot_user(update.effective_user)
    except Exception:
        pass

    user_contexts[user_id] = context

    if not is_authorized(user_id):
        text = (
            "🔐 <b>ACCESS REQUIRED</b>\n"
            "ဒီ bot ကို အသုံးပြုရန် Admin ထုတ်ပေးထားသော access key လိုအပ်ပါတယ်။\n\n"
            "🔑 ဆက်လက်ရန် အောက်က ခလုတ်ကိုနှိပ်ပါ။"
        )
        if update.message:
            await update.message.reply_text(text, parse_mode=ParseMode.HTML,
                reply_markup=access_denied_markup())
        else:
            await update.callback_query.edit_message_text(text, parse_mode=ParseMode.HTML,
                reply_markup=access_denied_markup())
        return

    if is_admin(user_id):
        keyboard = InlineKeyboardMarkup(
            [list(row) for row in main_menu_markup().inline_keyboard]
            + [[InlineKeyboardButton("⚙️  ADMIN PANEL", callback_data="admin_back")]]
        )
        welcome_text = (
            "🌐 <b>KYAWZIN PROXY</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "👑 <b>ADMIN MODE</b>  ·  🟢 <b>ONLINE</b>\n\n"
            "Choose a protocol or paste a Manual URL."
        )
    else:
        keyboard = main_menu_markup()
        welcome_text = (
            "🌐 <b>KYAWZIN PROXY</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "🔓 <b>ACCESS GRANTED</b>  ·  🟢 <b>ONLINE</b>\n\n"
            "Choose a protocol or paste a Manual URL."
        )
    if update.message:
        await update.message.reply_text(welcome_text, parse_mode=ParseMode.HTML, reply_markup=keyboard)
    else:
        await update.callback_query.edit_message_text(welcome_text, parse_mode=ParseMode.HTML, reply_markup=keyboard)


# ═══════════════════════════════════════════════════════════
# ★ Key Message Handler
# ═══════════════════════════════════════════════════════════
async def key_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if not context.user_data.get("awaiting_key"):
        return

    key = update.message.text.strip().upper()
    context.user_data["awaiting_key"] = False
    expire_stale_keys()

    if key not in ACTIVE_KEYS:
        await update.message.reply_text(
            "❌ <b>Key မှားယွင်းနေပါသည်</b>\n\n"
            "Admin ထံမှ Key အသစ် တောင်းပါ။\n"
            "Key ကို ပြန်စစ်ပြီး ထပ်မံ ပို့ပါ။",
            parse_mode=ParseMode.HTML,
            reply_markup=access_denied_markup())
        return

    info = ACTIVE_KEYS[key]

    reserved = info.get("reserved_for")
    if reserved is not None and int(reserved) != user_id:
        await update.message.reply_text(
            f"⚠️ <b>ဒီ Key က သင်အတွက် မဟုတ်ပါ</b>\n\n"
            f"🔑 Key: <code>{key}</code>\n"
            f"👤 Reserved for: <code>{reserved}</code>\n"
            f"👤 Your ID: <code>{user_id}</code>",
            parse_mode=ParseMode.HTML,
            reply_markup=access_denied_markup())
        return

    if info.get("used_by") and int(info["used_by"]) != user_id:
        await update.message.reply_text(
            "⚠️ <b>ဒီ Key ကို အခြား User တစ်ယောက် အသုံးပြုပြီးပါပြီ။</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=access_denied_markup())
        return

    info["used_by"] = user_id
    info["user_id"] = user_id
    info["used_at"] = time.time()
    USER_KEYS[user_id] = key
    save_key_store()

    if is_admin(user_id):
        keyboard = InlineKeyboardMarkup(
            [list(row) for row in main_menu_markup().inline_keyboard]
            + [[InlineKeyboardButton("⚙️  ADMIN PANEL", callback_data="admin_back")]]
        )
    else:
        keyboard = main_menu_markup()

    await update.message.reply_text(
        "🎊 <b>ACCESS GRANTED</b>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"🔑 Key: <code>{key}</code>\n"
        f"⏳ Expires: <code>{format_expiry(info['expires_at'])}</code>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "✅ သင့် Key ကို အောင်မြင်စွာ ချိတ်ဆက်ပြီးပါပြီ။",
        parse_mode=ParseMode.HTML,
        reply_markup=keyboard)


# ═══════════════════════════════════════════════════════════
# ★ Genkey Text Handler
# ═══════════════════════════════════════════════════════════
async def genkey_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id):
        return

    if not context.user_data.get("awaiting_gen_user_id"):
        return

    raw_input = update.message.text.strip()
    context.user_data["awaiting_gen_user_id"] = False

    if not raw_input.isdigit():
        await update.message.reply_text(
            "❌ <b>Invalid User ID</b>\n\n"
            "ဂဏန်းသက်သက် ရိုက်ထည့်ပါ။\n"
            "📌 ဥပမာ: <code>6779617599</code>",
            parse_mode=ParseMode.HTML,
            reply_markup=admin_markup())
        context.user_data.pop("pending_duration", None)
        return

    target_uid = int(raw_input)
    duration_code = context.user_data.pop("pending_duration", None)
    if not duration_code:
        await update.message.reply_text(
            "❌ <b>Duration မရှိတော့ပါ</b>\n\nပြန်စပါ။",
            parse_mode=ParseMode.HTML, reply_markup=admin_markup())
        return

    duration_seconds = KEY_DURATIONS.get(duration_code)
    if duration_seconds is None:
        await update.message.reply_text("❌ Unknown duration",
            reply_markup=admin_markup())
        return

    duration_label = {
        "1h": "1 hour", "2h": "2 hours", "6h": "6 hours",
        "1d": "1 day", "3d": "3 days", "5d": "5 days",
        "7d": "7 days", "10d": "10 days", "15d": "15 days",
        "20d": "20 days", "30d": "30 days",
    }[duration_code]

    expire_stale_keys()
    key = generate_access_key()
    expires_at = time.time() + duration_seconds
    ACTIVE_KEYS[key] = {
        "created_by": user_id,
        "user_id": target_uid,
        "duration": duration_code,
        "expires_at": expires_at,
        "reserved_for": target_uid,
        "created_at": time.time(),
        "used_by": None,
    }
    save_key_store()

    await update.message.reply_text(
        "✅ <b>KEY GENERATED</b>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"🔑 Key: <code>{key}</code>\n"
        f"👤 For User ID: <code>{target_uid}</code>\n"
        f"⏳ Valid for: <b>{duration_label}</b>\n"
        f"📅 Expires: <code>{format_expiry(expires_at)}</code>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "⚠️ ဒီ Key ကို အဲ့ User ID ပဲ သုံးလို့ ရပါမယ်။\n\n"
        "📤 Key ကို User ကို ပေးပါ။",
        parse_mode=ParseMode.HTML,
        reply_markup=admin_markup())


# ═══════════════════════════════════════════════════════════
# ★ Admin Del Key Handler
# ═══════════════════════════════════════════════════════════
async def admin_delkey_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    if not context.user_data.get("awaiting_delkey"): return
    raw_input = update.message.text.strip()
    context.user_data["awaiting_delkey"] = False
    expire_stale_keys()

    if raw_input.isdigit():
        target_uid = int(raw_input)
        target_key = USER_KEYS.get(target_uid)
        if not target_key or target_key not in ACTIVE_KEYS:
            await update.message.reply_text(
                f"❌ <b>USER ID NOT FOUND</b>\n\n<code>{target_uid}</code> အတွက် active key မရှိပါ။",
                parse_mode=ParseMode.HTML, reply_markup=admin_markup())
            return
        info = ACTIVE_KEYS[target_key]
        pending_delete[user_id] = {"key": target_key, "user_id": target_uid, "expires_at": info.get("expires_at")}
    else:
        target_key = raw_input.upper()
        if target_key not in ACTIVE_KEYS:
            await update.message.reply_text(
                f"❌ <b>KEY NOT FOUND</b>\n\n<code>{html.escape(target_key)}</code> မရှိပါ။",
                parse_mode=ParseMode.HTML, reply_markup=admin_markup())
            return
        info = ACTIVE_KEYS[target_key]
        pending_delete[user_id] = {"key": target_key, "user_id": info.get("user_id"), "expires_at": info.get("expires_at")}

    record = pending_delete[user_id]
    linked = record["user_id"]
    expires = record["expires_at"]
    await update.message.reply_text(
        "⚠️ <b>CONFIRM DELETE</b>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"🔑 Key: <code>{record['key']}</code>\n"
        f"👤 User ID: <code>{linked if linked else 'Not claimed yet'}</code>\n"
        f"⏳ Expires: <code>{format_expiry(expires) if expires else 'Unknown'}</code>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "ဒီ Key ကို ဖျက်မှာ သေချာပါသလား?\n"
        "👉 <b>DONE</b> = ဖျက်မည်  ·  <b>CANCEL</b> = မဖျက်တော့ပါ",
        parse_mode=ParseMode.HTML, reply_markup=delete_confirm_markup())


# ═══════════════════════════════════════════════════════════
# ★ Broadcast
# ═══════════════════════════════════════════════════════════
async def broadcast_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    if not context.user_data.get("awaiting_broadcast"): return

    message_text = update.message.text.strip()

    if not message_text:
        await update.message.reply_text("❌ Message ဗလာဖြစ်နေပါသည်။",
            reply_markup=admin_markup())
        context.user_data["awaiting_broadcast"] = False
        return

    if len(message_text) > 4000:
        await update.message.reply_text("❌ Message ရှည်လွန်းပါသည် (max 4000 chars)။",
            reply_markup=admin_markup())
        context.user_data["awaiting_broadcast"] = False
        return

    context.user_data["awaiting_broadcast"] = False
    context.user_data["broadcast_preview"] = message_text

    bot_users = load_bot_users()
    total = len(bot_users)

    preview_text = (
        f"📢 <b>BROADCAST PREVIEW</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👥 Recipients: <b>{total}</b> users\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📝 <b>Message:</b>\n\n"
        f"{message_text}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ ဒီ Message ကို User {total} ယောက်ဆီ ပို့မှာ သေချာပါသလား?"
    )

    await update.message.reply_text(
        preview_text,
        parse_mode=ParseMode.HTML,
        reply_markup=broadcast_confirm_markup())


async def broadcast_message_from_query(query, context, message_text: str):
    bot_users = load_bot_users()
    user_ids = list(bot_users.keys())

    if not user_ids:
        try:
            await query.edit_message_text("⚠️ User မရှိသေးပါ။",
                reply_markup=admin_markup())
        except Exception:
            pass
        return

    total = len(user_ids)
    sent = 0
    failed = 0
    blocked = 0

    for i, uid in enumerate(user_ids, 1):
        try:
            target_id = int(uid)
            await context.bot.send_message(
                chat_id=target_id,
                text=message_text,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=False)
            sent += 1
        except Exception as e:
            err_str = str(e).lower()
            if "blocked" in err_str or "forbidden" in err_str:
                blocked += 1
            else:
                failed += 1

        if i % 10 == 0 or i == total:
            try:
                await query.edit_message_text(
                    f"📢 <b>Broadcasting...</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"📤 Sent: <b>{sent}</b> / {total}\n"
                    f"❌ Failed: <b>{failed}</b>\n"
                    f"🚫 Blocked: <b>{blocked}</b>\n"
                    f"📊 Progress: <b>{(i/total)*100:.1f}%</b>",
                    parse_mode=ParseMode.HTML)
            except Exception:
                pass

        await asyncio.sleep(0.05)

    final_text = (
        f"✅ <b>BROADCAST COMPLETE</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📤 Sent: <b>{sent}</b> / {total}\n"
        f"❌ Failed: <b>{failed}</b>\n"
        f"🚫 Blocked: <b>{blocked}</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🕐 {now_mm_str()}"
    )
    try:
        await query.edit_message_text(final_text, parse_mode=ParseMode.HTML,
            reply_markup=admin_markup())
    except Exception:
        pass


async def manual_url_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    if not context.user_data.get("awaiting_manual_url"): return
    url = update.message.text.strip()
    context.user_data["awaiting_manual_url"] = False
    if not (url.startswith("http://") or url.startswith("https://")):
        await update.message.reply_text("❌ http:// သို့မဟုတ် https:// နဲ့ စပါ။",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ ပင်မမီနူး", callback_data="back_home")]]))
        return
    active_task = scan_tasks.get(chat_id)
    if active_task is not None and not active_task.done():
        await update.message.reply_text("⚠️ Scan တစ်ခု ပြေးနေပြီးသားပါ။")
        return
    scanning_jobs[chat_id] = True

    async def run_guarded():
        try:
            await run_manual_url_scan(context, chat_id, user_id, url)
        finally:
            scanning_jobs[chat_id] = False
            scan_tasks.pop(chat_id, None)

    task = asyncio.create_task(run_guarded())
    scan_tasks[chat_id] = task


# ═══════════════════════════════════════════════════════════
# ★ Main Proxy Scan
# ═══════════════════════════════════════════════════════════
async def run_proxy_scan(query, context, chat_id, proxy_type):
    try:
        display_name = "ALL" if proxy_type == "all" else proxy_type.upper()
        limit_count = MAX_ALL_SCAN_CANDIDATES if proxy_type == "all" else MAX_SINGLE_SCAN_CANDIDATES
        stop_keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("⏹  STOP SCAN", callback_data="stop_scan")]])

        try:
            await query.edit_message_text(
                "🌐 <b>KYAWZIN PROXY</b> · <code>SCAN SETUP</code>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                f"📡 Protocol: <b>{display_name}</b>\n"
                f"📥 Collecting up to <b>{limit_count:,}</b> candidates.\n"
                "⏳ Loading public proxy sources…\n\n"
                f"✅ Live: 2/4 ×2 checks\n"
                f"✅ Final: 2/4 ×2 recheck\n"
                f"✅ Only proxies passing ≤{FAST_PROXY_MAX_LATENCY_MS} ms are included.\n"
                "Use STOP anytime to keep the verified results so far.",
                parse_mode=ParseMode.HTML, reply_markup=stop_keyboard)
        except Exception:
            pass

        source_task = asyncio.create_task(fetch_proxies_by_type(proxy_type, limit=limit_count))
        while not source_task.done():
            if not scanning_jobs.get(chat_id, False):
                source_task.cancel()
                await asyncio.gather(source_task, return_exceptions=True)
                try:
                    await query.edit_message_text("🛑 Scan ရပ်လိုက်ပါပြီ။")
                except Exception:
                    pass
                return
            await asyncio.wait({source_task}, timeout=0.2)
        proxies = source_task.result()
        if not scanning_jobs.get(chat_id, False):
            try:
                await query.edit_message_text("🛑 Scan ရပ်လိုက်ပါပြီ။")
            except Exception:
                pass
            return
        total = len(proxies)

        if total == 0:
            try:
                await query.edit_message_text(
                    "⚠️ <b>NO PROXIES FOUND</b>\n"
                    f"No {display_name} sources returned usable proxies.",
                    parse_mode=ParseMode.HTML,
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ ပင်မမီနူး", callback_data="back_home")]]))
            except Exception:
                pass
            return

        try:
            msg = await query.edit_message_text(
                "🌐 <b>KYAWZIN PROXY</b> · <code>SCANNING</code>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                f"🛰 Protocol: <b>{display_name}</b>\n"
                f"📥 Candidate pool: <code>{total:,} / {limit_count:,} max</code>\n"
                f"📦 Checked: <code>0 / {total:,}</code>\n"
                "📊 Progress: <b>0.00%</b>\n"
                "⚡ Speed: <code>0 proxy/s</code>\n"
                "✅ Live (2/4 ×2): <b>0</b>\n"
                "<code>▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱</code>\n"
                "━━━━━━━━━━━━━━━━━━━━\n"
                "📥 <b>LIVE RESULTS</b>\n"
                "<i>Waiting for verified proxies…</i>",
                parse_mode=ParseMode.HTML, reply_markup=stop_keyboard)
        except Exception:
            return

        checked = 0
        found = 0
        retries = 0
        start_time = time.time()
        found_proxy_records = []
        formatted_items = []
        semaphore = asyncio.Semaphore(CONCURRENCY)

        async def worker(proxy, session):
            nonlocal checked, found, retries
            if not scanning_jobs.get(chat_id, False):
                return
            async with semaphore:
                if not scanning_jobs.get(chat_id, False):
                    return
                try:
                    is_ok, ping, details = await asyncio.wait_for(
                        verify_proxy_double_check(
                            proxy, proxy_type,
                            min_passed=2, require_google=False,
                            timeout_total=6.0,
                            gap_seconds=0.1,
                        ),
                        timeout=10.0,
                    )
                except asyncio.TimeoutError:
                    is_ok, ping, details = False, 0, {}
                except Exception:
                    is_ok, ping, details = False, 0, {}
                checked += 1
                if is_ok and 0 < ping <= FAST_PROXY_MAX_LATENCY_MS:
                    found += 1
                    if proxy.startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://")):
                        clean_proxy = proxy
                    elif proxy_type in ("socks4", "socks5"):
                        clean_proxy = f"{proxy_type}://{proxy}"
                    else:
                        clean_proxy = f"http://{proxy}"
                    found_proxy_records.append((ping, clean_proxy, details))
                    cc = details.get("country_code", "?")
                    flag = country_code_to_flag(cc)
                    passed = details.get("passed", "?/4")
                    line_text = (
                        f"• <code>{html.escape(clean_proxy)}</code>  ·  "
                        f"<code>{ping} ms</code>  ·  {flag}  ·  {passed}"
                    )
                    formatted_items.append((ping, line_text))
                else:
                    retries += 1

        batch_size = SCAN_BATCH_SIZE
        is_stopped = False
        fast_target_reached = False
        percent = 0.0

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=CONCURRENCY, ttl_dns_cache=300)
        ) as session:
            for i in range(0, total, batch_size):
                if not scanning_jobs.get(chat_id, False):
                    is_stopped = True
                    break
                batch = proxies[i:i+batch_size]
                tasks = [worker(p, session) for p in batch]
                await asyncio.gather(*tasks)
                if not scanning_jobs.get(chat_id, False):
                    is_stopped = True
                    percent = (checked / total) * 100 if total else 0.0
                    break
                elapsed = time.time() - start_time
                speed = int(checked / elapsed) if elapsed > 0 else 0
                percent = (checked / total) * 100
                filled = min(20, max(0, int(percent // 5)))
                bar = "▰" * filled + "▱" * (20 - filled)
                remaining = max(total - checked, 0)
                eta_seconds = int(remaining / speed) if speed > 0 else 0
                eta_text = f"{eta_seconds // 60:02d}:{eta_seconds % 60:02d}" if speed > 0 else "estimating"

                header_part = (
                    "🌐 <b>KYAWZIN PROXY</b> · <code>SCANNING</code>\n"
                    f"🛰 Protocol: <b>{display_name}</b>\n"
                    f"📦 Checked: <code>{checked:,} / {total:,}</code>\n"
                    f"📊 Progress: <b>{percent:.2f}%</b>  ·  ⚡ <code>{speed:,}/s</code>\n"
                    f"✅ Verified (2/4 ×2): <b>{found}</b>  ·  ⏱ ETA: <code>{eta_text}</code>\n"
                    f"<code>{bar}</code>\n"
                    "━━━━━━━━━━━━━━━━━━━━\n"
                    f"📥 <b>VERIFIED · 2/4 ×2</b>\n"
                )
                temp_lines = []
                current_len = len(header_part)
                for _, item in sorted(formatted_items, key=lambda result: result[0])[:100]:
                    item_len = len(item) + 2
                    if current_len + item_len < 3900:
                        temp_lines.append(item)
                        current_len += item_len
                    else:
                        break
                recent_box_items = "\n".join(temp_lines) if temp_lines else "<i>Waiting…</i>"
                live_text = header_part + recent_box_items
                try:
                    await msg.edit_text(live_text, parse_mode=ParseMode.HTML, reply_markup=stop_keyboard)
                except Exception:
                    pass
                await asyncio.sleep(0.02)
                if found >= FAST_PROXY_TARGET:
                    fast_target_reached = True

        initial_result_count = len(found_proxy_records)
        if initial_result_count:
            try:
                await msg.edit_text(
                    f"🔄 Final recheck: 2/4 ×2 on {initial_result_count} candidates…",
                    parse_mode=ParseMode.HTML, reply_markup=stop_keyboard)
            except Exception:
                pass

            final_semaphore = asyncio.Semaphore(CONCURRENCY)
            done_final = {'n': 0}
            lock_final = asyncio.Lock()

            async def final_recheck(record):
                ping0, proxy, _ = record
                async with final_semaphore:
                    try:
                        is_ok, ping_ms, details = await asyncio.wait_for(
                            verify_proxy_double_check(
                                proxy, proxy_type,
                                min_passed=2, require_google=False,
                                timeout_total=6.0,
                                gap_seconds=0.1,
                            ),
                            timeout=10.0,
                        )
                    except Exception:
                        is_ok, ping_ms, details = False, 0, {}
                    async with lock_final:
                        done_final['n'] += 1
                        if done_final['n'] % 10 == 0 or done_final['n'] == initial_result_count:
                            try:
                                await msg.edit_text(
                                    f"🔄 Final 2/4 ×2 recheck: {done_final['n']}/{initial_result_count}",
                                    parse_mode=ParseMode.HTML, reply_markup=stop_keyboard)
                            except Exception:
                                pass
                    if not is_ok or ping_ms <= 0 or ping_ms > FAST_PROXY_MAX_LATENCY_MS:
                        return None
                    return (ping_ms, proxy, details)

            final_results = await asyncio.gather(
                *(final_recheck(record) for record in found_proxy_records),
                return_exceptions=True,
            )
            valid_records = []
            for r in final_results:
                if isinstance(r, tuple):
                    valid_records.append(r)
            valid_records.sort(key=lambda x: (x[0], x[1]))
            retries += initial_result_count - len(valid_records)
            found_proxy_records = valid_records
            found = len(found_proxy_records)
            formatted_items = []
            for ping, proxy, details in valid_records:
                cc = details.get("country_code", "?")
                flag = country_code_to_flag(cc)
                passed = details.get("passed", "?/4")
                formatted_items.append((ping,
                    f"• <code>{html.escape(proxy)}</code>  ·  <code>{ping} ms</code>  ·  {flag}  ·  {passed}"))

        scanning_jobs[chat_id] = False
        fast_count = sum(1 for ping, _, _ in found_proxy_records if ping <= FAST_PROXY_MAX_LATENCY_MS)
        status_title = ("🛑 SCAN STOPPED" if is_stopped
                        else "⚡ FAST RESULTS READY" if fast_target_reached
                        else "✅ SCAN COMPLETE")
        ordered_formatted = [it for _, it in sorted(formatted_items, key=lambda x: x[0])]
        ordered_results = sorted(found_proxy_records, key=lambda x: x[0])
        final_blocks = min(20, max(0, int(percent // 5)))
        final_bar = "▰" * final_blocks + "▱" * (20 - final_blocks)

        final_status_text = (
            f"🌐 <b>KYAWZIN PROXY · {status_title}</b>\n"
            f"📦 Checked: <code>{checked:,} / {total:,}</code>\n"
            f"✅ Qualified (2/4 ×2): <b>{found}</b>  ·  ❌ Excluded: <b>{retries}</b>\n"
            f"⚡ Verified at ≤{FAST_PROXY_MAX_LATENCY_MS} ms: <b>{fast_count}</b>\n"
            f"📊 Progress: <b>{percent:.2f}%</b>\n"
            f"<code>{final_bar}</code>"
        )
        try:
            await msg.edit_text(final_status_text, parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ ပင်မမီနူး", callback_data="back_home")]]))
        except Exception:
            pass

        if ordered_formatted:
            chunks = []
            cur = f"🌐 <b>KYAWZIN PROXY · VERIFIED 2/4 ×2</b>\n📥 ≤{FAST_PROXY_MAX_LATENCY_MS} ms\n\n"
            for item in ordered_formatted[:100]:
                add = item + "\n\n"
                if len(cur) + len(add) > 3900:
                    chunks.append(cur)
                    cur = f"🌐 <b>KYAWZIN PROXY · VERIFIED (cont.)</b>\n\n" + add
                else:
                    cur += add
            chunks.append(cur)
            for ch in chunks:
                try:
                    await context.bot.send_message(chat_id, ch, parse_mode=ParseMode.HTML)
                except Exception:
                    await context.bot.send_message(chat_id, ch)

        if ordered_results:
            content = "\n\n".join(p for _, p, _ in ordered_results)
            fb = io.BytesIO(content.encode("utf-8"))
            fb.name = f"proxy_{proxy_type}_{'partial' if is_stopped else 'live'}_2x4check.txt"
            try:
                await context.bot.send_document(chat_id, document=fb,
                    caption=(f"📁 <code>{fb.name}</code>\n"
                             f"✅ <b>{len(ordered_results)}</b> proxies · 2/4 ×2 verified"),
                    parse_mode=ParseMode.HTML)
            except Exception:
                logger.exception("File send failed")

    except Exception as e:
        logger.exception("Proxy scan failed for chat %s", chat_id)
        err_text = f"{type(e).__name__}: {str(e)[:300]}"
        try:
            await query.edit_message_text(
                "❌ <b>Scan failed</b>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                f"<code>{html.escape(err_text)}</code>",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("⬅️ ပင်မမီနူး", callback_data="back_home")]]))
        except Exception:
            pass
    finally:
        scanning_jobs[chat_id] = False


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data

    logger.info(f"[BUTTON] data={data!r}")

    try:
        track_bot_user(update.effective_user)
    except Exception:
        pass

    try:
        if data == "stop_scan":
            await query.answer("ရပ်ပြီး ရလဒ်တွေ ဖိုင်လုပ်နေတယ်…")
        else:
            await query.answer()
    except Exception:
        pass

    chat_id = query.message.chat_id if query.message else 0
    user_contexts[chat_id] = context

    if data == "admin_back":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True)
            return
        try:
            bot_users = load_bot_users()
            expire_stale_keys()
            online_count = 0
            for uid_str in bot_users.keys():
                try:
                    uid = int(uid_str)
                    if is_user_online(uid):
                        online_count += 1
                except Exception:
                    continue

            panel_text = (
                "⚙️ <b>KYAWZIN · ADMIN PANEL</b>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                f"🔑 Active Keys : <code>{len(ACTIVE_KEYS)}</code>\n"
                f"👥 Users       : <code>{len(USER_KEYS)}</code>\n"
                f"📇 Bot Users   : <code>{len(bot_users)}</code>\n"
                f"🟢 Online      : <code>{online_count}</code>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                f"🕐 {now_mm_str()}"
            )
            await query.edit_message_text(
                panel_text,
                parse_mode=ParseMode.HTML,
                reply_markup=admin_markup())
        except Exception as e:
            logger.exception(f"admin_back error: {e}")
        return

    if data == "admin_generate_key":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        await query.edit_message_text("🎲 <b>CREATE ACCESS KEY</b>\n⏳ Choose duration:",
            parse_mode=ParseMode.HTML, reply_markup=key_duration_markup())
        return

    if data.startswith("admin_duration_"):
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        duration_code = data.removeprefix("admin_duration_")
        duration_seconds = KEY_DURATIONS.get(duration_code)
        if duration_seconds is None:
            await query.answer("Unknown duration", show_alert=True); return

        context.user_data["pending_duration"] = duration_code
        context.user_data["awaiting_gen_user_id"] = True

        duration_label = {
            "1h": "1 hour", "2h": "2 hours", "6h": "6 hours",
            "1d": "1 day", "3d": "3 days", "5d": "5 days",
            "7d": "7 days", "10d": "10 days", "15d": "15 days",
            "20d": "20 days", "30d": "30 days",
        }[duration_code]

        await query.edit_message_text(
            f"🎫 <b>CREATE KEY — {duration_label}</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "📌 Key ကို သုံးမယ့် <b>User ID</b> ကို ရိုက်ထည့်ပါ။\n\n"
            "⚠️ ဒီ Key ကို အဲ့ User ID ပဲ သုံးလို့ ရပါမယ်။\n\n"
            "📌 ဥပမာ: <code>6779617599</code>\n\n"
            "💡 User ရဲ့ ID ကို မသိရင် — User ကို @userinfobot မှာ စစ်ခိုင်းပါ။",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌  CANCEL", callback_data="admin_back")]]))
        return

    if data == "admin_list_keys":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        expire_stale_keys()
        if not ACTIVE_KEYS:
            body = "🗝 <b>ACTIVE KEYS</b>\n\n<code>No active keys.</code>"
        else:
            lines = []
            for key, info in ACTIVE_KEYS.items():
                status = "✅ USED" if info.get("used_by") else "🆓 AVAILABLE"
                reserved = info.get("reserved_for") or info.get("user_id") or "Any"
                remaining = format_remaining_mm(info.get("expires_at", 0))
                lines.append(f"🔑 <code>{key}</code> · {status}\n"
                             f"   👤 For: <code>{reserved}</code>\n"
                             f"   ⏳ Remaining: <b>{remaining}</b>")
            body = f"🗝 <b>ACTIVE KEYS ({len(ACTIVE_KEYS)})</b>\n\n" + "\n\n".join(lines)
        if len(body) > 4000:
            body = body[:4000] + "\n<i>...</i>"
        await query.edit_message_text(body, parse_mode=ParseMode.HTML, reply_markup=admin_markup())
        return

    if data == "admin_clear_all_keys":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        total = len(ACTIVE_KEYS)
        await query.edit_message_text(
            "🧹 <b>CLEAR ALL KEYS</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🔑 Active Keys: <b>{total}</b>\n"
            f"👥 Users: <b>{len(USER_KEYS)}</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "⚠️ <b>ဒီ Key အားလုံးကို ဖျက်မှာ သေချာပါသလား?</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=clear_all_confirm_markup())
        return

    if data == "admin_clear_all_confirm":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        cleared_keys = len(ACTIVE_KEYS)
        cleared_users = len(USER_KEYS)
        ACTIVE_KEYS.clear()
        USER_KEYS.clear()
        save_key_store()
        await query.edit_message_text(
            "✅ <b>ALL KEYS CLEARED</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🗑️ Removed Keys: <b>{cleared_keys}</b>\n"
            f"👥 Revoked Users: <b>{cleared_users}</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "🕐 " + now_mm_str(),
            parse_mode=ParseMode.HTML,
            reply_markup=admin_markup())
        return

    if data == "admin_list_users" or data == "admin_user_list_refresh":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        expire_stale_keys()
        if not USER_KEYS:
            body = "👥 <b>AUTHORIZED USERS</b>\n\n<i>No users yet.</i>"
            await query.edit_message_text(body, parse_mode=ParseMode.HTML, reply_markup=admin_markup())
            return

        bot_users = load_bot_users()
        lines = []
        for uid, key in list(USER_KEYS.items()):
            info = ACTIVE_KEYS.get(key)
            if not info: continue

            online = is_user_online(uid)
            status = "🟢 ONLINE" if online else "🔴 OFFLINE"

            remaining = format_remaining_mm(info.get("expires_at", 0))

            u_info = bot_users.get(str(uid), {})
            uname = u_info.get("username", "")
            fname = u_info.get("first_name", "") or "?"
            uname_str = f"@{uname}" if uname else fname

            lines.append(
                f"👤 <code>{uid}</code> · {uname_str}\n"
                f"   🔑 <code>{key}</code>\n"
                f"   {status}  ·  ⏳ {remaining}"
            )

        body = (
            f"👥 <b>AUTHORIZED USERS</b>  ·  <b>{len(USER_KEYS)}</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            + "\n\n".join(lines[:25])
        )
        if len(lines) > 25:
            body += f"\n\n<i>... နောက်ထပ် {len(lines) - 25} ခု</i>"

        if len(body) > 4000:
            body = body[:4000] + "\n<i>...</i>"

        rows = [
            [InlineKeyboardButton("🔄  REFRESH", callback_data="admin_user_list_refresh"),
             InlineKeyboardButton("↩️  BACK", callback_data="admin_back")]
        ]

        try:
            await query.edit_message_text(body, parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(rows))
        except Exception:
            pass
        return

    if data == "admin_bot_status" or data == "admin_bot_status_refresh":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        expire_stale_keys()

        bot_users = load_bot_users()
        total_users = len(bot_users)
        online_count = 0

        for uid_str in bot_users.keys():
            try:
                uid = int(uid_str)
                if is_user_online(uid):
                    online_count += 1
            except Exception:
                continue

        total_keys = len(ACTIVE_KEYS)
        used_keys = sum(1 for k, v in ACTIVE_KEYS.items() if v.get("used_by"))
        free_keys = total_keys - used_keys
        authorized_users = len(USER_KEYS)

        body = (
            "📊 <b>BOT STATUS</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🕐 {now_mm_str()}\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "👥 <b>USERS</b>\n"
            f"   📇 Total Bot Users : <b>{total_users}</b>\n"
            f"   🟢 Online (5m)      : <b>{online_count}</b>\n"
            f"   🔑 Authorized      : <b>{authorized_users}</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "🔑 <b>ACTIVE KEYS</b>\n"
            f"   📋 Total Keys      : <b>{total_keys}</b>\n"
            f"   ✅ Used            : <b>{used_keys}</b>\n"
            f"   🆓 Available       : <b>{free_keys}</b>\n"
            "━━━━━━━━━━━━━━━━━━"
        )

        try:
            await query.edit_message_text(body, parse_mode=ParseMode.HTML,
                reply_markup=bot_status_markup())
        except Exception:
            pass
        return

    if data.startswith("admin_view_"):
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        try:
            target_uid = int(data[len("admin_view_"):])
        except ValueError:
            return

        bot_users = load_bot_users()
        u_info = bot_users.get(str(target_uid), {})
        uname = u_info.get("username", "")
        fname = u_info.get("first_name", "") or "?"
        uname_str = f"@{uname}" if uname else fname

        key = USER_KEYS.get(target_uid, "N/A")
        online = is_user_online(target_uid)
        status = "🟢 ONLINE" if online else "🔴 OFFLINE"

        info = ACTIVE_KEYS.get(key)
        remaining = format_remaining_mm(info.get("expires_at", 0)) if info else "N/A"

        body = (
            f"👤 <b>USER INFO</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"👤 User: <code>{target_uid}</code> · {uname_str}\n"
            f"🔑 Key: <code>{key}</code>\n"
            f"📡 Status: <b>{status}</b>\n"
            f"⏳ Remaining: <b>{remaining}</b>\n"
            f"━━━━━━━━━━━━━━━━━━"
        )

        try:
            await query.edit_message_text(body, parse_mode=ParseMode.HTML,
                reply_markup=user_action_markup(target_uid))
        except Exception:
            pass
        return

    if data == "admin_delete_key":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        context.user_data["awaiting_delkey"] = True
        pending_delete.pop(chat_id, None)
        await query.edit_message_text(
            "🗑️ <b>DELETE ACCESS KEY</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "Key သို့မဟုတ် User ID ကို message အနေနဲ့ ရိုက်ထည့်ပါ။",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("↩️  ADMIN PANEL", callback_data="admin_back")]]))
        return

    if data == "admin_delkey_confirm":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        record = pending_delete.pop(chat_id, None)
        if not record:
            await query.edit_message_text("⚠️ <b>NO PENDING DELETE</b>",
                parse_mode=ParseMode.HTML, reply_markup=admin_markup()); return
        target_key = record["key"]
        info = ACTIVE_KEYS.pop(target_key, None)
        if info is None:
            await query.edit_message_text("⚠️ <b>KEY NOT FOUND</b>",
                parse_mode=ParseMode.HTML, reply_markup=admin_markup()); return
        linked_user = info.get("used_by") or info.get("user_id")
        if linked_user is not None:
            USER_KEYS.pop(int(linked_user), None)
        save_key_store()
        await query.edit_message_text(
            "✅ <b>KEY DELETED</b>\n"
            f"🗑️ Removed: <code>{target_key}</code>\n"
            f"👤 User ID: <code>{linked_user if linked_user else 'Not claimed'}</code>\n"
            f"📊 Remaining: <b>{len(ACTIVE_KEYS)}</b>",
            parse_mode=ParseMode.HTML, reply_markup=admin_markup())
        return

    if data == "admin_delkey_cancel":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        record = pending_delete.pop(chat_id, None)
        if record:
            await query.edit_message_text(
                f"❌ <b>DELETE CANCELLED</b>\n🔑 <code>{record['key']}</code>",
                parse_mode=ParseMode.HTML, reply_markup=admin_markup())
        else:
            await query.edit_message_text("❌ <b>NOTHING TO CANCEL</b>",
                parse_mode=ParseMode.HTML, reply_markup=admin_markup())
        return

    if data == "admin_broadcast":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        context.user_data["awaiting_broadcast"] = True
        bot_users = load_bot_users()
        total = len(bot_users)
        await query.edit_message_text(
            "📢 <b>BROADCAST MESSAGE</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"👥 Recipients: <b>{total}</b> users\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "User အားလုံးဆီ ပို့မယ့် Message ကို ရိုက်ထည့်ပါ။",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌  CANCEL", callback_data="admin_back")]]))
        return

    if data == "admin_broadcast_send":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        message_text = context.user_data.get("broadcast_preview")
        if not message_text:
            await query.edit_message_text(
                "⚠️ <b>NO MESSAGE</b>\n\nPreview မရှိတော့ပါ။ ပြန်စပါ။",
                parse_mode=ParseMode.HTML, reply_markup=admin_markup())
            return
        try:
            await query.edit_message_text(
                "📢 <b>Broadcasting started...</b>\n\n⏳ ခဏစောင့်ပါ။",
                parse_mode=ParseMode.HTML)
        except Exception:
            pass
        await broadcast_message_from_query(query, context, message_text)
        return

    if data == "admin_broadcast_cancel":
        if not is_admin(chat_id):
            await query.answer("Admin only", show_alert=True); return
        context.user_data["awaiting_broadcast"] = False
        context.user_data.pop("broadcast_preview", None)
        await query.edit_message_text(
            "❌ <b>BROADCAST CANCELLED</b>",
            parse_mode=ParseMode.HTML, reply_markup=admin_markup())
        return

    if data == "enter_key":
        context.user_data["awaiting_key"] = True
        await query.edit_message_text(
            "🔐 <b>ENTER ACCESS KEY</b>\n\n"
            "Admin ပေးထားတဲ့ Key ကို ပို့ပါ။\n"
            "Format: <code>XXXX-XXXX-XXXX-XXXX</code>",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅️ BACK", callback_data="back_home")]]))
        return

    if not is_authorized(chat_id):
        await query.edit_message_text(
            "🔐 <b>ACCESS REQUIRED</b>\n\nValid Access Key မရှိသေးပါ။",
            parse_mode=ParseMode.HTML, reply_markup=access_denied_markup())
        return

    if data == "select_manual_url":
        active_task = scan_tasks.get(chat_id)
        if active_task is not None and not active_task.done():
            await query.answer("Scan တစ်ခု ပြေးနေပြီးသားပါ။", show_alert=True); return
        context.user_data["awaiting_manual_url"] = True
        await query.edit_message_text(
            "🔗 <b>MANUAL URL SCAN</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "Proxy API URL တစ်ခု ပို့ပါ။\n\n"
            "📌 ဥပမာ:\n"
            "<code>https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt</code>\n\n"
            "📋 Format လက်ခံမှု:\n"
            "• <code>socks5://1.2.3.4:1080</code>\n"
            "• <code>1.2.3.4:1080</code> (URL ထဲက keyword အလိုက် auto)\n\n"
            "🔍 2/4 ×2 double-check\n"
            "🚩 နိုင်ငံအလံ ပြပါမယ်။\n"
            "⚠️ SOCKS proxy အတွက် <code>aiohttp-socks</code> လိုတယ်။",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅️ ပင်မမီနူး", callback_data="back_home")]]))
        return

    if data.startswith("select_"):
        proxy_type = data.split("_")[1]
        user_selected_type[chat_id] = proxy_type
        display_name = "ALL PROTOCOLS" if proxy_type == "all" else proxy_type.upper()
        keyboard = [
            [InlineKeyboardButton("🚀  START SCAN", callback_data="start_scan")],
            [InlineKeyboardButton("🏠  MAIN MENU", callback_data="back_home")]
        ]
        try:
            await query.edit_message_text(
                "🌐 <b>KYAWZIN PROXY</b>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                f"📡 Selected: <b>{display_name}</b>\n\n"
                "Verification: <b>2/4 × 2 checks</b>\n"
                "🚩 Country flags will be shown\n"
                f"⚡ Only ≤{FAST_PROXY_MAX_LATENCY_MS}ms proxies are kept\n\n"
                "Press <b>START SCAN</b> when ready.",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(keyboard))
        except Exception:
            pass

    elif data == "start_scan":
        active_task = scan_tasks.get(chat_id)
        if active_task is not None and not active_task.done():
            await query.answer("Scan running", show_alert=True); return
        proxy_type = user_selected_type.get(chat_id, "all")
        scanning_jobs[chat_id] = True

        async def run_guarded():
            try:
                await run_proxy_scan(query, context, chat_id, proxy_type)
            finally:
                scanning_jobs[chat_id] = False
                scan_tasks.pop(chat_id, None)

        task = asyncio.create_task(run_guarded())
        scan_tasks[chat_id] = task

    elif data == "stop_scan":
        scanning_jobs[chat_id] = False
        active_task = scan_tasks.get(chat_id)
        if active_task is None or active_task.done():
            try:
                await query.edit_message_text("ℹ️ Scan မရှိပါ။")
            except Exception:
                pass
            return
        try:
            await query.edit_message_text(
                "🛑 <b>STOPPING SCAN</b>\n"
                "Final recheck ကို ဆက်လုပ်နေတယ် — ခဏစောင့်ပါ။",
                parse_mode=ParseMode.HTML)
        except Exception:
            pass

    elif data == "back_home":
        scanning_jobs[chat_id] = False
        keyboard_rows = [list(row) for row in main_menu_markup().inline_keyboard]
        if is_admin(chat_id):
            keyboard_rows.append([InlineKeyboardButton("⚙️  ADMIN PANEL", callback_data="admin_back")])
        try:
            await query.edit_message_text(
                "🌐 <b>KYAWZIN PROXY</b>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                "📡 Choose a protocol or paste a Manual URL.",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(keyboard_rows))
        except Exception:
            pass

    elif data == "help":
        keyboard = [[InlineKeyboardButton("🏠  MAIN MENU", callback_data="back_home")]]
        try:
            await query.edit_message_text(
                "📖 <b>KYAWZIN · QUICK GUIDE</b>\n"
                "━━━━━━━━━━━━━━━━━━\n"
                "1. Protocol ရွေး <b>သို့မဟုတ်</b> Manual URL ပေး။\n"
                "2. Bot က Live မှာ 2/4 ×2 စစ်မယ်။\n"
                "3. Final မှာ 2/4 ×2 ထပ်စစ်မယ်။\n"
                f"4. ≤{FAST_PROXY_MAX_LATENCY_MS}ms ပဲ ယူမယ်။\n"
                "5. 🚩 နိုင်ငံအလံ ပြမယ်။\n"
                "6. STOP နှိပ်လည်း Final ဆက်လုပ်မယ်။",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(keyboard))
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
# ★ Unified Text Handler
# ═══════════════════════════════════════════════════════════
async def unified_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_data = context.user_data

    if user_data.get("awaiting_key"):
        await key_message_handler(update, context)
        return
    if user_data.get("awaiting_gen_user_id"):
        await genkey_text_handler(update, context)
        return
    if user_data.get("awaiting_delkey"):
        await admin_delkey_text_handler(update, context)
        return
    if user_data.get("awaiting_broadcast"):
        await broadcast_text_handler(update, context)
        return
    if user_data.get("awaiting_manual_url"):
        await manual_url_text_handler(update, context)
        return
    return


# ═══════════════════════════════════════════════════════════
# ★ Main
# ═══════════════════════════════════════════════════════════
def main():
    from telegram.request import HTTPXRequest

    bot_request = HTTPXRequest(
        connection_pool_size=20,
        read_timeout=20.0, write_timeout=20.0,
        connect_timeout=15.0, pool_timeout=15.0,
    )
    updates_request = HTTPXRequest(
        connection_pool_size=1,
        read_timeout=35.0, write_timeout=20.0,
        connect_timeout=15.0, pool_timeout=15.0,
    )
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .request(bot_request)
        .get_updates_request(updates_request)
        .build()
    )
    
    # install_polling_heartbeat(app) - ဒီနေရာမှာ Error တက်နေတဲ့အတွက် ဖျက်ထားပါတယ်။
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, unified_text_handler))

    print("🌐 KYAWZIN PROXY စတင်အလုပ်လုပ်နေပါပြီ...")
    print(f"🔧 aiohttp_socks: {'OK' if AIOHTTP_SOCKS_AVAILABLE else 'MISSING'}")
    app.run_polling(
        timeout=15,
        drop_pending_updates=True,
        bootstrap_retries=-1,
    )


if __name__ == "__main__":
    main()