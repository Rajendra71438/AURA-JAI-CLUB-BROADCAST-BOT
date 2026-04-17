"""
bot.py — Telegram Bot with full panel UI and extended admin controls.
- Auto‑approve toggle for join requests.
- Hierarchical roles: Superadmin → Admin → Subadmin.
- Background broadcast with zero delay, silent confirmation.
"""

import asyncio
import logging
import sqlite3
from contextlib import contextmanager
from datetime import date
from functools import partial

from dotenv import load_dotenv
import os

from telegram import (
    Update,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
)
from telegram.error import TelegramError, Forbidden
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ChatJoinRequestHandler,
    filters,
    ContextTypes,
)

# ══════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════

load_dotenv()

BOT_TOKEN:       str = os.getenv("BOT_TOKEN", "")
SOURCE_CHAT_ID:  int = int(os.getenv("SOURCE_CHAT_ID", "0"))
ADMIN_ID:        int = int(os.getenv("ADMIN_ID", "0"))

BROADCAST_DELAY: float = 0.0   # No delay between messages
MAX_RETRIES:     int   = 2
DB_PATH:         str   = "bot.db"

if not BOT_TOKEN:      raise ValueError("BOT_TOKEN not set in .env")
if not ADMIN_ID:       raise ValueError("ADMIN_ID not set in .env")

# ══════════════════════════════════════════════
# MINIMAL LOGGING CONFIGURATION
# ══════════════════════════════════════════════

logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    level=logging.WARNING,   # Only warnings and errors by default
)

# Silence noisy libraries completely
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("telegram").setLevel(logging.WARNING)
logging.getLogger("telegram.ext").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)

# Keep INFO for our own logger so we see "Bot started"
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ══════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as c:
        # Existing tables
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id    INTEGER PRIMARY KEY,
                first_seen DATE NOT NULL DEFAULT (DATE('now'))
            );
            CREATE TABLE IF NOT EXISTS subadmins (
                user_id  INTEGER PRIMARY KEY,
                added_at TIMESTAMP DEFAULT (DATETIME('now'))
            );
            CREATE TABLE IF NOT EXISTS messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                position   INTEGER NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS state (
                user_id INTEGER PRIMARY KEY,
                action  TEXT NOT NULL,
                data    TEXT
            );
        """)
        # New tables
        c.executescript("""
            CREATE TABLE IF NOT EXISTS pending_requests (
                user_id    INTEGER,
                chat_id    INTEGER,
                created_at TIMESTAMP DEFAULT (DATETIME('now')),
                PRIMARY KEY (user_id, chat_id)
            );
            CREATE TABLE IF NOT EXISTS subadmin_perms (
                user_id INTEGER PRIMARY KEY,
                can_broadcast INTEGER DEFAULT 1,
                can_stats INTEGER DEFAULT 1,
                can_manage_seq INTEGER DEFAULT 0,
                can_manage_subadmins INTEGER DEFAULT 0,
                can_change_source INTEGER DEFAULT 0,
                can_set_post_button INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES subadmins(user_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS post_sequence (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                message_text TEXT,
                button_text TEXT,
                button_url TEXT
            );
        """)
        # Add role column to subadmins if not exists
        try:
            c.execute("ALTER TABLE subadmins ADD COLUMN role TEXT DEFAULT 'subadmin'")
        except sqlite3.OperationalError:
            pass  # column already exists

        # Default configs
        c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('source_chat_id', ?)",
                  (str(SOURCE_CHAT_ID),))
        c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('auto_approve', '0')")
        c.execute("INSERT OR IGNORE INTO post_sequence (id) VALUES (1)")
    logger.info("Database ready.")


# ── Users ──────────────────────────────────────

def db_upsert_user(user_id: int) -> bool:
    with get_conn() as c:
        return c.execute(
            "INSERT OR IGNORE INTO users (user_id) VALUES (?)", (user_id,)
        ).rowcount > 0

def db_total_users() -> int:
    with get_conn() as c:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

def db_daily_users() -> int:
    with get_conn() as c:
        return c.execute(
            "SELECT COUNT(*) FROM users WHERE first_seen = ?",
            (date.today().isoformat(),)
        ).fetchone()[0]

def db_all_user_ids() -> list:
    with get_conn() as c:
        return [r["user_id"] for r in c.execute("SELECT user_id FROM users").fetchall()]


# ── Roles & Admins ─────────────────────────────

def is_main_admin(user_id: int) -> bool:
    return user_id == ADMIN_ID

def db_get_admin_role(user_id: int) -> str | None:
    with get_conn() as c:
        row = c.execute(
            "SELECT role FROM subadmins WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row["role"] if row else None

def db_is_subadmin(user_id: int) -> bool:
    return db_get_admin_role(user_id) is not None

def db_is_admin(user_id: int) -> bool:
    """True for superadmin or admin role."""
    return is_main_admin(user_id) or db_get_admin_role(user_id) == "admin"

def is_any_admin(user_id: int) -> bool:
    return is_main_admin(user_id) or db_is_subadmin(user_id)

def db_add_admin(user_id: int, role: str = "subadmin") -> bool:
    with get_conn() as c:
        try:
            c.execute(
                "INSERT INTO subadmins (user_id, role) VALUES (?, ?)",
                (user_id, role)
            )
            c.execute("INSERT INTO subadmin_perms (user_id) VALUES (?)", (user_id,))
            return True
        except sqlite3.IntegrityError:
            return False

def db_remove_subadmin(user_id: int) -> bool:
    with get_conn() as c:
        return c.execute(
            "DELETE FROM subadmins WHERE user_id = ?", (user_id,)
        ).rowcount > 0

def db_list_admins(role_filter: str = None) -> list:
    """Return list of subadmin rows. If role_filter given, only that role."""
    with get_conn() as c:
        if role_filter:
            return c.execute(
                "SELECT user_id, role FROM subadmins WHERE role = ?", (role_filter,)
            ).fetchall()
        return c.execute("SELECT user_id, role FROM subadmins").fetchall()

def db_get_all_admin_ids() -> list:
    """Return list of all admin IDs (main + all subadmins)."""
    ids = [ADMIN_ID]
    ids.extend(r["user_id"] for r in db_list_admins())
    return ids


# ── Subadmin Permissions ───────────────────────

PERMISSIONS = [
    "can_broadcast",
    "can_stats",
    "can_manage_seq",
    "can_change_source",
    "can_set_post_button",
    "can_manage_subadmins",
]

PERM_DISPLAY = {
    "can_broadcast": "📢 Broadcast",
    "can_stats": "📊 Stats",
    "can_manage_seq": "📨 Manage Sequence",
    "can_change_source": "📡 Change Source",
    "can_set_post_button": "🔘 Set Post Button",
    "can_manage_subadmins": "👥 Manage Subadmins",
}

def db_get_subadmin_perms(user_id: int) -> dict:
    with get_conn() as c:
        row = c.execute(
            "SELECT * FROM subadmin_perms WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row:
            return {}
        return {k: bool(row[k]) for k in row.keys() if k != "user_id"}

def db_set_subadmin_perm(user_id: int, perm: str, value: bool) -> None:
    with get_conn() as c:
        c.execute(
            f"UPDATE subadmin_perms SET {perm} = ? WHERE user_id = ?",
            (int(value), user_id)
        )

def db_has_perm(user_id: int, perm: str) -> bool:
    if is_main_admin(user_id):
        return True
    perms = db_get_subadmin_perms(user_id)
    return perms.get(perm, False)


# ── Auto‑approve config ────────────────────────

def db_get_auto_approve() -> bool:
    with get_conn() as c:
        row = c.execute("SELECT value FROM config WHERE key = 'auto_approve'").fetchone()
        return row and row["value"] == "1"

def db_set_auto_approve(value: bool) -> None:
    with get_conn() as c:
        c.execute(
            "UPDATE config SET value = ? WHERE key = 'auto_approve'",
            ("1" if value else "0",)
        )


# ── Pending Join Requests ──────────────────────

def db_add_pending_request(user_id: int, chat_id: int) -> None:
    with get_conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO pending_requests (user_id, chat_id) VALUES (?,?)",
            (user_id, chat_id)
        )

def db_get_pending_requests() -> list:
    with get_conn() as c:
        return c.execute(
            "SELECT user_id, chat_id FROM pending_requests"
        ).fetchall()

def db_clear_pending_requests() -> None:
    with get_conn() as c:
        c.execute("DELETE FROM pending_requests")


# ── Message sequence ───────────────────────────

def db_add_message(message_id: int, position: int) -> bool:
    with get_conn() as c:
        try:
            c.execute(
                "INSERT OR REPLACE INTO messages (message_id, position) VALUES (?,?)",
                (message_id, position),
            )
            return True
        except sqlite3.IntegrityError:
            return False

def db_remove_message(message_id: int) -> bool:
    with get_conn() as c:
        return c.execute(
            "DELETE FROM messages WHERE message_id = ?", (message_id,)
        ).rowcount > 0

def db_remove_message_pos(position: int) -> bool:
    with get_conn() as c:
        return c.execute(
            "DELETE FROM messages WHERE position = ?", (position,)
        ).rowcount > 0

def db_get_messages() -> list:
    with get_conn() as c:
        return c.execute("SELECT * FROM messages ORDER BY position ASC").fetchall()

def db_reorder_message(message_id: int, new_position: int) -> bool:
    with get_conn() as c:
        c.execute(
            "UPDATE messages SET position = -1 WHERE position = ? AND message_id != ?",
            (new_position, message_id),
        )
        ok = c.execute(
            "UPDATE messages SET position = ? WHERE message_id = ?",
            (new_position, message_id),
        ).rowcount > 0
        c.execute("DELETE FROM messages WHERE position = -1")
        return ok


# ── Config ─────────────────────────────────────

def db_get_source_chat_id() -> int:
    with get_conn() as c:
        row = c.execute("SELECT value FROM config WHERE key = 'source_chat_id'").fetchone()
        return int(row["value"]) if row else SOURCE_CHAT_ID

def db_set_source_chat_id(chat_id: int) -> None:
    with get_conn() as c:
        c.execute(
            "UPDATE config SET value = ? WHERE key = 'source_chat_id'",
            (str(chat_id),)
        )


# ── Post‑sequence custom message ───────────────

def db_get_post_sequence() -> dict:
    with get_conn() as c:
        row = c.execute("SELECT message_text, button_text, button_url FROM post_sequence WHERE id = 1").fetchone()
        return dict(row) if row else {}

def db_set_post_sequence(message_text: str, button_text: str, button_url: str) -> None:
    with get_conn() as c:
        c.execute(
            "UPDATE post_sequence SET message_text = ?, button_text = ?, button_url = ? WHERE id = 1",
            (message_text, button_text, button_url)
        )


# ── State machine ──────────────────────────────

def db_set_state(user_id: int, action: str, data: str = "") -> None:
    with get_conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO state (user_id, action, data) VALUES (?,?,?)",
            (user_id, action, data),
        )

def db_get_state(user_id: int) -> tuple:
    """Returns (action, data) or (None, None)."""
    with get_conn() as c:
        row = c.execute(
            "SELECT action, data FROM state WHERE user_id = ?", (user_id,)
        ).fetchone()
        return (row["action"], row["data"]) if row else (None, None)

def db_clear_state(user_id: int) -> None:
    with get_conn() as c:
        c.execute("DELETE FROM state WHERE user_id = ?", (user_id,))


# ══════════════════════════════════════════════
# ASYNC HELPER
# ══════════════════════════════════════════════

async def run(func, *args):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, partial(func, *args))


# ══════════════════════════════════════════════
# KEYBOARDS
# ══════════════════════════════════════════════

def admin_panel_kb() -> ReplyKeyboardMarkup:
    auto_status = "🔄 Auto‑Approve: " + ("ON ✅" if db_get_auto_approve() else "OFF ❌")
    return ReplyKeyboardMarkup(
        [
            ["📢 Broadcast",       "📊 Stats"],
            ["👑 Admins",          "👥 Subadmins"],
            ["📨 Message Sequence", "✅ Approve All Requests"],
            ["📡 Change Source Channel", auto_status],
            ["🔘 Set Post Button", "🗑 Remove Post Button"],
            ["⚙️ Subadmin Permissions"],
        ],
        resize_keyboard=True,
    )

def subadmin_panel_kb(user_id: int) -> ReplyKeyboardMarkup:
    """Dynamic panel based on subadmin permissions and role."""
    perms = db_get_subadmin_perms(user_id)
    role = db_get_admin_role(user_id)
    buttons = []
    if perms.get("can_broadcast", False):
        buttons.append(["📢 Broadcast"])
    if perms.get("can_stats", False):
        buttons.append(["📊 Stats"])
    if perms.get("can_manage_seq", False):
        buttons.append(["📨 Message Sequence"])
    if perms.get("can_change_source", False):
        buttons.append(["📡 Change Source Channel"])
    if perms.get("can_set_post_button", False):
        buttons.append(["🔘 Set Post Button", "🗑 Remove Post Button"])
    if role == "admin" and perms.get("can_manage_subadmins", False):
        buttons.append(["👥 Subadmins"])
    if not buttons:
        buttons = [["ℹ️ No permissions"]]
    return ReplyKeyboardMarkup(buttons, resize_keyboard=True)

def sequence_panel_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [
            ["➕ Add Message",    "➖ Remove Message"],
            ["🔀 Reorder Message", "📄 List Messages"],
            ["🔙 Back to Panel"],
        ],
        resize_keyboard=True,
    )

def cancel_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [["❌ Cancel"]],
        resize_keyboard=True,
    )

def staff_kb(user_id: int) -> ReplyKeyboardMarkup:
    return admin_panel_kb() if is_main_admin(user_id) else subadmin_panel_kb(user_id)


# ══════════════════════════════════════════════
# PANEL SENDER
# ══════════════════════════════════════════════

async def open_panel(update: Update, user_id: int, note: str = "") -> None:
    """Send the correct panel keyboard for this user."""
    await run(db_clear_state, user_id)

    if is_main_admin(user_id):
        text = f"{note}\n\n👑 *SUPER ADMIN* — CHOOSE AN ACTION:" if note else "👑 *SUPER ADMIN* — CHOOSE AN ACTION:"
        kb   = admin_panel_kb()
    elif await run(db_is_subadmin, user_id):
        role = await run(db_get_admin_role, user_id)
        title = "ADMIN" if role == "admin" else "SUBADMIN"
        text = f"{note}\n\n🛠 *{title} PANEL* — CHOOSE AN ACTION:" if note else f"🛠 *{title} PANEL* — CHOOSE AN ACTION:"
        kb   = subadmin_panel_kb(user_id)
    else:
        return

    await update.message.reply_text(text.strip(), parse_mode="Markdown", reply_markup=kb)


# ══════════════════════════════════════════════
# /start
# ══════════════════════════════════════════════

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user:
        return

    await run(db_upsert_user, user.id)
    await run(db_clear_state, user.id)

    if is_any_admin(user.id):
        await open_panel(update, user.id)
        return

    # Send sequence to regular user
    source_id = await run(db_get_source_chat_id)
    for row in await run(db_get_messages):
        try:
            await context.bot.copy_message(
                chat_id=user.id,
                from_chat_id=source_id,
                message_id=row["message_id"],
            )
        except Forbidden:
            logger.warning("User %s blocked the bot during /start sequence.", user.id)
            break
        except TelegramError as e:
            logger.error("Sequence error msg %s → user %s: %s", row["message_id"], user.id, e)
        await asyncio.sleep(BROADCAST_DELAY)

    post = await run(db_get_post_sequence)
    if post.get("message_text"):
        kb = None
        if post.get("button_text") and post.get("button_url"):
            kb = InlineKeyboardMarkup([[InlineKeyboardButton(post["button_text"], url=post["button_url"])]])
        try:
            await context.bot.send_message(
                chat_id=user.id,
                text=post["message_text"],
                reply_markup=kb,
                parse_mode="Markdown"
            )
        except Exception as e:
            logger.error("Failed to send post‑sequence message to %s: %s", user.id, e)


# ══════════════════════════════════════════════
# JOIN REQUEST
# ══════════════════════════════════════════════

async def on_join_request(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    jr = update.chat_join_request
    if not jr:
        return
    user = jr.from_user
    if not user:
        return

    await run(db_upsert_user, user.id)

    source_id = await run(db_get_source_chat_id)
    for row in await run(db_get_messages):
        try:
            await context.bot.copy_message(
                chat_id=user.id,
                from_chat_id=source_id,
                message_id=row["message_id"],
            )
        except Forbidden:
            logger.warning("User %s blocked the bot — stopping sequence.", user.id)
            break
        except TelegramError as e:
            logger.error("Sequence error msg %s → user %s: %s", row["message_id"], user.id, e)
        await asyncio.sleep(BROADCAST_DELAY)

    post = await run(db_get_post_sequence)
    if post.get("message_text"):
        kb = None
        if post.get("button_text") and post.get("button_url"):
            kb = InlineKeyboardMarkup([[InlineKeyboardButton(post["button_text"], url=post["button_url"])]])
        try:
            await context.bot.send_message(
                chat_id=user.id,
                text=post["message_text"],
                reply_markup=kb,
                parse_mode="Markdown"
            )
        except Exception as e:
            logger.error("Failed to send post‑sequence message to %s: %s", user.id, e)

    # Auto‑approve if enabled
    if await run(db_get_auto_approve):
        try:
            await context.bot.approve_chat_join_request(chat_id=jr.chat.id, user_id=user.id)
            logger.info("Auto‑approved join request for %s", user.id)
        except Exception as e:
            logger.error("Auto‑approve failed for %s: %s", user.id, e)
    else:
        await run(db_add_pending_request, user.id, jr.chat.id)
        logger.info("Join request from %s stored for manual approval.", user.id)


# ══════════════════════════════════════════════
# STATS
# ══════════════════════════════════════════════

async def _send_stats(update: Update, is_cb: bool = False) -> None:
    user = update.effective_user
    if not user:
        return
    if not is_any_admin(user.id):
        txt = "⛔ Admins only."
        if is_cb:
            await update.callback_query.answer(txt, show_alert=True)
        else:
            await update.message.reply_text(txt)
        return
    total = await run(db_total_users)
    daily = await run(db_daily_users)
    pending = len(await run(db_get_pending_requests))
    auto = "ON ✅" if await run(db_get_auto_approve) else "OFF ❌"
    text  = (
        "📊 *Bot Statistics*\n\n"
        f"👥 Total users:      `{total}`\n"
        f"🗓 Today's new users: `{daily}`\n"
        f"⏳ Pending approvals: `{pending}`\n"
        f"🔄 Auto‑approve:      `{auto}`"
    )
    if is_cb:
        await update.callback_query.answer()
        await update.callback_query.message.reply_text(text, parse_mode="Markdown")
    else:
        await update.message.reply_text(text, parse_mode="Markdown")

async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _send_stats(update, is_cb=False)

async def cb_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _send_stats(update, is_cb=True)


# ══════════════════════════════════════════════
# BACKGROUND BROADCAST TASK (silent, zero delay)
# ══════════════════════════════════════════════

async def background_broadcast(
    source_msg,           # original message to copy (if no text)
    bot,                  # bot instance
    text: str = None      # optional text instead of copying
) -> None:
    """Run broadcast silently in background. No report is sent."""
    for uid in await run(db_all_user_ids):
        for attempt in range(MAX_RETRIES + 1):
            try:
                if text:
                    await bot.send_message(chat_id=uid, text=text)
                else:
                    await source_msg.copy(chat_id=uid)
                break
            except Forbidden:
                break
            except TelegramError as e:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(1)
                else:
                    logger.warning("Broadcast failed for %s: %s", uid, e)
            except Exception as e:
                logger.exception("Unexpected error for %s: %s", uid, e)
                break
        # No delay (BROADCAST_DELAY = 0)


# ══════════════════════════════════════════════
# FORWARD NON‑ADMIN MESSAGES TO ADMINS
# ══════════════════════════════════════════════

async def forward_to_admins(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Forward any non‑admin message to all admins."""
    msg = update.message
    user = update.effective_user
    if not user or not msg:
        return

    admin_ids = await run(db_get_all_admin_ids)
    for admin_id in admin_ids:
        try:
            await msg.forward(chat_id=admin_id)
        except Exception as e:
            logger.error("Failed to forward to admin %s: %s", admin_id, e)


# ══════════════════════════════════════════════
# CALLBACK HANDLERS (for inline keyboards)
# ══════════════════════════════════════════════

async def subadmin_list_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show list of subadmins to manage permissions."""
    query = update.callback_query
    await query.answer()
    user = update.effective_user
    if not is_main_admin(user.id):
        await query.edit_message_text("⛔ Only main admin can manage permissions.")
        return

    subs = await run(db_list_admins)  # all subadmins regardless of role
    if not subs:
        await query.edit_message_text("ℹ️ No subadmins configured.")
        return

    keyboard = []
    for sub in subs:
        sid = sub["user_id"]
        role = sub["role"]
        label = f"👤 {sid} ({role.upper()})"
        keyboard.append([InlineKeyboardButton(label, callback_data=f"perm_sub_{sid}")])
    keyboard.append([InlineKeyboardButton("🔙 Close", callback_data="perm_close")])

    await query.edit_message_text(
        "⚙️ *Select a subadmin to manage permissions:*",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def subadmin_perm_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show permission toggles for a specific subadmin."""
    query = update.callback_query
    await query.answer()
    user = update.effective_user
    if not is_main_admin(user.id):
        await query.edit_message_text("⛔ Only main admin can manage permissions.")
        return

    data = query.data
    if not data.startswith("perm_sub_"):
        return
    sub_id = int(data.split("_")[2])

    perms = await run(db_get_subadmin_perms, sub_id)
    if not perms:
        await query.edit_message_text(f"ℹ️ Subadmin `{sub_id}` not found or has no permissions.")
        return

    role = await run(db_get_admin_role, sub_id)
    keyboard = []
    for perm in PERMISSIONS:
        display = PERM_DISPLAY.get(perm, perm)
        status = "✅" if perms.get(perm, False) else "❌"
        keyboard.append([
            InlineKeyboardButton(
                f"{status} {display}",
                callback_data=f"perm_toggle_{sub_id}_{perm}"
            )
        ])
    keyboard.append([InlineKeyboardButton("🔙 Back to list", callback_data="perm_list")])
    keyboard.append([InlineKeyboardButton("🔙 Close", callback_data="perm_close")])

    await query.edit_message_text(
        f"⚙️ *Permissions for {role.upper()}* `{sub_id}`\n"
        "Tap a button to toggle ON/OFF.",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def perm_toggle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Toggle a specific permission and refresh the menu."""
    query = update.callback_query
    await query.answer()
    user = update.effective_user
    if not is_main_admin(user.id):
        await query.edit_message_text("⛔ Only main admin can manage permissions.")
        return

    data = query.data
    if not data.startswith("perm_toggle_"):
        return
    parts = data.split("_")
    sub_id = int(parts[2])
    perm = "_".join(parts[3:])

    perms = await run(db_get_subadmin_perms, sub_id)
    if perm not in perms:
        await query.answer("Invalid permission.", show_alert=True)
        return

    new_val = not perms[perm]
    await run(db_set_subadmin_perm, sub_id, perm, new_val)

    # Refresh the menu
    perms = await run(db_get_subadmin_perms, sub_id)
    role = await run(db_get_admin_role, sub_id)
    keyboard = []
    for p in PERMISSIONS:
        display = PERM_DISPLAY.get(p, p)
        status = "✅" if perms.get(p, False) else "❌"
        keyboard.append([
            InlineKeyboardButton(
                f"{status} {display}",
                callback_data=f"perm_toggle_{sub_id}_{p}"
            )
        ])
    keyboard.append([InlineKeyboardButton("🔙 Back to list", callback_data="perm_list")])
    keyboard.append([InlineKeyboardButton("🔙 Close", callback_data="perm_close")])

    await query.edit_message_text(
        f"⚙️ *Permissions for {role.upper()}* `{sub_id}`\n"
        f"`{perm}` is now {'✅ ON' if new_val else '❌ OFF'}.",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def perm_close_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Close the permission menu."""
    query = update.callback_query
    await query.answer()
    await query.delete_message()


# ══════════════════════════════════════════════
# UNIFIED MESSAGE HANDLER
# ══════════════════════════════════════════════

async def on_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg  = update.message
    user = update.effective_user
    if not user or not msg:
        return

    uid   = user.id
    text  = (msg.text or "").strip()

    # Forward non‑admin messages to admins
    if not is_any_admin(uid):
        await forward_to_admins(update, context)
        return

    action, data = await run(db_get_state, uid)

    if text == "❌ Cancel":
        if is_any_admin(uid):
            await open_panel(update, uid, "↩️ Cancelled.")
        else:
            await run(db_clear_state, uid)
            await msg.reply_text("↩️ Cancelled.", reply_markup=ReplyKeyboardRemove())
        return

    # ── State: awaiting broadcast ──
    if action == "awaiting_broadcast":
        if not db_has_perm(uid, "can_broadcast"):
            await open_panel(update, uid, "⛔ You don't have permission to broadcast.")
            return
        await run(db_clear_state, uid)

        # Simple confirmation only
        await msg.reply_text("✅ Broadcast done")
        await open_panel(update, uid)

        # Launch background task
        asyncio.create_task(
            background_broadcast(
                source_msg=msg,
                bot=context.bot,
                text=None
            )
        )
        return

    # ── State: awaiting add admin (superadmin only) ──
    if action == "awaiting_add_admin":
        if not is_main_admin(uid):
            await open_panel(update, uid, "⛔ Only superadmin can add admins.")
            return
        await run(db_clear_state, uid)
        try:
            tid = int(text)
            if tid == ADMIN_ID:
                reply = "ℹ️ Cannot add the main admin."
            else:
                ok = await run(db_add_admin, tid, "admin")
                reply = f"✅ `{tid}` added as Admin." if ok else f"ℹ️ `{tid}` is already an admin/subadmin."
        except ValueError:
            reply = "❌ Invalid ID — please send a numeric Telegram user ID."
        await open_panel(update, uid, reply)
        return

    # ── State: awaiting add subadmin (superadmin or admin) ──
    if action == "awaiting_add_subadmin":
        if not (is_main_admin(uid) or db_is_admin(uid)):
            await open_panel(update, uid, "⛔ You don't have permission to add subadmins.")
            return
        await run(db_clear_state, uid)
        try:
            tid = int(text)
            if tid == ADMIN_ID:
                reply = "ℹ️ Cannot add the main admin."
            else:
                role = "subadmin" if not is_main_admin(uid) else "subadmin"
                ok = await run(db_add_admin, tid, role)
                reply = f"✅ `{tid}` added as Subadmin." if ok else f"ℹ️ `{tid}` is already an admin/subadmin."
        except ValueError:
            reply = "❌ Invalid ID — please send a numeric Telegram user ID."
        await open_panel(update, uid, reply)
        return

    # ── State: awaiting remove admin (superadmin only) ──
    if action == "awaiting_remove_admin":
        if not is_main_admin(uid):
            await open_panel(update, uid, "⛔ Only superadmin can remove admins.")
            return
        await run(db_clear_state, uid)
        try:
            tid = int(text)
            if tid == ADMIN_ID:
                reply = "ℹ️ The main admin cannot be removed."
            else:
                ok = await run(db_remove_subadmin, tid)
                reply = f"✅ Admin/Subadmin `{tid}` removed." if ok else f"ℹ️ `{tid}` was not an admin/subadmin."
        except ValueError:
            reply = "❌ Invalid ID."
        await open_panel(update, uid, reply)
        return

    # ── State: awaiting remove subadmin (admin or superadmin) ──
    if action == "awaiting_remove_subadmin":
        if not (is_main_admin(uid) or db_is_admin(uid)):
            await open_panel(update, uid, "⛔ You don't have permission to remove subadmins.")
            return
        await run(db_clear_state, uid)
        try:
            tid = int(text)
            if tid == ADMIN_ID:
                reply = "ℹ️ The main admin cannot be removed."
            else:
                ok = await run(db_remove_subadmin, tid)
                reply = f"✅ Subadmin `{tid}` removed." if ok else f"ℹ️ `{tid}` was not a subadmin."
        except ValueError:
            reply = "❌ Invalid ID."
        await open_panel(update, uid, reply)
        return

    # ── State: awaiting add message ──
    if action == "awaiting_addmsg":
        if not db_has_perm(uid, "can_manage_seq"):
            await open_panel(update, uid, "⛔ You don't have permission to manage sequence.")
            return
        await run(db_clear_state, uid)
        parts = text.split()
        try:
            mid, pos = int(parts[0]), int(parts[1])
            if pos < 1:
                reply = "❌ Position must be ≥ 1."
            else:
                ok    = await run(db_add_message, mid, pos)
                reply = (
                    f"✅ Message `{mid}` added at position `{pos}`."
                    if ok else
                    "❌ Duplicate position — use 🔀 Reorder to move an existing entry first."
                )
        except (ValueError, IndexError):
            reply = "❌ Invalid input. Expected: `<message_id> <position>` (two numbers)."
        await _open_sequence_panel(update, uid, reply)
        return

    # ── State: awaiting remove message ──
    if action == "awaiting_removemsg":
        if not db_has_perm(uid, "can_manage_seq"):
            await open_panel(update, uid, "⛔ You don't have permission to manage sequence.")
            return
        await run(db_clear_state, uid)
        try:
            mid   = int(text)
            ok    = await run(db_remove_message, mid)
            reply = f"✅ Message `{mid}` removed." if ok else f"ℹ️ Message ID `{mid}` not found."
        except ValueError:
            reply = "❌ Invalid ID."
        await _open_sequence_panel(update, uid, reply)
        return

    # ── State: awaiting reorder message ──
    if action == "awaiting_reordermsg":
        if not db_has_perm(uid, "can_manage_seq"):
            await open_panel(update, uid, "⛔ You don't have permission to manage sequence.")
            return
        await run(db_clear_state, uid)
        parts = text.split()
        try:
            mid, pos = int(parts[0]), int(parts[1])
            ok    = await run(db_reorder_message, mid, pos)
            reply = (
                f"✅ Message `{mid}` moved to position `{pos}`."
                if ok else
                f"ℹ️ Message ID `{mid}` not found."
            )
        except (ValueError, IndexError):
            reply = "❌ Invalid input. Expected: `<message_id> <new_position>` (two numbers)."
        await _open_sequence_panel(update, uid, reply)
        return

    # ── State: awaiting change source ──
    if action == "awaiting_change_source":
        if not db_has_perm(uid, "can_change_source"):
            await open_panel(update, uid, "⛔ You don't have permission to change source channel.")
            return
        await run(db_clear_state, uid)
        try:
            new_id = int(text)
            await run(db_set_source_chat_id, new_id)
            reply = f"✅ Source channel updated to `{new_id}`."
        except ValueError:
            reply = "❌ Invalid chat ID."
        await open_panel(update, uid, reply)
        return

    # ── State: awaiting set post button ──
    if action == "awaiting_set_post":
        if not db_has_perm(uid, "can_set_post_button"):
            await open_panel(update, uid, "⛔ You don't have permission to set post button.")
            return
        await run(db_clear_state, uid)
        parts = text.split("|")
        msg_text = parts[0].strip()
        btn_text = parts[1].strip() if len(parts) > 1 else ""
        btn_url  = parts[2].strip() if len(parts) > 2 else ""
        await run(db_set_post_sequence, msg_text, btn_text, btn_url)
        reply = "✅ Post‑sequence message updated.\n"
        if not btn_text or not btn_url:
            reply += "ℹ️ Button has been removed (or left empty)."
        await open_panel(update, uid, reply)
        return

    # ── State: awaiting remove post button ──
    if action == "awaiting_remove_post_button":
        if not db_has_perm(uid, "can_set_post_button"):
            await open_panel(update, uid, "⛔ You don't have permission to modify the post button.")
            return
        await run(db_clear_state, uid)
        if text.lower() != "yes":
            await open_panel(update, uid, "↩️ Removal cancelled.")
            return
        current = await run(db_get_post_sequence)
        await run(db_set_post_sequence, current.get("message_text", ""), "", "")
        await open_panel(update, uid, "✅ Post button has been removed.")
        return

    # ── Button: Broadcast ──
    if text == "📢 Broadcast":
        if not db_has_perm(uid, "can_broadcast"):
            await msg.reply_text("⛔ You don't have permission to broadcast.")
            return
        await run(db_set_state, uid, "awaiting_broadcast")
        await msg.reply_text(
            "📝 Send the message you want to broadcast now.\n"
            "_(Supports text, photo, video, document — any format)_",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Button: Stats ──
    if text == "📊 Stats":
        if not db_has_perm(uid, "can_stats"):
            await msg.reply_text("⛔ You don't have permission to view stats.")
            return
        total = await run(db_total_users)
        daily = await run(db_daily_users)
        pending = len(await run(db_get_pending_requests))
        auto = "ON ✅" if await run(db_get_auto_approve) else "OFF ❌"
        await msg.reply_text(
            "📊 *Bot Statistics*\n\n"
            f"👥 Total users:       `{total}`\n"
            f"🗓 Today's new users: `{daily}`\n"
            f"⏳ Pending approvals: `{pending}`\n"
            f"🔄 Auto‑approve:      `{auto}`",
            parse_mode="Markdown",
            reply_markup=staff_kb(uid),
            )
        return

    # ── Button: Admins (superadmin only) ──
    if text == "👑 Admins" and is_main_admin(uid):
        rows = await run(db_list_admins, "admin")
        if rows:
            listing = "\n".join(f"• `{r['user_id']}` (Admin)" for r in rows)
        else:
            listing = "_No admins._"
        await msg.reply_text(
            f"👑 *Admin Management*\n\n{listing}\n\n"
            "Use buttons below to add/remove admins.",
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardMarkup(
                [["➕ Add Admin", "➖ Remove Admin"], ["🔙 Back to Panel"]],
                resize_keyboard=True
            )
        )
        return

    if text == "➕ Add Admin" and is_main_admin(uid):
        await run(db_set_state, uid, "awaiting_add_admin")
        await msg.reply_text(
            "👑 Send the *Telegram user ID* of the person to add as Admin:",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    if text == "➖ Remove Admin" and is_main_admin(uid):
        rows = await run(db_list_admins, "admin")
        if not rows:
            await msg.reply_text("ℹ️ No admins to remove.", reply_markup=admin_panel_kb())
            return
        listing = "\n".join(f"• `{r['user_id']}`" for r in rows)
        await run(db_set_state, uid, "awaiting_remove_admin")
        await msg.reply_text(
            f"🟡 *Current Admins:*\n{listing}\n\n"
            "Send the *user ID* to remove:",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Button: Subadmins (superadmin or admin) ──
    if text == "👥 Subadmins":
        if not (is_main_admin(uid) or db_is_admin(uid)):
            await msg.reply_text("⛔ You don't have permission to manage subadmins.")
            return
        if is_main_admin(uid):
            rows = await run(db_list_admins)  # all
            listing = "\n".join(f"• `{r['user_id']}` ({r['role'].capitalize()})" for r in rows)
        else:
            rows = await run(db_list_admins, "subadmin")
            listing = "\n".join(f"• `{r['user_id']}`" for r in rows) if rows else "_No subadmins._"
        await msg.reply_text(
            f"👥 *Subadmin Management*\n\n{listing}\n\n"
            "Use buttons below to add/remove subadmins.",
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardMarkup(
                [["➕ Add Subadmin", "➖ Remove Subadmin"], ["🔙 Back to Panel"]],
                resize_keyboard=True
            )
        )
        return

    if text == "➕ Add Subadmin":
        if not (is_main_admin(uid) or db_is_admin(uid)):
            await msg.reply_text("⛔ You don't have permission to add subadmins.")
            return
        await run(db_set_state, uid, "awaiting_add_subadmin")
        await msg.reply_text(
            "👤 Send the *Telegram user ID* of the person to add as Subadmin:",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    if text == "➖ Remove Subadmin":
        if not (is_main_admin(uid) or db_is_admin(uid)):
            await msg.reply_text("⛔ You don't have permission to remove subadmins.")
            return
        if is_main_admin(uid):
            rows = await run(db_list_admins)  # all
        else:
            rows = await run(db_list_admins, "subadmin")
        if not rows:
            await msg.reply_text("ℹ️ No subadmins to remove.", reply_markup=staff_kb(uid))
            return
        listing = "\n".join(f"• `{r['user_id']}`" for r in rows)
        await run(db_set_state, uid, "awaiting_remove_subadmin")
        await msg.reply_text(
            f"🟡 *Current Subadmins:*\n{listing}\n\n"
            "Send the *user ID* to remove:",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Button: Approve All Requests (main admin only) ──
    if text == "✅ Approve All Requests" and is_main_admin(uid):
        pending = await run(db_get_pending_requests)
        if not pending:
            await msg.reply_text("ℹ️ No pending join requests.", reply_markup=admin_panel_kb())
            return
        status = await msg.reply_text(f"⏳ Approving {len(pending)} requests…")
        approved = 0
        for req in pending:
            try:
                await context.bot.approve_chat_join_request(
                    chat_id=req["chat_id"],
                    user_id=req["user_id"]
                )
                approved += 1
            except Exception as e:
                logger.error("Failed to approve %s in %s: %s", req["user_id"], req["chat_id"], e)
            await asyncio.sleep(0.1)
        await run(db_clear_pending_requests)
        await status.edit_text(f"✅ Approved {approved} out of {len(pending)} requests.")
        await open_panel(update, uid)
        return

    # ── Button: Change Source Channel ──
    if text == "📡 Change Source Channel":
        if not db_has_perm(uid, "can_change_source"):
            await msg.reply_text("⛔ You don't have permission to change source channel.")
            return
        current = await run(db_get_source_chat_id)
        await run(db_set_state, uid, "awaiting_change_source")
        await msg.reply_text(
            f"Current source channel ID: `{current}`\n\n"
            "Send the new *channel ID* (numeric):",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Button: Set Post Button ──
    if text == "🔘 Set Post Button":
        if not db_has_perm(uid, "can_set_post_button"):
            await msg.reply_text("⛔ You don't have permission to set post button.")
            return
        current = await run(db_get_post_sequence)
        info = f"Current: `{current.get('message_text','')}`"
        if current.get('button_text'):
            info += f" | Button: `{current['button_text']}` → `{current['button_url']}`"
        await run(db_set_state, uid, "awaiting_set_post")
        await msg.reply_text(
            f"{info}\n\n"
            "Send the new configuration in the format:\n"
            "`Message text | Button text | Button URL`\n"
            "_(Button text and URL are optional; omit to remove button)_\n\n"
            "Example with button:\n"
            "`Thanks for joining! | Visit site | https://example.com`\n\n"
            "Example without button:\n"
            "`Thanks for joining!`",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Button: Remove Post Button ──
    if text == "🗑 Remove Post Button":
        if not db_has_perm(uid, "can_set_post_button"):
            await msg.reply_text("⛔ You don't have permission to modify the post button.")
            return
        current = await run(db_get_post_sequence)
        info = f"Current message: `{current.get('message_text','')}`"
        if current.get('button_text'):
            info += f"\nCurrent button: `{current['button_text']}` → `{current['button_url']}`"
        await run(db_set_state, uid, "awaiting_remove_post_button")
        await msg.reply_text(
            f"{info}\n\n"
            "Are you sure you want to *remove the button*?\n"
            "Type `yes` to confirm, or `❌ Cancel` to abort.",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Button: Auto‑Approve Toggle (superadmin only) ──
    if text.startswith("🔄 Auto‑Approve:") and is_main_admin(uid):
        current = await run(db_get_auto_approve)
        new_val = not current
        await run(db_set_auto_approve, new_val)
        await open_panel(update, uid, f"🔄 Auto‑approve is now {'ON ✅' if new_val else 'OFF ❌'}")
        return

    # ── Button: Subadmin Permissions (main admin only) ──
    if text == "⚙️ Subadmin Permissions" and is_main_admin(uid):
        subs = await run(db_list_admins)
        if not subs:
            await msg.reply_text("ℹ️ No subadmins to configure.", reply_markup=admin_panel_kb())
            return

        keyboard = []
        for sub in subs:
            sid = sub["user_id"]
            role = sub["role"]
            keyboard.append([InlineKeyboardButton(f"👤 {sid} ({role.upper()})", callback_data=f"perm_sub_{sid}")])
        keyboard.append([InlineKeyboardButton("🔙 Close", callback_data="perm_close")])

        await msg.reply_text(
            "⚙️ *Select a subadmin to manage permissions:*",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return

    # ── Button: Message Sequence ──
    if text == "📨 Message Sequence":
        if not db_has_perm(uid, "can_manage_seq"):
            await msg.reply_text("⛔ You don't have permission to manage sequence.")
            return
        await _open_sequence_panel(update, uid)
        return

    # ── Sequence sub‑panel: Add Message ──
    if text == "➕ Add Message" and db_has_perm(uid, "can_manage_seq"):
        await run(db_set_state, uid, "awaiting_addmsg")
        await msg.reply_text(
            "📩 Send the *message ID* and *position* separated by a space.\n\n"
            "Example: `101 1`\n"
            "_(This copies message 101 from source channel at position 1)_",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Sequence sub‑panel: Remove Message ──
    if text == "➖ Remove Message" and db_has_perm(uid, "can_manage_seq"):
        rows = await run(db_get_messages)
        if not rows:
            await _open_sequence_panel(update, uid, "ℹ️ Sequence is empty.")
            return
        listing = "\n".join(f"  `{r['position']}.` msg\\_id `{r['message_id']}`" for r in rows)
        await run(db_set_state, uid, "awaiting_removemsg")
        await msg.reply_text(
            f"📋 *Current sequence:*\n{listing}\n\n"
            "Send the *message ID* to remove:",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Sequence sub‑panel: Reorder Message ──
    if text == "🔀 Reorder Message" and db_has_perm(uid, "can_manage_seq"):
        rows = await run(db_get_messages)
        if not rows:
            await _open_sequence_panel(update, uid, "ℹ️ Sequence is empty.")
            return
        listing = "\n".join(f"  `{r['position']}.` msg\\_id `{r['message_id']}`" for r in rows)
        await run(db_set_state, uid, "awaiting_reordermsg")
        await msg.reply_text(
            f"📋 *Current sequence:*\n{listing}\n\n"
            "Send *message\\_id* and *new\\_position* separated by a space.\n"
            "Example: `101 3`",
            parse_mode="Markdown",
            reply_markup=cancel_kb(),
        )
        return

    # ── Sequence sub‑panel: List Messages ──
    if text == "📄 List Messages" and db_has_perm(uid, "can_manage_seq"):
        rows = await run(db_get_messages)
        if rows:
            body = "\n".join(f"  `{r['position']}.` msg\\_id `{r['message_id']}`" for r in rows)
        else:
            body = "_Sequence is empty._"
        await msg.reply_text(
            f"📋 *Message Sequence*\n\n{body}",
            parse_mode="Markdown",
            reply_markup=sequence_panel_kb(),
        )
        return

    # ── Sequence sub‑panel: Back to Panel ──
    if text == "🔙 Back to Panel":
        await open_panel(update, uid)
        return


async def _open_sequence_panel(update: Update, uid: int, note: str = "") -> None:
    text = (f"{note}\n\n📨 *Message Sequence Panel*" if note else "📨 *Message Sequence Panel*")
    await update.message.reply_text(
        text.strip(), parse_mode="Markdown", reply_markup=sequence_panel_kb()
    )


# ══════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════

def main() -> None:
    init_db()

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(ChatJoinRequestHandler(on_join_request))
    app.add_handler(CallbackQueryHandler(cb_stats, pattern="^stats$"))

    # Callback handlers for subadmin permissions UI
    app.add_handler(CallbackQueryHandler(subadmin_list_callback, pattern="^perm_list$"))
    app.add_handler(CallbackQueryHandler(subadmin_perm_menu_callback, pattern="^perm_sub_"))
    app.add_handler(CallbackQueryHandler(perm_toggle_callback, pattern="^perm_toggle_"))
    app.add_handler(CallbackQueryHandler(perm_close_callback, pattern="^perm_close$"))

    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND, on_message))

    logger.info("Bot started — polling…")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
