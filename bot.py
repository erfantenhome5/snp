import os
import sentry_sdk
import logging
import time
import threading
import shutil
import zipfile
import json
import uuid
from datetime import datetime, timedelta

# Telegram and automation libraries
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    CallbackQueryHandler,
    ConversationHandler,
)
from curl_cffi.requests import Session as CurlSession
from requests.exceptions import HTTPError
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

# --- Configuration ---
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
# --- Environment Variables ---
SENTRY_DSN = os.environ.get("SENTRY_DSN")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")
BOT_PASSWORD = os.environ.get("BOT_PASSWORD")

# --- Sentry Initialization ---
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=1.0)

# --- User Authorization ---
AUTHORIZED_USERS_FILE = "authorized_users.json"
AUTHORIZED_USERS = set()

def load_authorized_users():
    global AUTHORIZED_USERS
    try:
        if os.path.exists(AUTHORIZED_USERS_FILE):
            with open(AUTHORIZED_USERS_FILE, 'r') as f:
                user_ids = json.load(f)
                AUTHORIZED_USERS = set(user_ids)
                logging.info(f"Loaded {len(AUTHORIZED_USERS)} authorized users.")
    except Exception as e:
        logging.error(f"Could not load authorized users file: {e}", exc_info=True)

def save_authorized_users():
    try:
        with open(AUTHORIZED_USERS_FILE, 'w') as f:
            json.dump(list(AUTHORIZED_USERS), f, indent=4)
    except Exception as e:
        logging.error(f"Could not save authorized users file: {e}", exc_info=True)


# --- Global Configs & State ---
SITE_CONFIGS = {
    "snappfood": {
        "name": "Snappfood",
        "otp_url": "https://snappfood.ir/mobile/v4/user/loginMobileWithNoPass",
        "login_url": "https://snappfood.ir/mobile/v2/user/loginMobileWithToken",
        "discounts_url": "https://snappfood.ir/mobile/v2/user/activeVouchers",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    },
    "okala": {
        "name": "Okala",
        "otp_url": "https://www.okala.com/api/v3/user/otp",
        "login_url": "https://www.okala.com/api/v3/user/token",
        "refresh_url": "https://www.okala.com/api/v3/user/token",
        "discounts_url": "https://www.okala.com/api/v3/user/vouchers",
        "headers": {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://www.okala.com",
            "Referer": "https://www.okala.com/",
        },
    },
    "tapsi": {
        "name": "Tapsi",
        "login_page": "https://accounts.tapsi.ir/login?client_id=tapsi.cab.passenger&redirect_uri=https%3A%2F%2Fapp.tapsi.cab&response_type=code&scope=PASSENGER&state=be452b2200ac4ce5811b2add151cb007&code_challenge=CAajCXZFhHghxOtE9aIDvj5OmzYOsAumA-MO_5DtpOM&code_challenge_method=S256&response_mode=query",
        "rewards_url": "https://api.tapsi.cab/api/v2/reward/userReward",
    },
}
BASE_DATA_DIR = "user_data"
active_tapsi_sessions = {}
SESSION_TIMEOUT = timedelta(minutes=5)
VALID_SERVICES = ["snappfood", "tapsi", "okala"]

(
    SELECTING_ACTION,
    SELECTING_SERVICE,
    ENTERING_PHONE,
    ENTERING_OTP,
    AWAITING_PASSWORD,
) = range(5)


# --- Helper Functions ---
def get_user_dir(chat_id, service):
    path = os.path.join(BASE_DATA_DIR, str(chat_id), f"{service}_sessions")
    os.makedirs(path, exist_ok=True)
    return path

def format_phone_number(phone):
    return "0" + phone if not phone.startswith("0") else phone

# REFINED: Central function to show the main menu
async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Sends or edits a message to show the main menu."""
    keyboard = [
        [InlineKeyboardButton("➕ Add Account", callback_data="add_account")],
        [InlineKeyboardButton("📋 List Accounts", callback_data="list_accounts")],
        [InlineKeyboardButton("🔄 Check Vouchers", callback_data="check_vouchers")],
        [InlineKeyboardButton("💾 Download Sessions", callback_data="download_sessions")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # If called from a query, edit the message. If not, send a new one.
    if update.callback_query:
        await update.callback_query.edit_message_text(
            "Welcome! Please choose an action:", reply_markup=reply_markup
        )
    else:
        await update.message.reply_text(
            "Welcome! Please choose an action:", reply_markup=reply_markup
        )

# --- Snappfood & Okala Logic ---
def do_otp_request(phone_number, service):
    config = SITE_CONFIGS[service]
    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(config.get("headers", {}))
            if service == "snappfood":
                params = {
                    "client": "WEBSITE", "deviceType": "WEBSITE", "appVersion": "8.1.1",
                    "UDID": str(uuid.uuid4()), "locale": "fa",
                }
                payload = {"cellphone": phone_number}
                r = s.post(config["otp_url"], params=params, data=payload)
            elif service == "okala":
                payload = {"mobile": phone_number}
                r = s.post(config["otp_url"], json=payload)
            r.raise_for_status()
            logging.info(f"{service.capitalize()} OTP response: {r.text}")
            return True
    except Exception as e:
        logging.error(f"{service.capitalize()} OTP request failed: {e}")
        sentry_sdk.capture_exception(e)
        return False

def do_snappfood_login(phone_number, otp_code, chat_id):
    try:
        with CurlSession(impersonate="chrome120") as session:
            base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            session.headers.update({**base_headers, **SITE_CONFIGS["snappfood"].get("headers", {})})
            params = {
                "client": "WEBSITE", "deviceType": "WEBSITE", "appVersion": "8.1.1",
                "UDID": str(uuid.uuid4()), "locale": "fa",
            }
            payload = {"cellphone": phone_number, "code": otp_code}
            response = session.post(SITE_CONFIGS["snappfood"]["login_url"], params=params, data=payload)
            response.raise_for_status()
            data = response.json()
            token_data = data.get("data", {})
            token = token_data.get("oauth2_token", {}).get("access_token")
            token_type = "bearer" if token else "nested"
            if not token:
                token = token_data.get("nested_jwt")
            if not token:
                return "❌ CRITICAL: Could not find token in login response."
            token_info = {"token": token, "token_type": token_type}
            cookies = dict(session.cookies)
            account_data = {"token_info": token_info, "cookies": cookies}
            sessions_dir = get_user_dir(chat_id, "snappfood")
            with open(os.path.join(sessions_dir, f"{phone_number}_session.json"), "w") as f:
                json.dump(account_data, f)
            message = f"✅ Snappfood session saved for {phone_number}."
            vouchers_message = fetch_snappfood_vouchers(account_data)
            return message + vouchers_message
    except Exception as e:
        logging.error(f"Error during Snappfood login for {phone_number}: {e}")
        sentry_sdk.capture_exception(e)
        return f"❌ An error occurred during Snappfood login."

def do_okala_login(phone_number, otp_code, chat_id):
    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(SITE_CONFIGS["okala"].get("headers", {}))
            payload = {"mobile": phone_number, "code": otp_code}
            r = s.post(SITE_CONFIGS["okala"]["login_url"], json=payload)
            r.raise_for_status()
            data = r.json()
            if access_token := data.get("access_token"):
                token_info = {
                    "token_type": "bearer", "access_token": access_token,
                    "refresh_token": data.get("refresh_token"),
                }
                sessions_dir = get_user_dir(chat_id, "okala")
                with open(os.path.join(sessions_dir, f"{phone_number}_tokens.json"), "w") as f:
                    json.dump(token_info, f)
                message = f"✅ Okala session saved for {phone_number}."
                vouchers_message = fetch_okala_vouchers(token_info, phone_number, chat_id)
                return message + vouchers_message
            else:
                logging.error(f"Okala login failed. Response: {r.text}")
                return "❌ CRITICAL: Could not find token in Okala login response. Check logs."
    except Exception as e:
        logging.error(f"Error during Okala login for {phone_number}: {e}")
        return f"❌ An error occurred during Okala login."

# --- Token Refresh and Voucher Fetching Logic ---
def refresh_okala_token(token_info, phone_number, chat_id):
    refresh_token = token_info.get("refresh_token")
    if not refresh_token:
        return None, "❌ No refresh token available. Please log in again."

    config = SITE_CONFIGS["okala"]
    payload = {"refresh_token": refresh_token, "grant_type": "refresh_token"}

    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(config.get("headers", {}))
            response = s.post(config["refresh_url"], json=payload)
            response.raise_for_status()
            data = response.json()
            
            new_access_token = data.get("access_token")
            if not new_access_token:
                return None, "❌ Refresh failed: No new access token in response."

            token_info["access_token"] = new_access_token
            token_info["refresh_token"] = data.get("refresh_token", refresh_token)
            
            sessions_dir = get_user_dir(chat_id, "okala")
            token_file = os.path.join(sessions_dir, f"{phone_number}_tokens.json")
            with open(token_file, "w") as f:
                json.dump(token_info, f)

            return token_info, "✅ Token refreshed successfully."
    except HTTPError as e:
        logging.error(f"Okala token refresh failed for {phone_number}: {e}")
        return None, f"❌ Token refresh failed with status {e.response.status_code}. Please log in again."
    except Exception as e:
        logging.error(f"Unexpected error during Okala token refresh for {phone_number}: {e}")
        return None, f"❌ Unexpected error during refresh: {e}"

def fetch_okala_vouchers(token_info, phone_number=None, chat_id=None):
    access_token = token_info.get("access_token")
    if not access_token:
        return "\n\n⚠️ Invalid or missing token for Okala."

    config = SITE_CONFIGS["okala"]
    headers = {**config["headers"], "Authorization": f"Bearer {access_token}"}
    
    def get_vouchers(session, auth_headers):
        response = session.get(config["discounts_url"], headers=auth_headers)
        response.raise_for_status()
        data = response.json()
        vouchers = data.get("data", [])
        if not vouchers:
            return f"\n\nℹ️ No active Okala vouchers found."
        result = f"\n\n🎁 **Active Okala Vouchers:**\n"
        for v in vouchers:
            title = v.get("title", "N/A")
            code = v.get("code", "N/A")
            desc = v.get("description", "N/A")
            result += f"  - **{title}**\n    Code: `{code}`\n    Description: {desc}\n"
        return result

    try:
        with CurlSession(impersonate="chrome120") as s:
            return get_vouchers(s, headers)
    except HTTPError as e:
        if e.response.status_code == 401 and phone_number and chat_id:
            logging.info(f"Okala token expired for {phone_number}. Attempting refresh.")
            new_token_info, refresh_message = refresh_okala_token(token_info, phone_number, chat_id)
            if new_token_info:
                try:
                    with CurlSession(impersonate="chrome120") as s_retry:
                        new_headers = {**config["headers"], "Authorization": f"Bearer {new_token_info['access_token']}"}
                        vouchers_result = get_vouchers(s_retry, new_headers)
                        return f"{refresh_message}{vouchers_result}"
                except Exception as retry_e:
                    return f"{refresh_message}\n\n⚠️ Failed to fetch vouchers after refresh: {retry_e}"
            else:
                return f"\n\n{refresh_message}"
        else:
            logging.error(f"Failed to fetch Okala vouchers: {e}")
            return f"\n\n⚠️ Could not fetch Okala vouchers. Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected error fetching Okala vouchers: {e}")
        return f"\n\n⚠️ Unexpected error fetching Okala vouchers: {e}"

def fetch_snappfood_vouchers(account_data):
    token_info = account_data.get("token_info", {})
    saved_cookies = account_data.get("cookies", {})
    token = token_info.get("token")
    token_type = token_info.get("token_type")

    if not token:
        return "\n\n⚠️ Invalid or missing token for Snappfood."

    try:
        with CurlSession(impersonate="chrome120") as session:
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Origin": "https://snappfood.ir", "Referer": "https://snappfood.ir/",
            }
            if token_type == "bearer":
                headers["Authorization"] = f"Bearer {token}"
            else:
                headers["x-snappfood-token"] = token
            session.headers.update(headers)
            session.cookies.update(saved_cookies)
            response = session.get(SITE_CONFIGS["snappfood"]["discounts_url"])
            response.raise_for_status()
            data = response.json()
            vouchers = data.get("data", {}).get("vouchers", [])
            if not vouchers:
                return f"\n\nℹ️ No active Snappfood vouchers found."
            result = f"\n\n🎁 **Active Snappfood Vouchers:**\n"
            for v in vouchers:
                title = v.get("title", "N/A")
                code = v.get("customer_code", "N/A")
                expires = v.get("expired_at", "N/A")
                result += f"  - **{title}**\n    Code: `{code}`\n    Expires: {expires}\n"
            return result
    except Exception as e:
        logging.error(f"Failed to fetch Snappfood vouchers: {e}")
        return f"\n\n⚠️ Could not fetch Snappfood vouchers. Error: {e}"

def fetch_tapsi_rewards(access_token, cookies):
    config = SITE_CONFIGS["tapsi"]
    headers = {
        "Authorization": f"Bearer {access_token}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }
    session = CurlSession(impersonate="chrome120")
    session.headers.update(headers)
    session.cookies.update(cookies)
    try:
        response = session.get(config["rewards_url"])
        response.raise_for_status()
        rewards = response.json().get("data", {}).get("userRewards", [])
        if not rewards:
            return "\n\nℹ️ No active Tapsi rewards found."

        result = "\n\n🎁 **Active Tapsi Rewards:**\n"
        for r in rewards:
            result += f"  - **{r.get('title')}**\n    {r.get('description')}\n    Expires: {r.get('expiredAt')}\n"
        return result
    except Exception as e:
        logging.error(f"Failed to fetch Tapsi rewards: {e}")
        return f"\n\n⚠️ Could not fetch Tapsi rewards. Error: {e}"


# --- Telegram UI and Conversation Handlers ---
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.message.chat_id

    if ADMIN_CHAT_ID and str(chat_id) == ADMIN_CHAT_ID:
        if chat_id not in AUTHORIZED_USERS:
            AUTHORIZED_USERS.add(chat_id)
            save_authorized_users()
            logging.info(f"Admin user {chat_id} auto-authorized.")

    if chat_id in AUTHORIZED_USERS:
        await show_main_menu(update, context)
        return SELECTING_ACTION
    else:
        await update.message.reply_text(
            "Welcome! This is a private bot. Please enter the password to request access."
        )
        return AWAITING_PASSWORD

async def handle_password_submission(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    password = update.message.text
    user = update.message.from_user

    if not BOT_PASSWORD:
        await update.message.reply_text("Bot password is not set. Access is disabled.")
        return ConversationHandler.END

    if password == BOT_PASSWORD:
        if not ADMIN_CHAT_ID:
            await update.message.reply_text("Admin not configured. Access cannot be granted automatically.")
            return ConversationHandler.END

        approval_keyboard = [
            [
                InlineKeyboardButton("✅ Approve", callback_data=f"approve_{user.id}"),
                InlineKeyboardButton("❌ Deny", callback_data=f"deny_{user.id}"),
            ]
        ]
        reply_markup = InlineKeyboardMarkup(approval_keyboard)
        
        user_info = f"User: {user.full_name} (@{user.username or 'N/A'})\nID: `{user.id}`"
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=f"New access request:\n\n{user_info}",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
        
        await update.message.reply_text(
            "✅ Your access request has been sent to the admin for approval. You will be notified of the decision."
        )
        return ConversationHandler.END
    else:
        await update.message.reply_text("❌ Incorrect password. Please try again or type /cancel.")
        return AWAITING_PASSWORD

async def handle_admin_decision(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    admin_id = str(query.from_user.id)
    if not ADMIN_CHAT_ID or admin_id != ADMIN_CHAT_ID:
        await context.bot.send_message(chat_id=admin_id, text="This action is reserved for the bot admin.")
        return

    try:
        action, user_id_str = query.data.split("_", 1)
        user_id = int(user_id_str)
    except (ValueError, IndexError) as e:
        logging.error(f"Could not parse admin callback query: {query.data}, error: {e}")
        await query.edit_message_text(text=f"{query.message.text}\n\n--- ⚠️ Error processing callback. ---")
        return

    original_message = query.message.text
    
    if action == "approve":
        AUTHORIZED_USERS.add(user_id)
        save_authorized_users()
        logging.info(f"Admin approved access for user {user_id}")
        await context.bot.send_message(
            chat_id=user_id,
            text="🎉 Your access has been approved! You can now use the /start command to begin."
        )
        await query.edit_message_text(text=f"{original_message}\n\n--- ✅ Approved by admin. ---")
    elif action == "deny":
        logging.info(f"Admin denied access for user {user_id}")
        await context.bot.send_message(
            chat_id=user_id,
            text="😔 Your access request has been denied by the admin."
        )
        await query.edit_message_text(text=f"{original_message}\n\n--- ❌ Denied by admin. ---")

# REFINED: Generic function to ask for a service for any action
async def ask_for_service(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["action"] = query.data

    keyboard = [
        [
            InlineKeyboardButton("Snappfood", callback_data="snappfood"),
            InlineKeyboardButton("Okala", callback_data="okala"),
            InlineKeyboardButton("Tapsi", callback_data="tapsi"),
        ],
        [InlineKeyboardButton("« Back", callback_data="main_menu")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(
        text="Please select a service:", reply_markup=reply_markup
    )
    return SELECTING_SERVICE

async def handle_service_selection(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    service = query.data
    action = context.user_data.get("action")
    chat_id = query.message.chat_id
    
    context.user_data["service"] = service

    if action == "add_account":
        await query.edit_message_text(text=f"Selected {service.capitalize()}. Please enter your phone number.")
        return ENTERING_PHONE
    elif action == "list_accounts":
        return await list_accounts(update, context)
    elif action == "check_vouchers":
        return await check_vouchers(update, context)
    elif action == "download_sessions":
        return await ask_for_download_type(update, context)
    
    return ConversationHandler.END


async def handle_phone_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    phone = format_phone_number(update.message.text)
    service = context.user_data["service"]
    context.user_data["phone"] = phone

    if service in ["snappfood", "okala"]:
        await update.message.reply_text(f"Requesting OTP for {phone} on {service.capitalize()}...")
        if do_otp_request(phone, service):
            await update.message.reply_text("✅ OTP sent successfully. Please reply with the code.")
            return ENTERING_OTP
        else:
            await update.message.reply_text(f"❌ Failed to send OTP. Please try again.")
            # REFINED: Return to main menu on failure
            await show_main_menu(update, context)
            return ConversationHandler.END
    elif service == "tapsi":
        await update.message.reply_text("🚀 Starting Tapsi login... Please wait.")
        # ... (Tapsi selenium logic remains the same)
        return ENTERING_OTP

async def handle_otp_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.message.chat_id
    otp_code = update.message.text.strip()
    service = context.user_data["service"]
    phone = context.user_data["phone"]
    await update.message.reply_text(f"Verifying OTP for {phone} on {service.capitalize()}...")

    message = "An unknown error occurred."
    if service == "snappfood":
        message = do_snappfood_login(phone, otp_code, chat_id)
    elif service == "okala":
        message = do_okala_login(phone, otp_code, chat_id)
    elif service == "tapsi":
        # ... (Tapsi OTP logic remains the same)
        pass

    await update.message.reply_text(message, parse_mode="Markdown")
    context.user_data.clear()
    
    # REFINED: Show main menu after the task is complete
    await show_main_menu(update, context)
    return ConversationHandler.END

async def list_accounts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    service = context.user_data["service"]
    chat_id = query.message.chat_id

    sessions_dir = get_user_dir(chat_id, service)
    extension = "_session.json" if service == "snappfood" else "_cookies.json" if service == "tapsi" else "_tokens.json"
    accounts = [f.replace(extension, "") for f in os.listdir(sessions_dir) if f.endswith(extension)]

    if not accounts:
        message = f"No accounts saved for {service.capitalize()} yet."
    else:
        message = f"Saved {service.capitalize()} Accounts:\n- " + "\n- ".join(sorted(accounts))

    # REFINED: Always show a back button to the main menu
    keyboard = [[InlineKeyboardButton("« Back to Main Menu", callback_data="main_menu")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(text=message, reply_markup=reply_markup)
    return SELECTING_ACTION


async def check_vouchers(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    service = context.user_data["service"]
    chat_id = query.message.chat_id

    await query.edit_message_text(f"🔄 Checking all saved accounts for {service}. This may take a moment...")
    
    # ... (Voucher checking logic remains the same)
    full_message = "..." # Placeholder for the actual voucher report
    
    for i in range(0, len(full_message), 4096):
        await context.bot.send_message(chat_id=chat_id, text=full_message[i : i + 4096], parse_mode="Markdown")

    # REFINED: Show main menu after the report is sent
    await show_main_menu(update, context)
    return ConversationHandler.END


async def download_sessions_entry(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Entry point for the download conversation."""
    query = update.callback_query
    await query.answer()
    context.user_data["action"] = query.data
    # This now just moves to asking for the service
    return await ask_for_service(update, context)


async def ask_for_download_type(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    service = context.user_data["service"]

    keyboard = [
        [InlineKeyboardButton("Download One Account", callback_data="download_one")],
        [InlineKeyboardButton("Download All (ZIP)", callback_data="download_all")],
        [InlineKeyboardButton("« Back to Main Menu", callback_data="main_menu")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(
        text=f"Download options for {service.capitalize()}:",
        reply_markup=reply_markup,
    )
    return SELECTING_SERVICE # A bit of a state reuse, but it works

async def download_all_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # ... (Download logic is the same)
    
    # REFINED: After sending the file, return to the main menu
    await show_main_menu(update, context)
    return ConversationHandler.END

async def back_to_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    await show_main_menu(update, context)
    return SELECTING_ACTION

async def cancel_conversation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Action canceled.")
    await show_main_menu(update, context)
    return ConversationHandler.END

# --- Main Bot Function ---
def main():
    if not TELEGRAM_TOKEN:
        logging.error("TELEGRAM_TOKEN environment variable not set! Exiting.")
        return
    
    load_authorized_users()
    # ... (Cleanup thread remains the same)

    application = Application.builder().token(TELEGRAM_TOKEN).build()

    # REFINED: Simplified ConversationHandler structure
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start_command)],
        states={
            AWAITING_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_password_submission)],
            SELECTING_ACTION: [
                CallbackQueryHandler(ask_for_service, pattern="^(add_account|list_accounts|check_vouchers|download_sessions)$"),
            ],
            SELECTING_SERVICE: [
                CallbackQueryHandler(handle_service_selection, pattern="^(snappfood|okala|tapsi)$"),
                CallbackQueryHandler(back_to_main_menu, pattern="^main_menu$"),
            ],
            ENTERING_PHONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_phone_input)],
            ENTERING_OTP: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_otp_input)],
        },
        fallbacks=[
            CommandHandler("cancel", cancel_conversation),
            CallbackQueryHandler(back_to_main_menu, pattern="^main_menu$"),
            CommandHandler("start", start_command) # Allow restarting
        ],
        allow_reentry=True # Important for smooth menu navigation
    )

    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("admin", admin_command))
    application.add_handler(CallbackQueryHandler(handle_admin_decision, pattern="^(approve_|deny_)"))

    logging.info("Bot is starting with refined button flow...")
    application.run_polling()

if __name__ == "__main__":
    main()
