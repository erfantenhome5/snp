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
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)
from curl_cffi.requests import Session as CurlSession
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException

# --- Configuration ---
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
# --- Environment Variables ---
SENTRY_DSN = os.environ.get("SENTRY_DSN")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")
BOT_PASSWORD = os.environ.get("BOT_PASSWORD")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
CHROMEDRIVER_PATH = os.environ.get("CHROMEDRIVER_PATH", "./chromedriver")

# --- Sentry Initialization ---
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=1.0)

# --- UI Text & Buttons (New Reply Keyboard Layout) ---
BTN_ADD_ACCOUNT = "➕ Add Account"
BTN_LIST_ACCOUNTS = "📋 List Accounts"
BTN_CHECK_VOUCHERS = "🔄 Check Vouchers"
BTN_DOWNLOAD_SESSIONS = "💾 Download Sessions"
VALID_SERVICES = ["Snappfood", "Tapsi", "Okala"]

# --- User Authorization ---
AUTHORIZED_USERS_FILE = "authorized_users.json"
AUTHORIZED_USERS = set()

def load_authorized_users():
    """Loads the set of authorized user IDs from a file."""
    global AUTHORIZED_USERS
    try:
        if os.path.exists(AUTHORIZED_USERS_FILE):
            with open(AUTHORIZED_USERS_FILE, 'r') as f:
                user_ids = json.load(f)
                AUTHORIZED_USERS = set(map(int, user_ids)) # Ensure IDs are integers
                logging.info(f"Loaded {len(AUTHORIZED_USERS)} authorized users.")
    except Exception as e:
        logging.error(f"Could not load authorized users file: {e}", exc_info=True)

def save_authorized_users():
    """Saves the set of authorized user IDs to a file."""
    try:
        with open(AUTHORIZED_USERS_FILE, 'w') as f:
            json.dump(list(AUTHORIZED_USERS), f, indent=4)
    except Exception as e:
        logging.error(f"Could not save authorized users file: {e}", exc_info=True)

# --- State tracking for multi-step operations ---
USER_STATE = {} # e.g. {chat_id: {"action": "add_account", "service": "snappfood"}}

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


# --- Helper & Path Functions ---
def get_user_dir(chat_id, service):
    path = os.path.join(BASE_DATA_DIR, str(chat_id), f"{service.lower()}_sessions")
    os.makedirs(path, exist_ok=True)
    return path

def format_phone_number(phone):
    return "0" + phone if not phone.startswith("0") else phone

# --- Authorization Decorator ---
from functools import wraps

def authorized(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        chat_id = update.effective_chat.id
        if chat_id in AUTHORIZED_USERS:
            return await func(update, context, *args, **kwargs)
        else:
            await update.message.reply_text("❌ You are not authorized to use this bot. Please use /start to request access.")
    return wrapper

# --- Snappfood & Okala Logic (Largely unchanged, but with added delays) ---
def do_otp_request(phone_number, service):
    config = SITE_CONFIGS[service.lower()]
    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(config.get("headers", {}))
            if service.lower() == "snappfood":
                params = {"client": "WEBSITE", "deviceType": "WEBSITE", "appVersion": "8.1.1", "UDID": str(uuid.uuid4()), "locale": "fa"}
                payload = {"cellphone": phone_number}
                r = s.post(config["otp_url"], params=params, data=payload)
            elif service.lower() == "okala":
                payload = {"mobile": phone_number}
                r = s.post(config["otp_url"], json=payload)
            r.raise_for_status()
            logging.info(f"{service.capitalize()} OTP response: {r.text}")
            return True, None
    except Exception as e:
        error_message = f"An unexpected error occurred: {e}"
        if hasattr(e, 'response') and hasattr(e.response, 'status_code'):
            error_message = f"❌ Failed to send OTP. Status: {e.response.status_code}. The API might have changed."
        logging.error(f"{service.capitalize()} OTP request failed: {error_message}")
        sentry_sdk.capture_exception(e)
        return False, error_message

def do_snappfood_login(phone_number, otp_code, chat_id):
    try:
        with CurlSession(impersonate="chrome120") as session:
            # ... (rest of the function is the same, just ensure service name is lowercased for config lookup)
            service_key = "snappfood"
            base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            session.headers.update({**base_headers, **SITE_CONFIGS[service_key].get("headers", {})})
            params = {"client": "WEBSITE", "deviceType": "WEBSITE", "appVersion": "8.1.1", "UDID": str(uuid.uuid4()), "locale": "fa"}
            payload = {"cellphone": phone_number, "code": otp_code}
            response = session.post(SITE_CONFIGS[service_key]["login_url"], params=params, data=payload)
            response.raise_for_status()
            data = response.json()
            token_data = data.get("data", {})
            token = token_data.get("oauth2_token", {}).get("access_token")
            token_type = "bearer" if token else "nested"
            if not token: token = token_data.get("nested_jwt")
            if not token: return "❌ CRITICAL: Could not find token in login response."
            token_info = {"token": token, "token_type": token_type}
            cookies = dict(session.cookies)
            account_data = {"token_info": token_info, "cookies": cookies}
            sessions_dir = get_user_dir(chat_id, service_key)
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
            service_key = "okala"
            s.headers.update(SITE_CONFIGS[service_key].get("headers", {}))
            payload = {"mobile": phone_number, "code": otp_code}
            r = s.post(SITE_CONFIGS[service_key]["login_url"], json=payload)
            r.raise_for_status()
            data = r.json()
            if access_token := data.get("access_token"):
                token_info = {"token_type": "bearer", "access_token": access_token, "refresh_token": data.get("refresh_token")}
                sessions_dir = get_user_dir(chat_id, service_key)
                with open(os.path.join(sessions_dir, f"{phone_number}_tokens.json"), "w") as f:
                    json.dump(token_info, f)
                message = f"✅ Okala session saved for {phone_number}."
                vouchers_message = fetch_okala_vouchers(token_info, phone_number, chat_id)
                return message + vouchers_message
            else:
                logging.error(f"Okala login failed. Response: {r.text}")
                return "❌ CRITICAL: Could not find token in Okala login response."
    except Exception as e:
        logging.error(f"Error during Okala login for {phone_number}: {e}")
        return f"❌ An error occurred during Okala login."

# --- Token Refresh and Voucher Fetching Logic ---
def refresh_okala_token(token_info, phone_number, chat_id):
    refresh_token = token_info.get("refresh_token")
    if not refresh_token: return None, "❌ No refresh token available. Please log in again."
    config = SITE_CONFIGS["okala"]
    payload = {"refresh_token": refresh_token, "grant_type": "refresh_token"}
    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(config.get("headers", {}))
            response = s.post(config["refresh_url"], json=payload)
            response.raise_for_status()
            data = response.json()
            new_access_token = data.get("access_token")
            if not new_access_token: return None, "❌ Refresh failed: No new access token in response."
            token_info["access_token"] = new_access_token
            token_info["refresh_token"] = data.get("refresh_token", refresh_token)
            sessions_dir = get_user_dir(chat_id, "okala")
            with open(os.path.join(sessions_dir, f"{phone_number}_tokens.json"), "w") as f:
                json.dump(token_info, f)
            return token_info, "✅ Token refreshed successfully."
    except Exception as e:
        logging.error(f"Okala token refresh failed for {phone_number}: {e}")
        sentry_sdk.capture_exception(e)
        return None, f"❌ Token refresh failed. Please log in again."

def fetch_okala_vouchers(token_info, phone_number=None, chat_id=None):
    access_token = token_info.get("access_token")
    if not access_token: return "\n\n⚠️ Invalid or missing token for Okala."
    config = SITE_CONFIGS["okala"]
    headers = {**config["headers"], "Authorization": f"Bearer {access_token}"}
    def get_vouchers(session, auth_headers):
        response = session.get(config["discounts_url"], headers=auth_headers)
        response.raise_for_status()
        data = response.json()
        vouchers = data.get("data", [])
        if not vouchers: return f"\n\nℹ️ No active Okala vouchers found."
        result = f"\n\n🎁 **Active Okala Vouchers:**\n"
        for v in vouchers:
            result += f"  - **{v.get('title', 'N/A')}**\n    Code: `{v.get('code', 'N/A')}`\n    Desc: {v.get('description', 'N/A')}\n"
        return result
    try:
        with CurlSession(impersonate="chrome120") as s:
            return get_vouchers(s, headers)
    except Exception as e:
        if hasattr(e, 'response') and e.response.status_code == 401 and phone_number and chat_id:
            logging.info(f"Okala token expired for {phone_number}. Attempting refresh.")
            new_token_info, refresh_message = refresh_okala_token(token_info, phone_number, chat_id)
            if new_token_info:
                try:
                    with CurlSession(impersonate="chrome120") as s_retry:
                        new_headers = {**config["headers"], "Authorization": f"Bearer {new_token_info['access_token']}"}
                        return f"{refresh_message}{get_vouchers(s_retry, new_headers)}"
                except Exception as retry_e:
                    return f"{refresh_message}\n\n⚠️ Failed to fetch vouchers after refresh: {retry_e}"
            else:
                return f"\n\n{refresh_message}"
        else:
            logging.error(f"Failed to fetch Okala vouchers: {e}")
            return f"\n\n⚠️ Could not fetch Okala vouchers. Error: {e}"

def fetch_snappfood_vouchers(account_data):
    token_info = account_data.get("token_info", {})
    token, token_type = token_info.get("token"), token_info.get("token_type")
    if not token: return "\n\n⚠️ Invalid or missing token for Snappfood."
    try:
        with CurlSession(impersonate="chrome120") as session:
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Origin": "https://snappfood.ir", "Referer": "https://snappfood.ir/"}
            if token_type == "bearer": headers["Authorization"] = f"Bearer {token}"
            else: headers["x-snappfood-token"] = token
            session.headers.update(headers)
            session.cookies.update(account_data.get("cookies", {}))
            response = session.get(SITE_CONFIGS["snappfood"]["discounts_url"])
            response.raise_for_status()
            data = response.json()
            vouchers = data.get("data", {}).get("vouchers", [])
            if not vouchers: return f"\n\nℹ️ No active Snappfood vouchers found."
            result = f"\n\n🎁 **Active Snappfood Vouchers:**\n"
            for v in vouchers:
                result += f"  - **{v.get('title', 'N/A')}**\n    Code: `{v.get('customer_code', 'N/A')}`\n    Expires: {v.get('expired_at', 'N/A')}\n"
            return result
    except Exception as e:
        logging.error(f"Failed to fetch Snappfood vouchers: {e}")
        return f"\n\n⚠️ Could not fetch Snappfood vouchers. Error: {e}"

def fetch_tapsi_rewards(access_token, cookies):
    config = SITE_CONFIGS["tapsi"]
    headers = {"Authorization": f"Bearer {access_token}", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"}
    session = CurlSession(impersonate="chrome120")
    session.headers.update(headers)
    session.cookies.update(cookies)
    try:
        response = session.get(config["rewards_url"])
        response.raise_for_status()
        rewards = response.json().get("data", {}).get("userRewards", [])
        if not rewards: return "\n\nℹ️ No active Tapsi rewards found."
        result = "\n\n🎁 **Active Tapsi Rewards:**\n"
        for r in rewards:
            result += f"  - **{r.get('title')}**\n    {r.get('description')}\n    Expires: {r.get('expiredAt')}\n"
        return result
    except Exception as e:
        logging.error(f"Failed to fetch Tapsi rewards: {e}")
        return f"\n\n⚠️ Could not fetch Tapsi rewards. Error: {e}"

# --- Gemini API Logic (Unchanged) ---
def call_gemini_api(prompt: str) -> str:
    if not GEMINI_API_KEY: return "❌ Gemini API key is not configured."
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    try:
        with CurlSession() as session:
            response = session.post(api_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        logging.error(f"Error calling Gemini API: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return f"❌ An unexpected error occurred with Gemini API: {e}"

# --- Telegram Command Handlers ---
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles the /start command and password-based authorization."""
    chat_id = update.effective_chat.id
    if ADMIN_CHAT_ID and str(chat_id) == ADMIN_CHAT_ID and chat_id not in AUTHORIZED_USERS:
        AUTHORIZED_USERS.add(chat_id)
        save_authorized_users()
        logging.info(f"Admin user {chat_id} auto-authorized.")

    if chat_id in AUTHORIZED_USERS:
        reply_keyboard = [[BTN_ADD_ACCOUNT], [BTN_LIST_ACCOUNTS], [BTN_CHECK_VOUCHERS], [BTN_DOWNLOAD_SESSIONS]]
        await update.message.reply_text(
            "Welcome! Please choose an action from the menu below.",
            reply_markup=ReplyKeyboardMarkup(reply_keyboard, resize_keyboard=True),
        )
    else:
        USER_STATE[chat_id] = {"action": "awaiting_password"}
        await update.message.reply_text(
            "Welcome! This is a private bot. Please enter the password to request access.",
            reply_markup=ReplyKeyboardRemove(),
        )

async def handle_password_submission(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles password submission for authorization."""
    chat_id = update.effective_chat.id
    password = update.message.text
    user = update.message.from_user

    if not BOT_PASSWORD:
        await update.message.reply_text("Bot password is not set. Access is disabled.")
        return

    if password == BOT_PASSWORD:
        if not ADMIN_CHAT_ID:
            await update.message.reply_text("Admin not configured. Access cannot be granted.")
            return

        # Send approval request to admin
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=f"New access request from: {user.full_name} (@{user.username or 'N/A'})\n"
                 f"To approve, reply with: `/approve {user.id}`"
        )
        await update.message.reply_text("✅ Your access request has been sent to the admin for approval.")
    else:
        await update.message.reply_text("❌ Incorrect password. Please try again.")
    
    if chat_id in USER_STATE:
        del USER_STATE[chat_id]

async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to approve a user."""
    admin_id = update.effective_chat.id
    if not ADMIN_CHAT_ID or str(admin_id) != ADMIN_CHAT_ID:
        await update.message.reply_text("❌ This command is for the admin only.")
        return
    
    try:
        user_id_to_approve = int(context.args[0])
        AUTHORIZED_USERS.add(user_id_to_approve)
        save_authorized_users()
        await context.bot.send_message(
            chat_id=user_id_to_approve,
            text="🎉 Your access has been approved! Use /start to begin."
        )
        await update.message.reply_text(f"✅ User {user_id_to_approve} has been authorized.")
        logging.info(f"Admin approved access for user {user_id_to_approve}")
    except (IndexError, ValueError):
        await update.message.reply_text("Usage: /approve <USER_ID>")

# --- Main Logic Handler ---
@authorized
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles all incoming messages from authorized users."""
    chat_id = update.effective_chat.id
    text = update.message.text

    # Check if user is in a multi-step process
    if chat_id in USER_STATE:
        state = USER_STATE[chat_id]
        action = state.get("action")

        if action == "awaiting_service":
            if text in VALID_SERVICES:
                USER_STATE[chat_id]["service"] = text
                if state.get("next_action") == "add_account":
                    USER_STATE[chat_id]["action"] = "awaiting_phone"
                    await update.message.reply_text(f"Selected {text}. Please enter the phone number.", reply_markup=ReplyKeyboardRemove())
                elif state.get("next_action") == "list_accounts":
                    await list_accounts(update, context, text)
                elif state.get("next_action") == "check_vouchers":
                    await check_vouchers(update, context, text)
                elif state.get("next_action") == "download_sessions":
                    await download_sessions(update, context, text)
            else:
                await update.message.reply_text("Invalid service. Please select one from the keyboard.")
            return

        elif action == "awaiting_phone":
            phone = format_phone_number(text)
            service = state["service"]
            USER_STATE[chat_id]["phone"] = phone
            
            if service.lower() in ["snappfood", "okala"]:
                await update.message.reply_text(f"Requesting OTP for {phone} on {service}...")
                success, error_msg = do_otp_request(phone, service)
                if success:
                    USER_STATE[chat_id]["action"] = "awaiting_otp"
                    await update.message.reply_text("✅ OTP sent. Please reply with the code.")
                else:
                    await update.message.reply_text(error_msg)
                    del USER_STATE[chat_id] # End process
                    await start_command(update, context) # Show main menu
            
            elif service.lower() == "tapsi":
                await handle_tapsi_phone_input(update, context, phone)
            return

        elif action == "awaiting_otp":
            otp = text.strip()
            service = state["service"]
            phone = state["phone"]
            await update.message.reply_text(f"Verifying OTP for {phone} on {service}...")
            
            message = "An unknown error occurred."
            if service.lower() == "snappfood":
                message = do_snappfood_login(phone, otp, chat_id)
            elif service.lower() == "okala":
                message = do_okala_login(phone, otp, chat_id)
            elif service.lower() == "tapsi":
                message = await handle_tapsi_otp_input(update, context, otp)
            
            await update.message.reply_text(message, parse_mode="Markdown")
            del USER_STATE[chat_id] # End process
            await start_command(update, context) # Show main menu
            return

    # Handle main menu buttons
    if text == BTN_ADD_ACCOUNT:
        USER_STATE[chat_id] = {"action": "awaiting_service", "next_action": "add_account"}
        await ask_for_service(update, context, "What service do you want to add an account for?")
    elif text == BTN_LIST_ACCOUNTS:
        USER_STATE[chat_id] = {"action": "awaiting_service", "next_action": "list_accounts"}
        await ask_for_service(update, context, "What service do you want to list accounts for?")
    elif text == BTN_CHECK_VOUCHERS:
        USER_STATE[chat_id] = {"action": "awaiting_service", "next_action": "check_vouchers"}
        await ask_for_service(update, context, "What service do you want to check vouchers for?")
    elif text == BTN_DOWNLOAD_SESSIONS:
        USER_STATE[chat_id] = {"action": "awaiting_service", "next_action": "download_sessions"}
        await ask_for_service(update, context, "What service do you want to download sessions for?")

async def ask_for_service(update: Update, context: ContextTypes.DEFAULT_TYPE, message: str):
    """Sends a message asking the user to select a service."""
    reply_keyboard = [[s] for s in VALID_SERVICES]
    await update.message.reply_text(
        message,
        reply_markup=ReplyKeyboardMarkup(reply_keyboard, one_time_keyboard=True, resize_keyboard=True),
    )

# --- Specific Action Handlers ---
async def list_accounts(update: Update, context: ContextTypes.DEFAULT_TYPE, service: str):
    chat_id = update.effective_chat.id
    sessions_dir = get_user_dir(chat_id, service)
    ext = "_session.json" if service == "Snappfood" else "_cookies.json" if service == "Tapsi" else "_tokens.json"
    accounts = [f.replace(ext, "") for f in os.listdir(sessions_dir) if f.endswith(ext)]
    
    if not accounts:
        message = f"No accounts saved for {service} yet."
    else:
        message = f"Saved {service} Accounts:\n- " + "\n- ".join(sorted(accounts))
    
    await update.message.reply_text(message)
    del USER_STATE[chat_id]
    await start_command(update, context) # Show main menu

async def check_vouchers(update: Update, context: ContextTypes.DEFAULT_TYPE, service: str):
    chat_id = update.effective_chat.id
    await update.message.reply_text(f"🔄 Checking all saved accounts for {service}. This may take a moment...")
    
    sessions_dir = get_user_dir(chat_id, service)
    ext = "_session.json" if service == "Snappfood" else "_cookies.json" if service == "Tapsi" else "_tokens.json"
    account_files = [f for f in os.listdir(sessions_dir) if f.endswith(ext)]

    if not account_files:
        await update.message.reply_text(f"No accounts found for {service} to check.")
        del USER_STATE[chat_id]
        await start_command(update, context)
        return

    full_message = f"--- 📜 Report for {service} Accounts ---\n"
    for filename in sorted(account_files):
        phone_number = filename.replace(ext, "")
        file_path = os.path.join(sessions_dir, filename)
        full_message += f"\n\n**Checking Account: `{phone_number}`**"
        try:
            if service == "Snappfood":
                with open(file_path, "r") as f: account_data = json.load(f)
                full_message += fetch_snappfood_vouchers(account_data)
            elif service == "Okala":
                with open(file_path, "r") as f: token_info = json.load(f)
                full_message += fetch_okala_vouchers(token_info, phone_number, chat_id)
            elif service == "Tapsi":
                with open(file_path, "r") as f: cookies_list = json.load(f)
                cookies_dict = {c["name"]: c["value"] for c in cookies_list}
                access_token = cookies_dict.get("accessToken")
                if access_token:
                    full_message += fetch_tapsi_rewards(access_token, cookies_dict)
                else:
                    full_message += "\n❌ Could not find accessToken in session file."
        except Exception as e:
            full_message += f"\n❌ An error occurred: {e}"
            sentry_sdk.capture_exception(e)
        
        time.sleep(1) # *** FIX for 429 Error: Wait 1 second between checks ***

    await update.message.reply_text(full_message, parse_mode="Markdown")
    del USER_STATE[chat_id]
    await start_command(update, context) # Show main menu

async def download_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE, service: str):
    chat_id = update.effective_chat.id
    sessions_dir = get_user_dir(chat_id, service)
    if not any(os.scandir(sessions_dir)):
        await update.message.reply_text(f"No accounts saved for {service} yet.")
        del USER_STATE[chat_id]
        await start_command(update, context)
        return

    zip_path_base = os.path.join(BASE_DATA_DIR, str(chat_id), f"{service.lower()}_sessions_backup")
    shutil.make_archive(zip_path_base, "zip", sessions_dir)
    zip_path = f"{zip_path_base}.zip"

    await update.message.reply_text(f"Sending a zip file with all your saved {service} sessions...")
    with open(zip_path, "rb") as doc:
        await context.bot.send_document(chat_id=chat_id, document=doc, filename=f"{service.lower()}_sessions.zip")
    os.remove(zip_path)
    del USER_STATE[chat_id]
    await start_command(update, context)

# --- Tapsi Selenium Logic ---
async def handle_tapsi_phone_input(update: Update, context: ContextTypes.DEFAULT_TYPE, phone: str):
    chat_id = update.effective_chat.id
    await update.message.reply_text("🚀 Starting Tapsi login... Please wait.", reply_markup=ReplyKeyboardRemove())
    if chat_id in active_tapsi_sessions:
        try: active_tapsi_sessions[chat_id]["driver"].quit()
        except WebDriverException: pass
        del active_tapsi_sessions[chat_id]

    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    driver = None
    try:
        if not os.path.isfile(CHROMEDRIVER_PATH) or not os.access(CHROMEDRIVER_PATH, os.X_OK):
            await update.message.reply_text(f"❌ ChromeDriver not found or not executable at: {CHROMEDRIVER_PATH}")
            del USER_STATE[chat_id]
            await start_command(update, context)
            return
        
        service_obj = Service(executable_path=CHROMEDRIVER_PATH)
        driver = webdriver.Chrome(service=service_obj, options=chrome_options)
        wait = WebDriverWait(driver, 40)
        driver.get(SITE_CONFIGS["tapsi"]["login_page"])
        wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "input[type='tel']"))).send_keys(phone)
        wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'دریافت کد')]"))).click()
        
        active_tapsi_sessions[chat_id] = {"driver": driver, "timestamp": datetime.now()}
        USER_STATE[chat_id]["action"] = "awaiting_otp"
        await update.message.reply_text(f"✅ OTP sent by Tapsi to {phone}. Please reply with the 5-digit code.")
    except Exception as e:
        if driver: driver.quit()
        await update.message.reply_text(f"❌ Failed to start Tapsi login. Error: {e}")
        sentry_sdk.capture_exception(e)
        del USER_STATE[chat_id]
        await start_command(update, context)

async def handle_tapsi_otp_input(update: Update, context: ContextTypes.DEFAULT_TYPE, otp_code: str):
    chat_id = update.effective_chat.id
    session_data = active_tapsi_sessions.get(chat_id)
    if not session_data:
        return "❌ Your Tapsi session has expired. Please try again."
    
    driver = session_data["driver"]
    phone = USER_STATE[chat_id]["phone"]
    message = ""
    try:
        wait = WebDriverWait(driver, 15)
        otp_inputs = wait.until(EC.presence_of_all_elements_located((By.XPATH, "//div[starts-with(@id, 'INPUT_DIGIT_NUMBER_CONTAINER')]/input")))
        if len(otp_inputs) >= 5 and len(otp_code) == 5:
            for i in range(5):
                otp_inputs[i].send_keys(otp_code[i])
                time.sleep(0.1)
        else:
            raise Exception("Could not find the 5 separate OTP input boxes.")

        wait.until(EC.element_to_be_clickable((By.XPATH, "//button[@type='button' and not(@disabled)]"))).click()
        wait.until(EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'سرویس‌ها')]")))

        sessions_dir = get_user_dir(chat_id, "tapsi")
        cookie_file_path = os.path.join(sessions_dir, f"{phone}_cookies.json")
        browser_cookies = {c["name"]: c["value"] for c in driver.get_cookies()}
        access_token = browser_cookies.get("accessToken")

        if access_token:
            with open(cookie_file_path, "w") as f: json.dump(driver.get_cookies(), f)
            message = f"✅ Tapsi session saved for {phone}!"
            message += fetch_tapsi_rewards(access_token, browser_cookies)
        else:
            message = "❌ Login successful, but could not find accessToken cookie."
    except Exception as e:
        sentry_sdk.capture_exception(e)
        message = f"❌ Tapsi login failed. Error: {e}"
    finally:
        driver.quit()
        if chat_id in active_tapsi_sessions:
            del active_tapsi_sessions[chat_id]
    return message

# --- Admin Commands (Unchanged) ---
@authorized
async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # ... (code is the same as before)
    pass

@authorized
async def gemini_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # ... (code is the same as before)
    pass

# --- Cleanup Thread (Unchanged) ---
def cleanup_old_sessions():
    # ... (code is the same as before)
    pass

# --- Main Bot Function ---
def main():
    if not all([TELEGRAM_TOKEN, ADMIN_CHAT_ID, BOT_PASSWORD, GEMINI_API_KEY]):
        logging.warning("One or more environment variables are not set. Bot may not function fully.")

    load_authorized_users()
    
    cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
    cleanup_thread.start()

    application = Application.builder().token(TELEGRAM_TOKEN).build()

    # Handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("approve", approve_command))
    application.add_handler(CommandHandler("admin", admin_command))
    application.add_handler(CommandHandler("gemini", gemini_command))
    
    # This handler will manage both password submission and all authorized actions
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_universal_text))

    logging.info("Bot is starting with new command-based flow...")
    application.run_polling()

async def handle_universal_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """A single handler to route text input based on user state."""
    chat_id = update.effective_chat.id
    
    # If user is awaiting password, process that first
    if USER_STATE.get(chat_id, {}).get("action") == "awaiting_password":
        await handle_password_submission(update, context)
    # Otherwise, if user is authorized, let the main handler process their command
    elif chat_id in AUTHORIZED_USERS:
        await handle_message(update, context)
    # If unauthorized and not in a state, just ignore or prompt to start
    else:
        await update.message.reply_text("Please use /start to begin.")

if __name__ == "__main__":
    main()
