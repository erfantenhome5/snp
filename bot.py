import os
import sentry_sdk
import logging
import time
import threading
import shutil
import zipfile
import json
import uuid
import sqlite3
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

# --- UI Text & Buttons ---
BTN_ADD_ACCOUNT = "➕ Add Account"
BTN_LIST_ACCOUNTS = "📋 List Accounts"
BTN_CHECK_VOUCHERS = "🔄 Check Vouchers"
BTN_DOWNLOAD_SESSIONS = "💾 Download Sessions"
VALID_SERVICES = ["Snappfood", "Tapsi", "Okala"]

# --- Database Setup ---
DB_FILE = "accounts.db"

def init_db():
    """Initializes the SQLite database and creates the necessary tables."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Main table for accounts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                phone_number TEXT NOT NULL,
                session_data TEXT NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Table for authorized users
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS authorized_users (
                user_id INTEGER PRIMARY KEY
            )
        ''')
        conn.commit()

# --- User Authorization ---
AUTHORIZED_USERS = set()

def load_authorized_users():
    """Loads authorized user IDs from the database."""
    global AUTHORIZED_USERS
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM authorized_users")
            users = cursor.fetchall()
            AUTHORIZED_USERS = {user[0] for user in users}
            logging.info(f"Loaded {len(AUTHORIZED_USERS)} authorized users from DB.")
    except Exception as e:
        logging.error(f"Could not load authorized users from DB: {e}", exc_info=True)

def add_authorized_user(user_id: int):
    """Adds a user to the authorized list in the database."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO authorized_users (user_id) VALUES (?)", (user_id,))
            conn.commit()
            AUTHORIZED_USERS.add(user_id)
    except Exception as e:
        logging.error(f"Could not save authorized user {user_id} to DB: {e}", exc_info=True)


# --- State tracking for multi-step operations ---
USER_STATE = {}

# --- Global Configs & State ---
SITE_CONFIGS = {
    "snappfood": {"name": "Snappfood", "otp_url": "https://snappfood.ir/mobile/v4/user/loginMobileWithNoPass", "login_url": "https://snappfood.ir/mobile/v2/user/loginMobileWithToken", "discounts_url": "https://snappfood.ir/mobile/v2/user/activeVouchers", "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
    "okala": {
        "name": "Okala",
        "otp_url": "https://apigateway.okala.com/api/voyager/C/CustomerAccount/OTPRegister",
        "login_url": "https://apigateway.okala.com/api/v1/accounts/tokens",
        "discounts_url": "https://apigateway.okala.com/api/discount/v1/discounts/customer",
        "headers": {
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://www.okala.com",
            "Referer": "https://www.okala.com/",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "source": "okala",
            "ui-version": "2.0"
        }
    },
    "tapsi": {"name": "Tapsi", "login_page": "https://accounts.tapsi.ir/login?client_id=tapsi.cab.passenger&redirect_uri=https%3A%2F%2Fapp.tapsi.cab&response_type=code&scope=PASSENGER&state=be452b2200ac4ce5811b2add151cb007&code_challenge=CAajCXZFhHghxOtE9aIDvj5OmzYOsAumA-MO_5DtpOM&code_challenge_method=S256&response_mode=query", "rewards_url": "https://api.tapsi.cab/api/v2/reward/userReward"},
}
BASE_DATA_DIR = "user_data"
active_tapsi_sessions = {}
SESSION_TIMEOUT = timedelta(minutes=5)


# --- Helper Functions ---
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

def admin_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        chat_id = update.effective_chat.id
        if ADMIN_CHAT_ID and str(chat_id) == ADMIN_CHAT_ID:
            return await func(update, context, *args, **kwargs)
        else:
            await update.message.reply_text("❌ This command is for the admin only.")
    return wrapper


# --- Retry Decorator for Rate Limiting ---
def retry_on_429(max_retries=3, delay=2.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    is_rate_limit_error = hasattr(e, 'response') and hasattr(e.response, 'status_code') and e.response.status_code == 429
                    if is_rate_limit_error:
                        logging.warning(f"Rate limit hit (429) on attempt {attempt + 1}/{max_retries} for {func.__name__}. Retrying in {delay}s...")
                        time.sleep(delay)
                    else:
                        raise e
            raise Exception(f"Function {func.__name__} failed after {max_retries} retries due to rate limiting.")
        return wrapper
    return decorator


# --- Logic with Retry Mechanism ---
@retry_on_429()
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
                # *** MODIFIED: Add extra headers and new payload for Okala OTP ***
                s.headers.update({
                    "Content-Type": "application/json",
                    "X-Correlation-Id": str(uuid.uuid4()),
                    "session-id": str(uuid.uuid4())
                })
                payload = {
                    "mobile": phone_number,
                    "confirmTerms": True,
                    "notRobot": False,
                    "ValidationCodeCreateReason": 5,
                    "OtpApp": 0,
                    "deviceTypeCode": 10,
                    "IsAppOnly": False
                }
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

def save_account_to_db(user_id, service, phone_number, session_data):
    account_id = str(uuid.uuid4())
    session_json = json.dumps(session_data)
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO accounts (id, user_id, service, phone_number, session_data) VALUES (?, ?, ?, ?, ?)",
            (account_id, user_id, service.lower(), phone_number, session_json)
        )
        conn.commit()
    return account_id

def do_snappfood_login(phone_number, otp_code, chat_id):
    try:
        with CurlSession(impersonate="chrome120") as session:
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
            if not token: return "❌ CRITICAL: Could not find token in login response.", None
            
            account_data = {"token_info": {"token": token, "token_type": token_type}, "cookies": dict(session.cookies)}
            account_id = save_account_to_db(chat_id, service_key, phone_number, account_data)
            
            message = f"✅ Snappfood session saved for {phone_number}.\n\nYour Unique Account ID is:\n`{account_id}`"
            vouchers_message = fetch_snappfood_vouchers(account_data)
            return message + vouchers_message, account_id
    except Exception as e:
        logging.error(f"Error during Snappfood login for {phone_number}: {e}")
        sentry_sdk.capture_exception(e)
        return f"❌ An error occurred during Snappfood login.", None

def do_okala_login(phone_number, otp_code, chat_id):
    try:
        with CurlSession(impersonate="chrome120") as s:
            service_key = "okala"
            s.headers.update(SITE_CONFIGS[service_key].get("headers", {}))
            s.headers.update({"Content-Type": "application/x-www-form-urlencoded"})
            payload = {
                "mobile_number": phone_number,
                "otp_code": otp_code,
                "grant_type": "customer_grant_type",
                "client_id": "customer_client_id",
                "client_secret": "u_M{'57j!%LI21#",
                "device_type_code": 10
            }
            r = s.post(SITE_CONFIGS[service_key]["login_url"], data=payload)
            r.raise_for_status()
            data = r.json()
            if access_token := data.get("access_token"):
                # *** MODIFIED: Save AlternativeId as cerberusId ***
                cerberus_id = data.get("UserInfo", {}).get("AlternativeId")
                token_info = {
                    "token_type": "Bearer", 
                    "access_token": access_token, 
                    "refresh_token": data.get("refresh_token"),
                    "cerberusId": cerberus_id
                }
                
                account_data = {"token_info": token_info, "cookies": dict(s.cookies)}
                account_id = save_account_to_db(chat_id, service_key, phone_number, account_data)
                
                message = f"✅ Okala session saved for {phone_number}.\n\nYour Unique Account ID is:\n`{account_id}`"
                vouchers_message = fetch_okala_vouchers(account_data, cerberus_id)
                return message + vouchers_message, account_id
            else:
                logging.error(f"Okala login failed. Response: {r.text}")
                return "❌ CRITICAL: Could not find token in Okala login response.", None
    except Exception as e:
        logging.error(f"Error during Okala login for {phone_number}: {e}")
        return f"❌ An error occurred during Okala login.", None

@retry_on_429()
def fetch_okala_vouchers(account_data, cerberus_id):
    token_info = account_data.get("token_info", {})
    access_token = token_info.get("access_token")
    if not access_token or not cerberus_id: return "\n\n⚠️ Invalid session data for Okala."
    
    config = SITE_CONFIGS["okala"]
    voucher_url = f"{config['discounts_url']}/{cerberus_id}"
    headers = {**config["headers"], "Authorization": f"Bearer {access_token}"}
    
    def get_vouchers(session, auth_headers):
        response = session.get(voucher_url, headers=auth_headers)
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
            s.cookies.update(account_data.get("cookies", {}))
            return get_vouchers(s, headers)
    except Exception as e:
        if hasattr(e, 'response') and e.response.status_code == 401:
            return "\n\n⚠️ Okala token may have expired. Please add the account again."
        else:
            raise e

@retry_on_429()
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
        raise e

@retry_on_429()
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
        raise e

# --- Gemini API Logic ---
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
    chat_id = update.effective_chat.id
    if ADMIN_CHAT_ID and str(chat_id) == ADMIN_CHAT_ID and chat_id not in AUTHORIZED_USERS:
        add_authorized_user(chat_id)
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
    chat_id = update.effective_chat.id
    password = update.message.text
    user = update.message.from_user

    if password == BOT_PASSWORD:
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=f"New access request from: {user.full_name} (@{user.username or 'N/A'})\n"
                 f"To approve, reply with: `/approve {user.id}`"
        )
        await update.message.reply_text("✅ Your access request has been sent to the admin for approval.")
    else:
        await update.message.reply_text("❌ Incorrect password.")
    
    if chat_id in USER_STATE:
        del USER_STATE[chat_id]

@admin_only
async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id_to_approve = int(context.args[0])
        add_authorized_user(user_id_to_approve)
        await context.bot.send_message(chat_id=user_id_to_approve, text="🎉 Your access has been approved! Use /start to begin.")
        await update.message.reply_text(f"✅ User {user_id_to_approve} has been authorized.")
    except (IndexError, ValueError):
        await update.message.reply_text("Usage: /approve <USER_ID>")

# --- Main Logic Handler ---
@authorized
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    text = update.message.text

    if chat_id in USER_STATE:
        state = USER_STATE[chat_id]
        action = state.get("action")

        if action == "awaiting_service":
            if text in VALID_SERVICES:
                USER_STATE[chat_id]["service"] = text
                next_action = state.get("next_action")
                if next_action == "add_account":
                    USER_STATE[chat_id]["action"] = "awaiting_phone"
                    await update.message.reply_text(f"Selected {text}. Please enter the phone number.", reply_markup=ReplyKeyboardRemove())
                elif next_action == "list_accounts": await list_accounts(update, context, text)
                elif next_action == "check_vouchers": await check_vouchers(update, context, text)
                elif next_action == "download_sessions": await download_sessions(update, context, text)
            else:
                await update.message.reply_text("Invalid service. Please select one from the keyboard.")
            return

        elif action == "awaiting_phone":
            phone = format_phone_number(text)
            service = state["service"]
            USER_STATE[chat_id]["phone"] = phone
            if service.lower() in ["snappfood", "okala"]:
                success, error_msg = do_otp_request(phone, service)
                if success:
                    USER_STATE[chat_id]["action"] = "awaiting_otp"
                    await update.message.reply_text("✅ OTP sent. Please reply with the code.")
                else:
                    await update.message.reply_text(error_msg)
                    del USER_STATE[chat_id]
                    await start_command(update, context)
            elif service.lower() == "tapsi":
                await handle_tapsi_phone_input(update, context, phone)
            return

        elif action == "awaiting_otp":
            otp = text.strip()
            service = state["service"]
            phone = state["phone"]
            await update.message.reply_text(f"Verifying OTP for {phone} on {service}...")
            
            message, account_id = "An unknown error occurred.", None
            if service.lower() == "snappfood": message, account_id = do_snappfood_login(phone, otp, chat_id)
            elif service.lower() == "okala": message, account_id = do_okala_login(phone, otp, chat_id)
            elif service.lower() == "tapsi": message, account_id = await handle_tapsi_otp_input(update, context, otp)
            
            await update.message.reply_text(message, parse_mode="Markdown")
            del USER_STATE[chat_id]
            await start_command(update, context)
            return

    if text == BTN_ADD_ACCOUNT:
        USER_STATE[chat_id] = {"action": "awaiting_service", "next_action": "add_account"}
        await ask_for_service(update, context, "What service do you want to add?")
    elif text == BTN_LIST_ACCOUNTS:
        USER_STATE[chat_id] = {"action": "awaiting_service", "next_action": "list_accounts"}
        await ask_for_service(update, context, "List accounts for which service?")
    elif text == BTN_CHECK_VOUCHERS:
        USER_STATE[chat_id] = {"action": "awaiting_service", "next_action": "check_vouchers"}
        await ask_for_service(update, context, "Check vouchers for which service?")
    elif text == BTN_DOWNLOAD_SESSIONS:
        USER_STATE[chat_id] = {"action": "awaiting_service", "next_action": "download_sessions"}
        await ask_for_service(update, context, "Download sessions for which service?")

async def ask_for_service(update: Update, context: ContextTypes.DEFAULT_TYPE, message: str):
    reply_keyboard = [[s] for s in VALID_SERVICES]
    await update.message.reply_text(
        message,
        reply_markup=ReplyKeyboardMarkup(reply_keyboard, one_time_keyboard=True, resize_keyboard=True),
    )

async def list_accounts(update: Update, context: ContextTypes.DEFAULT_TYPE, service: str):
    chat_id = update.effective_chat.id
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT phone_number, id FROM accounts WHERE user_id = ? AND service = ?",
            (chat_id, service.lower())
        )
        accounts = cursor.fetchall()
    
    if not accounts:
        message = f"No accounts saved for {service} yet."
    else:
        message = f"Saved {service} Accounts:\n"
        for phone, acc_id in accounts:
            message += f"- Phone: {phone}\n  ID: `{acc_id}`\n"
    
    await update.message.reply_text(message, parse_mode="Markdown")
    del USER_STATE[chat_id]
    await start_command(update, context)

async def check_vouchers(update: Update, context: ContextTypes.DEFAULT_TYPE, service: str):
    chat_id = update.effective_chat.id
    await update.message.reply_text(f"🔄 Checking all saved accounts for {service}. This may take a moment...")
    
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT phone_number, session_data FROM accounts WHERE user_id = ? AND service = ?",
            (chat_id, service.lower())
        )
        accounts = cursor.fetchall()

    if not accounts:
        await update.message.reply_text(f"No accounts found for {service} to check.")
        del USER_STATE[chat_id]
        await start_command(update, context)
        return

    full_message = f"--- 📜 Report for {service} Accounts ---\n"
    for phone_number, session_json in accounts:
        full_message += f"\n\n**Checking Account: `{phone_number}`**"
        try:
            session_data = json.loads(session_json)
            if service == "Snappfood":
                full_message += fetch_snappfood_vouchers(session_data)
            elif service == "Okala":
                cerberus_id = session_data.get("token_info", {}).get("cerberusId")
                full_message += fetch_okala_vouchers(session_data, cerberus_id)
            elif service == "Tapsi":
                cookies_dict = {c["name"]: c["value"] for c in session_data}
                access_token = cookies_dict.get("accessToken")
                if access_token:
                    full_message += fetch_tapsi_rewards(access_token, cookies_dict)
                else:
                    full_message += "\n❌ Could not find accessToken in session file."
        except Exception as e:
            full_message += f"\n❌ An error occurred: {e}"
            sentry_sdk.capture_exception(e)
        
        time.sleep(1.5)

    await update.message.reply_text(full_message, parse_mode="Markdown")
    del USER_STATE[chat_id]
    await start_command(update, context)

async def download_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE, service: str):
    chat_id = update.effective_chat.id
    
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, session_data FROM accounts WHERE user_id = ? AND service = ?", (chat_id, service.lower()))
        accounts = cursor.fetchall()

    if not accounts:
        await update.message.reply_text(f"No accounts saved for {service} yet.")
        del USER_STATE[chat_id]
        await start_command(update, context)
        return

    temp_dir = os.path.join(BASE_DATA_DIR, str(chat_id), "temp_download")
    os.makedirs(temp_dir, exist_ok=True)
    
    for acc_id, session_json in accounts:
        with open(os.path.join(temp_dir, f"{acc_id}.json"), "w") as f:
            f.write(session_json)

    zip_path_base = os.path.join(BASE_DATA_DIR, str(chat_id), f"{service.lower()}_sessions_backup")
    shutil.make_archive(zip_path_base, "zip", temp_dir)
    shutil.rmtree(temp_dir)
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
        return "❌ Your Tapsi session has expired. Please try again.", None
    
    driver = session_data["driver"]
    phone = USER_STATE[chat_id]["phone"]
    message, account_id = "", None
    try:
        wait = WebDriverWait(driver, 15)
        otp_inputs = wait.until(EC.presence_of_all_elements_located((By.XPATH, "//div[starts-with(@id, 'INPUT_DIGIT_NUMBER_CONTAINER')]/input")))
        for i in range(5):
            otp_inputs[i].send_keys(otp_code[i])
            time.sleep(0.1)

        wait.until(EC.element_to_be_clickable((By.XPATH, "//button[@type='button' and not(@disabled)]"))).click()
        wait.until(EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'سرویس‌ها')]")))

        browser_cookies = driver.get_cookies()
        access_token = next((c['value'] for c in browser_cookies if c['name'] == 'accessToken'), None)

        if access_token:
            account_id = save_account_to_db(chat_id, "tapsi", phone, browser_cookies)
            message = f"✅ Tapsi session saved for {phone}!\n\nYour Unique Account ID is:\n`{account_id}`"
            message += fetch_tapsi_rewards(access_token, {c["name"]: c["value"] for c in browser_cookies})
        else:
            message = "❌ Login successful, but could not find accessToken cookie."
    except Exception as e:
        sentry_sdk.capture_exception(e)
        message = f"❌ Tapsi login failed. Error: {e}"
    finally:
        driver.quit()
        if chat_id in active_tapsi_sessions:
            del active_tapsi_sessions[chat_id]
    return message, account_id

# --- Admin Commands & Cleanup ---
@admin_only
async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = (
        "--- Admin Panel ---\n\n"
        "**Available Admin Commands:**\n"
        "- `/admin`: Shows this panel.\n"
        "- `/approve <USER_ID>`: Authorizes a new user.\n"
        "- `/gemini [prompt]`: Query the Gemini API.\n"
        "- `/migrate`: Convert old JSON session files to the new SQLite DB. **Run only once!**"
    )
    await update.message.reply_text(message, parse_mode='Markdown')

@admin_only
async def gemini_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    prompt = " ".join(context.args)
    if not prompt:
        await update.message.reply_text("Usage: `/gemini How does AI work?`")
        return
    await update.message.reply_text("🧠 Querying Gemini API, please wait...")
    response_text = call_gemini_api(prompt)
    await update.message.reply_text(response_text)

@admin_only
async def migrate_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Starting migration from JSON files to SQLite DB...")

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM accounts")
        count = cursor.fetchone()[0]
        if count > 0:
            await update.message.reply_text("❌ Migration failed: The 'accounts' table is not empty. Migration can only be run on a fresh database.")
            return

    migrated_count = 0
    error_count = 0
    old_data_dir = "user_data"

    if not os.path.isdir(old_data_dir):
        await update.message.reply_text("⚠️ No 'user_data' directory found to migrate from.")
        return

    for user_id_str in os.listdir(old_data_dir):
        user_path = os.path.join(old_data_dir, user_id_str)
        if not os.path.isdir(user_path):
            continue
        try:
            user_id = int(user_id_str)
            for service_dir_name in os.listdir(user_path):
                service_path = os.path.join(user_path, service_dir_name)
                if not os.path.isdir(service_path) or not service_dir_name.endswith("_sessions"):
                    continue
                
                service = service_dir_name.replace("_sessions", "")
                if service not in [s.lower() for s in VALID_SERVICES]:
                    continue

                for filename in os.listdir(service_path):
                    if not filename.endswith(".json"):
                        continue
                    
                    try:
                        phone_number = filename.split("_")[0]
                        file_path = os.path.join(service_path, filename)
                        with open(file_path, 'r') as f:
                            session_data = json.load(f)
                        
                        save_account_to_db(user_id, service, phone_number, session_data)
                        migrated_count += 1
                        logging.info(f"Migrated {service} account for user {user_id}, phone {phone_number}")
                    except Exception as e:
                        error_count += 1
                        logging.error(f"Failed to migrate file {filename} for user {user_id}: {e}")

        except (ValueError, TypeError):
            logging.warning(f"Skipping non-integer directory name: {user_id_str}")
            continue

    report = f"✅ Migration Complete!\n\n- Successfully migrated accounts: {migrated_count}\n- Failed files: {error_count}"
    await update.message.reply_text(report)


def cleanup_old_sessions():
    while True:
        try:
            for chat_id in list(active_tapsi_sessions.keys()):
                session_data = active_tapsi_sessions.get(chat_id)
                if session_data and (datetime.now() - session_data["timestamp"]) > SESSION_TIMEOUT:
                    logging.info(f"Cleaning up expired session for chat_id: {chat_id}")
                    try:
                        session_data["driver"].quit()
                    except WebDriverException as e:
                        logging.error(f"Error quitting expired driver for {chat_id}: {e}")
                    active_tapsi_sessions.pop(chat_id, None)
        except Exception as e:
            logging.error(f"Error in cleanup thread: {e}")
            sentry_sdk.capture_exception(e)
        time.sleep(60)

# --- Main Bot Function ---
def main():
    init_db()
    load_authorized_users()
    
    if not all([TELEGRAM_TOKEN, ADMIN_CHAT_ID, BOT_PASSWORD]):
        logging.warning("One or more critical environment variables are not set.")

    cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
    cleanup_thread.start()

    application = Application.builder().token(TELEGRAM_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("approve", approve_command))
    application.add_handler(CommandHandler("admin", admin_command))
    application.add_handler(CommandHandler("gemini", gemini_command))
    application.add_handler(CommandHandler("migrate", migrate_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_universal_text))

    logging.info("Bot is starting with DB and new command-based flow...")
    application.run_polling()

async def handle_universal_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if USER_STATE.get(chat_id, {}).get("action") == "awaiting_password":
        await handle_password_submission(update, context)
    elif chat_id in AUTHORIZED_USERS:
        await handle_message(update, context)
    else:
        await update.message.reply_text("Please use /start to begin.")

if __name__ == "__main__":
    main()
