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
from curl_cffi.requests import Session as CurlSession, HTTPError
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
# Make sure to set these in your environment
SENTRY_DSN = os.environ.get("SENTRY_DSN")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")
BOT_PASSWORD = os.environ.get("BOT_PASSWORD") # Add a password for the bot

# --- Sentry Initialization ---
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=1.0)

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
                AUTHORIZED_USERS = set(user_ids)
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
        "refresh_url": "https://www.okala.com/api/v3/user/token", # Assuming refresh uses the same endpoint
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

# Conversation states
(
    SELECTING_ACTION,
    SELECTING_SERVICE,
    ENTERING_PHONE,
    ENTERING_OTP,
    SELECTING_SERVICE_FOR_LIST,
    SELECTING_SERVICE_FOR_CHECK,
    SELECTING_SERVICE_FOR_DOWNLOAD,
    SELECTING_ACCOUNT_FOR_DOWNLOAD,
    AWAITING_PASSWORD, # New state for authorization
) = range(9)


# --- Helper & Path Functions ---
def get_user_dir(chat_id, service):
    path = os.path.join(BASE_DATA_DIR, str(chat_id), f"{service}_sessions")
    os.makedirs(path, exist_ok=True)
    return path


def format_phone_number(phone):
    return "0" + phone if not phone.startswith("0") else phone


# --- Snappfood & Okala Logic ---
def do_otp_request(phone_number, service):
    """Sends OTP for Snappfood or Okala."""
    config = SITE_CONFIGS[service]
    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(config.get("headers", {}))
            if service == "snappfood":
                params = {
                    "client": "WEBSITE",
                    "deviceType": "WEBSITE",
                    "appVersion": "8.1.1",
                    "UDID": str(uuid.uuid4()),
                    "locale": "fa",
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
    """Performs login for Snappfood, saves session (token+cookies), and fetches vouchers."""
    try:
        with CurlSession(impersonate="chrome120") as session:
            base_headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            session.headers.update(
                {**base_headers, **SITE_CONFIGS["snappfood"].get("headers", {})}
            )
            params = {
                "client": "WEBSITE",
                "deviceType": "WEBSITE",
                "appVersion": "8.1.1",
                "UDID": str(uuid.uuid4()),
                "locale": "fa",
            }
            payload = {"cellphone": phone_number, "code": otp_code}
            response = session.post(
                SITE_CONFIGS["snappfood"]["login_url"], params=params, data=payload
            )
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
            with open(
                os.path.join(sessions_dir, f"{phone_number}_session.json"), "w"
            ) as f:
                json.dump(account_data, f)
            message = f"✅ Snappfood session saved for {phone_number}."
            vouchers_message = fetch_snappfood_vouchers(account_data)
            return message + vouchers_message
    except Exception as e:
        logging.error(f"Error during Snappfood login for {phone_number}: {e}")
        sentry_sdk.capture_exception(e)
        return f"❌ An error occurred during Snappfood login."


def do_okala_login(phone_number, otp_code, chat_id):
    """Performs login for Okala, saves token, and fetches vouchers."""
    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(SITE_CONFIGS["okala"].get("headers", {}))
            payload = {"mobile": phone_number, "code": otp_code}
            r = s.post(SITE_CONFIGS["okala"]["login_url"], json=payload)
            r.raise_for_status()
            data = r.json()
            if access_token := data.get("access_token"):
                token_info = {
                    "token_type": "bearer",
                    "access_token": access_token,
                    "refresh_token": data.get("refresh_token"),
                }
                sessions_dir = get_user_dir(chat_id, "okala")
                with open(
                    os.path.join(sessions_dir, f"{phone_number}_tokens.json"), "w"
                ) as f:
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
    """Refreshes the Okala access token using the refresh token."""
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

            # Update token_info with new tokens
            token_info["access_token"] = new_access_token
            token_info["refresh_token"] = data.get("refresh_token", refresh_token) # Preserve old if not updated
            
            # Save updated tokens to file
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
    """Fetches Okala vouchers, refreshing the token if it has expired."""
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
                return f"\n\n{refresh_message}" # Return the error from the refresh attempt
        else:
            logging.error(f"Failed to fetch Okala vouchers: {e}")
            return f"\n\n⚠️ Could not fetch Okala vouchers. Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected error fetching Okala vouchers: {e}")
        return f"\n\n⚠️ Unexpected error fetching Okala vouchers: {e}"


def fetch_snappfood_vouchers(account_data):
    """Fetches Snappfood vouchers using a saved session (token + cookies)."""
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
                "Origin": "https://snappfood.ir",
                "Referer": "https://snappfood.ir/",
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
    """Acts as a gatekeeper, checking authorization before showing the main menu."""
    chat_id = update.message.chat_id

    # The admin is always authorized and is added to the set on first start
    if ADMIN_CHAT_ID and str(chat_id) == ADMIN_CHAT_ID:
        if chat_id not in AUTHORIZED_USERS:
            AUTHORIZED_USERS.add(chat_id)
            save_authorized_users()
            logging.info(f"Admin user {chat_id} auto-authorized.")

    if chat_id in AUTHORIZED_USERS:
        keyboard = [
            [InlineKeyboardButton("➕ Add Account", callback_data="add_account")],
            [InlineKeyboardButton("📋 List Accounts", callback_data="list_accounts")],
            [InlineKeyboardButton("🔄 Check Vouchers", callback_data="check_vouchers")],
            [
                InlineKeyboardButton(
                    "💾 Download Sessions", callback_data="download_sessions"
                )
            ],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(
            "Welcome! Please choose an action:", reply_markup=reply_markup
        )
        return SELECTING_ACTION
    else:
        await update.message.reply_text(
            "Welcome! This is a private bot. Please enter the password to request access."
        )
        return AWAITING_PASSWORD


async def handle_password_submission(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Checks the submitted password and requests admin approval."""
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
    """Handles the admin's 'Approve' or 'Deny' button press for user access."""
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


async def ask_for_service(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Asks the user to select a service."""
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


async def ask_for_phone(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Asks for the user's phone number."""
    query = update.callback_query
    await query.answer()
    service = query.data
    context.user_data["service"] = service

    await query.edit_message_text(
        text=f"Selected {service.capitalize()}. Please enter your phone number (e.g., 09123456789)."
    )
    return ENTERING_PHONE


async def handle_phone_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handles the phone number and initiates OTP request."""
    phone = format_phone_number(update.message.text)
    service = context.user_data["service"]
    chat_id = update.message.chat_id
    context.user_data["phone"] = phone

    if service in ["snappfood", "okala"]:
        await update.message.reply_text(
            f"Requesting OTP for {phone} on {service.capitalize()}..."
        )
        success = do_otp_request(phone, service)
        if success:
            await update.message.reply_text(
                f"✅ OTP sent successfully. Please reply with the code."
            )
            return ENTERING_OTP
        else:
            await update.message.reply_text(
                f"❌ Failed to send OTP for {service.capitalize()}. Please try again."
            )
            return ConversationHandler.END

    elif service == "tapsi":
        await update.message.reply_text("🚀 Starting Tapsi login... Please wait.")
        if chat_id in active_tapsi_sessions:
            try:
                active_tapsi_sessions[chat_id]["driver"].quit()
            except WebDriverException:
                pass
            del active_tapsi_sessions[chat_id]

        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument(
            "user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        )
        driver = None
        try:
            service_obj = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service_obj, options=chrome_options)
            wait = WebDriverWait(driver, 40)
            driver.get(SITE_CONFIGS["tapsi"]["login_page"])
            wait.until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, "input[type='tel']"))
            ).send_keys(phone)
            wait.until(
                EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'دریافت کد')]"))
            ).click()
            active_tapsi_sessions[chat_id] = {
                "driver": driver,
                "timestamp": datetime.now(),
            }
            await update.message.reply_text(
                f"✅ OTP sent by Tapsi to {phone}. Please reply with the 5-digit code.\n\n_This session will expire in 5 minutes._",
                parse_mode="Markdown",
            )
            return ENTERING_OTP
        except Exception as e:
            if driver:
                driver.quit()
            await update.message.reply_text(f"❌ Failed to start Tapsi login. Error: {e}")
            sentry_sdk.capture_exception(e)
            return ConversationHandler.END


async def handle_otp_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handles the OTP code and finalizes the login."""
    chat_id = update.message.chat_id
    otp_code = update.message.text.strip()
    service = context.user_data["service"]
    phone = context.user_data["phone"]
    await update.message.reply_text(
        f"Verifying OTP for {phone} on {service.capitalize()}..."
    )

    message = "An unknown error occurred."
    if service == "snappfood":
        message = do_snappfood_login(phone, otp_code, chat_id)
    elif service == "okala":
        message = do_okala_login(phone, otp_code, chat_id)
    elif service == "tapsi":
        session_data = active_tapsi_sessions.get(chat_id)
        if not session_data:
            message = "❌ Your Tapsi session has expired. Please try again."
        else:
            driver = session_data["driver"]
            try:
                wait = WebDriverWait(driver, 15)
                otp_inputs = wait.until(
                    EC.presence_of_all_elements_located(
                        (By.XPATH, "//div[starts-with(@id, 'INPUT_DIGIT_NUMBER_CONTAINER')]/input")
                    )
                )
                if len(otp_inputs) >= 5 and len(otp_code) == 5:
                    for i in range(5):
                        otp_inputs[i].send_keys(otp_code[i])
                        time.sleep(0.1)
                else:
                    raise Exception("Could not find the 5 separate OTP input boxes.")

                wait.until(
                    EC.element_to_be_clickable(
                        (By.XPATH, "//button[@type='button' and not(@disabled)]")
                    )
                ).click()
                wait.until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'سرویس‌ها')]")
                    )
                )

                sessions_dir = get_user_dir(chat_id, "tapsi")
                cookie_file_path = os.path.join(sessions_dir, f"{phone}_cookies.json")
                browser_cookies = {c["name"]: c["value"] for c in driver.get_cookies()}
                access_token = browser_cookies.get("accessToken")

                if access_token:
                    with open(cookie_file_path, "w") as f:
                        json.dump(driver.get_cookies(), f)
                    message = f"✅ Tapsi session saved for {phone}!"
                    rewards_message = fetch_tapsi_rewards(
                        access_token, browser_cookies
                    )
                    message += rewards_message
                else:
                    message = "❌ Login successful, but could not find accessToken cookie."
            except Exception as e:
                sentry_sdk.capture_exception(e)
                message = f"❌ Tapsi login failed. Error: {e}"
            finally:
                driver.quit()
                if chat_id in active_tapsi_sessions:
                    del active_tapsi_sessions[chat_id]

    await update.message.reply_text(message, parse_mode="Markdown")
    context.user_data.clear()
    return ConversationHandler.END


async def list_accounts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles the 'list_accounts' button press."""
    query = update.callback_query
    await query.answer()
    service = query.data
    chat_id = query.message.chat_id

    if service == "main_menu":
        return await back_to_main_menu(update, context)

    sessions_dir = get_user_dir(chat_id, service)
    extension = (
        "_session.json"
        if service == "snappfood"
        else "_cookies.json"
        if service == "tapsi"
        else "_tokens.json"
    )
    accounts = [
        f.replace(extension, "")
        for f in os.listdir(sessions_dir)
        if f.endswith(extension)
    ]

    if not accounts:
        message = f"No accounts saved for {service.capitalize()} yet."
    else:
        message = f"Saved {service.capitalize()} Accounts:\n- " + "\n- ".join(
            sorted(accounts)
        )

    keyboard = [[InlineKeyboardButton("« Back", callback_data="list_accounts_back")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(text=message, reply_markup=reply_markup)
    return SELECTING_SERVICE


async def check_vouchers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles the 'check_vouchers' button press and checks all accounts for a service."""
    query = update.callback_query
    await query.answer()
    service = query.data
    chat_id = query.message.chat_id

    if service == "main_menu":
        return await back_to_main_menu(update, context)

    sessions_dir = get_user_dir(chat_id, service)
    extension = (
        "_session.json"
        if service == "snappfood"
        else "_cookies.json"
        if service == "tapsi"
        else "_tokens.json"
    )
    account_files = [f for f in os.listdir(sessions_dir) if f.endswith(extension)]

    if not account_files:
        await query.edit_message_text(f"No accounts found for {service} to check.")
        return SELECTING_SERVICE

    await query.edit_message_text(
        f"🔄 Checking all {len(account_files)} saved account(s) for {service}. This may take a moment..."
    )

    full_message = f"--- 📜 Report for {service.capitalize()} Accounts ---\n"
    for filename in sorted(account_files):
        phone_number = filename.replace(extension, "")
        file_path = os.path.join(sessions_dir, filename)
        full_message += f"\n\n**Checking Account: `{phone_number}`**"
        try:
            if service == "snappfood":
                with open(file_path, "r") as f:
                    account_data = json.load(f)
                full_message += fetch_snappfood_vouchers(account_data)
            elif service == "okala":
                with open(file_path, "r") as f:
                    token_info = json.load(f)
                # Pass phone_number and chat_id for potential token refresh
                full_message += fetch_okala_vouchers(token_info, phone_number, chat_id)
            elif service == "tapsi":
                with open(file_path, "r") as f:
                    cookies_list = json.load(f)
                cookies_dict = {c["name"]: c["value"] for c in cookies_list}
                access_token = cookies_dict.get("accessToken")
                if access_token:
                    full_message += fetch_tapsi_rewards(access_token, cookies_dict)
                else:
                    full_message += "\n❌ Could not find accessToken in session file."
        except Exception as e:
            full_message += f"\n❌ An error occurred: {e}"
            sentry_sdk.capture_exception(e)

    # Send the potentially long message in chunks
    for i in range(0, len(full_message), 4096):
        await context.bot.send_message(
            chat_id=chat_id, text=full_message[i : i + 4096], parse_mode="Markdown"
        )

    # After sending the report, show the menu again
    keyboard = [[InlineKeyboardButton("« Back", callback_data="check_vouchers_back")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(
        chat_id=chat_id, text="Check complete.", reply_markup=reply_markup
    )
    return SELECTING_SERVICE


async def ask_for_download_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Asks to download one or all sessions for a service."""
    query = update.callback_query
    await query.answer()
    service = query.data
    context.user_data["service"] = service

    if service == "main_menu":
        return await back_to_main_menu(update, context)

    keyboard = [
        [InlineKeyboardButton("Download One Account", callback_data="download_one")],
        [InlineKeyboardButton("Download All (ZIP)", callback_data="download_all")],
        [InlineKeyboardButton("« Back", callback_data="download_sessions_back")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(
        text=f"Download options for {service.capitalize()}:",
        reply_markup=reply_markup,
    )
    return SELECTING_SERVICE_FOR_DOWNLOAD


async def ask_for_account_to_download(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Shows a list of accounts to download."""
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    service = context.user_data["service"]

    sessions_dir = get_user_dir(chat_id, service)
    extension = (
        "_session.json"
        if service == "snappfood"
        else "_cookies.json"
        if service == "tapsi"
        else "_tokens.json"
    )
    accounts = [
        f.replace(extension, "")
        for f in os.listdir(sessions_dir)
        if f.endswith(extension)
    ]

    if not accounts:
        await query.edit_message_text(f"No accounts saved for {service} yet.")
        return SELECTING_SERVICE_FOR_DOWNLOAD

    keyboard = [
        [InlineKeyboardButton(acc, callback_data=f"dl_{acc}")] for acc in sorted(accounts)
    ]
    keyboard.append([InlineKeyboardButton("« Back", callback_data="back_to_dl_type")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(
        text=f"Select account to download for {service.capitalize()}:",
        reply_markup=reply_markup,
    )
    return SELECTING_ACCOUNT_FOR_DOWNLOAD


async def download_one_session(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Sends the selected session file."""
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    service = context.user_data["service"]
    phone = query.data.split("_")[1]

    extension = (
        "_session.json"
        if service == "snappfood"
        else "_cookies.json"
        if service == "tapsi"
        else "_tokens.json"
    )
    file_path = os.path.join(get_user_dir(chat_id, service), f"{phone}{extension}")

    if os.path.exists(file_path):
        await query.message.reply_text(
            f"Sending session file for {phone}..."
        )
        with open(file_path, "rb") as doc:
            await context.bot.send_document(chat_id=chat_id, document=doc)
    else:
        await query.message.reply_text(f"❌ Could not find session for {phone}.")

    # Go back to download type selection
    return await ask_for_download_type(update, context)


async def download_all_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Zips and sends all sessions for a service."""
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    service = context.user_data["service"]

    sessions_dir = get_user_dir(chat_id, service)
    if not any(os.scandir(sessions_dir)):
        await query.edit_message_text(f"No accounts saved for {service} yet.")
        return SELECTING_SERVICE_FOR_DOWNLOAD

    zip_path_base = os.path.join(BASE_DATA_DIR, str(chat_id), f"{service}_sessions_backup")
    shutil.make_archive(zip_path_base, "zip", sessions_dir)
    zip_path = f"{zip_path_base}.zip"

    await query.message.reply_text(
        f"Sending a zip file with all your saved {service} sessions..."
    )
    with open(zip_path, "rb") as doc:
        await context.bot.send_document(
            chat_id=chat_id, document=doc, filename=f"{service}_sessions.zip"
        )

    os.remove(zip_path)
    # Go back to download type selection
    return await ask_for_download_type(update, context)


async def back_to_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Returns to the main menu."""
    query = update.callback_query
    await query.answer()
    keyboard = [
        [InlineKeyboardButton("➕ Add Account", callback_data="add_account")],
        [InlineKeyboardButton("📋 List Accounts", callback_data="list_accounts")],
        [InlineKeyboardButton("🔄 Check Vouchers", callback_data="check_vouchers")],
        [
            InlineKeyboardButton(
                "💾 Download Sessions", callback_data="download_sessions"
            )
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(
        "Welcome! Please choose an action:", reply_markup=reply_markup
    )
    return SELECTING_ACTION


async def cancel_conversation(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    """Cancels and ends the conversation."""
    await update.message.reply_text("Action canceled.")
    context.user_data.clear()
    return ConversationHandler.END


# --- Admin Command ---
async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to see bot usage."""
    chat_id = str(update.message.chat_id)
    if not ADMIN_CHAT_ID or chat_id != ADMIN_CHAT_ID:
        await update.message.reply_text("You are not authorized to use this command.")
        return

    try:
        user_dirs = [d for d in os.listdir(BASE_DATA_DIR) if os.path.isdir(os.path.join(BASE_DATA_DIR, d))]
        if not user_dirs:
            await update.message.reply_text("No user data found yet.")
            return
        
        message = "Bot users (by chat_id):\n"
        for user_id in user_dirs:
            auth_status = "✅" if int(user_id) in AUTHORIZED_USERS else "⏳"
            message += f"- `{user_id}` {auth_status}\n"
        await update.message.reply_text(message, parse_mode='Markdown')

    except Exception as e:
        await update.message.reply_text(f"An error occurred: {e}")
        sentry_sdk.capture_exception(e)


# --- Cleanup Thread for Tapsi Sessions (Unchanged) ---
def cleanup_old_sessions():
    while True:
        try:
            for chat_id in list(active_tapsi_sessions.keys()):
                session_data = active_tapsi_sessions.get(chat_id)
                if session_data and (
                    datetime.now() - session_data["timestamp"]
                ) > SESSION_TIMEOUT:
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
    if not TELEGRAM_TOKEN:
        logging.error("TELEGRAM_TOKEN environment variable not set! Exiting.")
        return
    if not ADMIN_CHAT_ID:
        logging.warning("ADMIN_CHAT_ID environment variable not set. Admin approval disabled.")
    if not BOT_PASSWORD:
        logging.warning("BOT_PASSWORD environment variable not set. Bot is open to public.")

    # Load authorized users from file on startup
    load_authorized_users()

    cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
    cleanup_thread.start()
    logging.info("Session cleanup thread started.")

    application = Application.builder().token(TELEGRAM_TOKEN).build()

    # Conversation handler for adding accounts
    add_conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(ask_for_service, pattern="^add_account$")],
        states={
            SELECTING_SERVICE: [
                CallbackQueryHandler(ask_for_phone, pattern="^(snappfood|okala|tapsi)$")
            ],
            ENTERING_PHONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_phone_input)],
            ENTERING_OTP: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_otp_input)],
        },
        fallbacks=[
            CommandHandler("cancel", cancel_conversation),
            CallbackQueryHandler(back_to_main_menu, pattern="^main_menu$"),
        ],
        map_to_parent={
            ConversationHandler.END: SELECTING_ACTION
        },
    )

    # Handlers for listing accounts
    list_conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(ask_for_service, pattern="^list_accounts$")],
        states={
            SELECTING_SERVICE: [
                CallbackQueryHandler(list_accounts, pattern="^(snappfood|okala|tapsi)$"),
                CallbackQueryHandler(ask_for_service, pattern="^list_accounts_back$")
            ]
        },
        fallbacks=[CallbackQueryHandler(back_to_main_menu, pattern="^main_menu$")],
        map_to_parent={ConversationHandler.END: SELECTING_ACTION},
    )

    # Handlers for checking vouchers
    check_conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(ask_for_service, pattern="^check_vouchers$")],
        states={
            SELECTING_SERVICE: [
                CallbackQueryHandler(check_vouchers, pattern="^(snappfood|okala|tapsi)$"),
                CallbackQueryHandler(ask_for_service, pattern="^check_vouchers_back$")
            ]
        },
        fallbacks=[CallbackQueryHandler(back_to_main_menu, pattern="^main_menu$")],
        map_to_parent={ConversationHandler.END: SELECTING_ACTION},
    )
    
    # Handlers for downloading sessions
    download_conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(ask_for_service, pattern="^download_sessions$")],
        states={
            SELECTING_SERVICE: [
                CallbackQueryHandler(ask_for_download_type, pattern="^(snappfood|okala|tapsi)$")
            ],
            SELECTING_SERVICE_FOR_DOWNLOAD: [
                CallbackQueryHandler(ask_for_account_to_download, pattern="^download_one$"),
                CallbackQueryHandler(download_all_sessions, pattern="^download_all$"),
                CallbackQueryHandler(ask_for_service, pattern="^download_sessions_back$")
            ],
            SELECTING_ACCOUNT_FOR_DOWNLOAD: [
                CallbackQueryHandler(download_one_session, pattern="^dl_"),
                CallbackQueryHandler(ask_for_download_type, pattern="^back_to_dl_type$")
            ]
        },
        fallbacks=[CallbackQueryHandler(back_to_main_menu, pattern="^main_menu$")],
        map_to_parent={ConversationHandler.END: SELECTING_ACTION},
    )

    # Main handler that routes all interactions, starting with authorization check
    main_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start_command)],
        states={
            AWAITING_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_password_submission)
            ],
            SELECTING_ACTION: [
                add_conv_handler,
                list_conv_handler,
                check_conv_handler,
                download_conv_handler,
                CallbackQueryHandler(back_to_main_menu, pattern="^main_menu$"),
            ]
        },
        fallbacks=[CommandHandler("start", start_command)],
    )

    application.add_handler(main_handler)
    application.add_handler(CommandHandler("admin", admin_command))
    # Add the handler for admin decisions on user access
    application.add_handler(CallbackQueryHandler(handle_admin_decision, pattern="^(approve_|deny_)"))


    logging.info("Bot is starting with new authorization flow...")
    application.run_polling()


if __name__ == "__main__":
    main()
