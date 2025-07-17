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
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from curl_cffi.requests import Session as CurlSession
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

# --- Configuration ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
SENTRY_DSN = os.environ.get('SENTRY_DSN')
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN')

# --- Sentry Initialization ---
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=1.0)

# --- Global Configs & State ---
SITE_CONFIGS = {
    "snappfood": {
        "name": "Snappfood",
        "otp_url": "https://snappfood.ir/mobile/v4/user/loginMobileWithNoPass",
        "login_url": "https://snappfood.ir/mobile/v2/user/loginMobileWithToken",
        "discounts_url": "https://snappfood.ir/mobile/v2/user/activeVouchers",
        "headers": { "Content-Type": "application/x-www-form-urlencoded" }
    },
    "okala": {
        "name": "Okala",
        "otp_url": "https://www.okala.com/api/v3/user/otp",
        "login_url": "https://www.okala.com/api/v3/user/token",
        "discounts_url": "https://www.okala.com/api/v3/user/vouchers",
        "headers": { "Content-Type": "application/json" }
    },
    "tapsi": {
        "name": "Tapsi",
        "login_page": "https://accounts.tapsi.ir/login?client_id=tapsi.cab.passenger&redirect_uri=https%3A%2F%2Fapp.tapsi.cab&response_type=code&scope=PASSENGER&state=be452b2200ac4ce5811b2add151cb007&code_challenge=CAajCXZFhHghxOtE9aIDvj5OmzYOsAumA-MO_5DtpOM&code_challenge_method=S256&response_mode=query",
        "rewards_url": "https://api.tapsi.cab/api/v2/reward/userReward"
    }
}
BASE_DATA_DIR = "user_data"
user_states = {}
active_tapsi_sessions = {}
SESSION_TIMEOUT = timedelta(minutes=5)
VALID_SERVICES = ['snappfood', 'tapsi', 'okala']

# --- Helper & Path Functions ---
def get_user_dir(chat_id, service):
    path = os.path.join(BASE_DATA_DIR, str(chat_id), f"{service}_sessions")
    os.makedirs(path, exist_ok=True)
    return path

def format_phone_number(phone):
    return '0' + phone if not phone.startswith('0') else phone

# --- Snappfood & Okala Logic ---
def do_otp_request(phone_number, service):
    """Sends OTP for Snappfood or Okala."""
    config = SITE_CONFIGS[service]
    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(config.get("headers", {}))
            if service == 'snappfood':
                params = { "client": "WEBSITE", "deviceType": "WEBSITE", "appVersion": "8.1.1", "UDID": str(uuid.uuid4()), "locale": "fa" }
                payload = {"cellphone": phone_number}
                r = s.post(config['otp_url'], params=params, data=payload)
            elif service == 'okala':
                payload = {"mobile": phone_number}
                r = s.post(config['otp_url'], json=payload)
            r.raise_for_status()
            return True
    except Exception as e:
        logging.error(f"{service.capitalize()} OTP request failed: {e}")
        sentry_sdk.capture_exception(e)
        return False

def do_login(phone_number, otp_code, service, chat_id):
    """Handles login for Snappfood and Okala, then fetches vouchers."""
    if service == 'snappfood':
        return do_snappfood_login(phone_number, otp_code, chat_id)
    elif service == 'okala':
        return do_okala_login(phone_number, otp_code, chat_id)
    return "❌ Unsupported service for this login function."

def do_snappfood_login(phone_number, otp_code, chat_id):
    """Performs login for Snappfood, saves session (token+cookies), and fetches vouchers."""
    try:
        with CurlSession(impersonate="chrome120") as session:
            # Set base headers
            base_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            session.headers.update({**base_headers, **SITE_CONFIGS['snappfood'].get("headers", {})})

            # Login request
            params = {"client": "WEBSITE", "deviceType": "WEBSITE", "appVersion": "8.1.1", "UDID": str(uuid.uuid4()), "locale": "fa"}
            payload = {"cellphone": phone_number, "code": otp_code}
            response = session.post(SITE_CONFIGS['snappfood']['login_url'], params=params, data=payload)
            response.raise_for_status()
            data = response.json()

            # Extract token
            token_data = data.get("data", {})
            token = token_data.get("oauth2_token", {}).get("access_token")
            token_type = 'bearer' if token else 'nested'
            if not token:
                token = token_data.get("nested_jwt")
            if not token:
                return "❌ CRITICAL: Could not find token in login response."

            # **Save both token and cookies**
            token_info = {"token": token, "token_type": token_type}
            cookies = dict(session.cookies)
            account_data = {"token_info": token_info, "cookies": cookies}

            sessions_dir = get_user_dir(chat_id, 'snappfood')
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
    """Performs login for Okala, saves token, and fetches vouchers."""
    try:
        with CurlSession(impersonate="chrome120") as s:
            payload = {"mobile": phone_number, "code": otp_code}
            r = s.post(SITE_CONFIGS['okala']['login_url'], json=payload)
            r.raise_for_status()
            data = r.json()

            if access_token := data.get('access_token'):
                token_info = {"token_type": "bearer", "access_token": access_token, "refresh_token": data.get('refresh_token')}
                sessions_dir = get_user_dir(chat_id, 'okala')
                with open(os.path.join(sessions_dir, f"{phone_number}_tokens.json"), "w") as f:
                    json.dump(token_info, f)

                message = f"✅ Okala session saved for {phone_number}."
                vouchers_message = fetch_okala_vouchers(token_info)
                return message + vouchers_message
            else:
                return "❌ CRITICAL: Could not find token in Okala login response."
    except Exception as e:
        logging.error(f"Error during Okala login for {phone_number}: {e}")
        return f"❌ An error occurred during Okala login."


def fetch_snappfood_vouchers(account_data):
    """Fetches Snappfood vouchers using a saved session (token + cookies)."""
    token_info = account_data.get("token_info", {})
    saved_cookies = account_data.get("cookies", {})
    token = token_info.get("token")
    token_type = token_info.get("token_type")

    if not token:
        return "\n\n⚠ Invalid or missing token for Snappfood."

    try:
        with CurlSession(impersonate="chrome120") as session:
            # Set headers
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Origin": "https://snappfood.ir", "Referer": "https://snappfood.ir/"
            }
            if token_type == "bearer":
                headers["Authorization"] = f"Bearer {token}"
            else:
                headers["x-snappfood-token"] = token
            session.headers.update(headers)
            # Load cookies into the session
            session.cookies.update(saved_cookies)

            response = session.get(SITE_CONFIGS['snappfood']['discounts_url'])
            response.raise_for_status()
            data = response.json()

            vouchers = data.get("data", {}).get("vouchers", [])
            if not vouchers: return f"\n\nℹ No active Snappfood vouchers found."
            result = f"\n\n🎁 **Active Snappfood Vouchers:**\n"
            for v in vouchers:
                title = v.get('title', 'N/A')
                code = v.get('customer_code', 'N/A')
                expires = v.get('expired_at', 'N/A')
                result += f"  - **{title}**\n    Code: `{code}`\n    Expires: {expires}\n"
            return result
    except Exception as e:
        logging.error(f"Failed to fetch Snappfood vouchers: {e}")
        return f"\n\n⚠ Could not fetch Snappfood vouchers. Error: {e}"

def fetch_okala_vouchers(token_info):
    """Fetches Okala vouchers using a saved token."""
    access_token = token_info.get("access_token")
    if not access_token:
        return "\n\n⚠ Invalid or missing token for Okala."

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {access_token}"
    }

    try:
        with CurlSession(impersonate="chrome120") as s:
            s.headers.update(headers)
            response = s.get(SITE_CONFIGS['okala']['discounts_url'])
            response.raise_for_status()
            data = response.json()
            vouchers = data.get("data", [])
            if not vouchers: return f"\n\nℹ No active Okala vouchers found."
            result = f"\n\n🎁 **Active Okala Vouchers:**\n"
            for v in vouchers:
                title = v.get('title', 'N/A')
                code = v.get('code', 'N/A')
                desc = v.get('description', 'N/A')
                result += f"  - **{title}**\n    Code: `{code}`\n    Description: {desc}\n"
            return result
    except Exception as e:
        logging.error(f"Failed to fetch Okala vouchers: {e}")
        return f"\n\n⚠ Could not fetch Okala vouchers. Error: {e}"


# --- Tapsi Logic (Unchanged) ---
def fetch_tapsi_rewards(access_token, cookies):
    config = SITE_CONFIGS['tapsi']
    headers = {
        'Authorization': f'Bearer {access_token}',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'
    }
    session = CurlSession(impersonate="chrome120")
    session.headers.update(headers)
    session.cookies.update(cookies)
    try:
        response = session.get(config['rewards_url'])
        response.raise_for_status()
        rewards = response.json().get('data', {}).get('userRewards', [])
        if not rewards:
            return "\n\nℹ No active Tapsi rewards found."

        result = "\n\n🎁 **Active Tapsi Rewards:**\n"
        for r in rewards:
            result += f"  - **{r.get('title')}**\n    {r.get('description')}\n    Expires: {r.get('expiredAt')}\n"
        return result
    except Exception as e:
        logging.error(f"Failed to fetch Tapsi rewards: {e}")
        return f"\n\n⚠ Could not fetch Tapsi rewards. Error: {e}"

# --- Telegram Bot Command Handlers ---
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "Welcome! Here are the available commands:\n\n"
        "**Adding Accounts:**\n"
        "`/add <service> <phone>`\n"
        "Example: `/add snappfood 09123456789`\n\n"
        "**Listing Accounts:**\n"
        "`/list <service>`\n"
        "Example: `/list tapsi`\n\n"
        "**Checking All Accounts:**\n"
        "`/check_all <service>`\n"
        "Example: `/check_all snappfood`\n\n"
        "**Downloading Sessions:**\n"
        "`/download <service> <phone>`\n"
        "`/download_all <service>`\n\n"
        "**Available Services:**\n"
        "`snappfood`, `tapsi`, `okala`"
    )
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def add_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    try:
        service_name = context.args[0].lower()
        phone = format_phone_number(context.args[1])
        if service_name not in VALID_SERVICES:
            await update.message.reply_text(f"Invalid service. Please choose from: {', '.join(VALID_SERVICES)}.")
            return

        user_states[chat_id] = {'service': service_name, 'phone': phone}

        if service_name in ['snappfood', 'okala']:
            await update.message.reply_text(f"Requesting OTP for {phone} on {service_name.capitalize()}...")
            success = do_otp_request(phone, service_name)
            await update.message.reply_text(f"✅ OTP sent successfully. Please reply with the code." if success else f"❌ Failed to send OTP for {service_name.capitalize()}.")

        elif service_name == 'tapsi':
            await update.message.reply_text("🚀 Starting Tapsi login... Please wait.")
            if chat_id in active_tapsi_sessions:
                try: active_tapsi_sessions[chat_id]['driver'].quit()
                except WebDriverException: pass
                del active_tapsi_sessions[chat_id]

            chrome_options = Options()
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
            driver = None
            try:
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
                wait = WebDriverWait(driver, 40)
                driver.get(SITE_CONFIGS['tapsi']['login_page'])
                wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "input[type='tel']"))).send_keys(phone)
                wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'دریافت کد')]"))).click()
                active_tapsi_sessions[chat_id] = {'driver': driver, 'timestamp': datetime.now()}
                await update.message.reply_text(f"✅ OTP sent by Tapsi to {phone}. Please reply with the 5-digit code.\n\n_This session will expire in 5 minutes._", parse_mode='Markdown')
            except Exception as e:
                if driver: driver.quit()
                await update.message.reply_text(f"❌ Failed to start Tapsi login. Error: {e}")
                sentry_sdk.capture_exception(e)
                if chat_id in user_states: del user_states[chat_id]

    except IndexError:
        await update.message.reply_text("Usage: /add <service> <phone_number>")

async def handle_otp_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if chat_id not in user_states:
        await update.message.reply_text("I don't have a pending request for you. Try /start.")
        return

    otp_code = update.message.text.strip()
    state = user_states[chat_id]
    service_name, phone = state['service'], state['phone']
    await update.message.reply_text(f"Verifying OTP for {phone} on {service_name.capitalize()}...")

    message = "An unknown error occurred."
    if service_name in ['snappfood', 'okala']:
        message = do_login(phone, otp_code, service_name, chat_id)

    elif service_name == 'tapsi':
        session_data = active_tapsi_sessions.get(chat_id)
        if not session_data:
            message = "❌ Your Tapsi session has expired. Please try again with `/add tapsi <phone>`."
        else:
            driver = session_data['driver']
            try:
                wait = WebDriverWait(driver, 15)
                otp_inputs = wait.until(EC.presence_of_all_elements_located((By.XPATH, "//div[starts-with(@id, 'INPUT_DIGIT_NUMBER_CONTAINER')]/input")))
                if len(otp_inputs) >= 5 and len(otp_code) == 5:
                    for i in range(5):
                        otp_inputs[i].send_keys(otp_code[i])
                        time.sleep(0.1)
                else: raise Exception("Could not find the 5 separate OTP input boxes.")

                wait.until(EC.element_to_be_clickable((By.XPATH, "//button[@type='button' and not(@disabled)]"))).click()
                wait.until(EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'سرویس‌ها')]")))

                sessions_dir = get_user_dir(chat_id, "tapsi")
                cookie_file_path = os.path.join(sessions_dir, f"{phone}_cookies.json")

                # Using dict(driver.get_cookies()) is more modern
                browser_cookies = {c['name']: c['value'] for c in driver.get_cookies()}
                access_token = browser_cookies.get('accessToken')

                if access_token:
                    with open(cookie_file_path, "w") as f: json.dump(driver.get_cookies(), f)
                    message = f"✅ Tapsi session saved for {phone}!"
                    rewards_message = fetch_tapsi_rewards(access_token, browser_cookies)
                    message += rewards_message
                else:
                    message = "❌ Login successful, but could not find accessToken cookie."

            except Exception as e:
                sentry_sdk.capture_exception(e)
                message = f"❌ Tapsi login failed. Error: {e}"
            finally:
                driver.quit()
                if chat_id in active_tapsi_sessions: del active_tapsi_sessions[chat_id]

    await update.message.reply_text(message, parse_mode='Markdown')
    if chat_id in user_states: del user_states[chat_id]

async def list_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    try:
        service = context.args[0].lower()
        if service not in VALID_SERVICES:
            await update.message.reply_text(f"Invalid service. Please choose from: {', '.join(VALID_SERVICES)}.")
            return

        sessions_dir = get_user_dir(chat_id, service)
        if service == 'snappfood':
            extension = "_session.json"
        elif service == 'tapsi':
            extension = "_cookies.json"
        else: # okala
            extension = "_tokens.json"

        accounts = [f.replace(extension, "") for f in os.listdir(sessions_dir) if f.endswith(extension)]

        if not accounts: await update.message.reply_text(f"No accounts saved for {service} yet.")
        else: await update.message.reply_text(f"Saved {service.capitalize()} Accounts:\n- " + "\n- ".join(sorted(accounts)))
    except IndexError:
        await update.message.reply_text("Usage: /list <service> (e.g., /list snappfood)")

async def check_all_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    try:
        service = context.args[0].lower()
        if service not in VALID_SERVICES:
            await update.message.reply_text(f"Invalid service. Please choose from: {', '.join(VALID_SERVICES)}.")
            return

        sessions_dir = get_user_dir(chat_id, service)
        if service == 'snappfood':
            extension = "_session.json"
        elif service == 'tapsi':
            extension = "_cookies.json"
        else: # okala
            extension = "_tokens.json"

        account_files = [f for f in os.listdir(sessions_dir) if f.endswith(extension)]

        if not account_files:
            await update.message.reply_text(f"No accounts found for {service} to check.")
            return

        await update.message.reply_text(f"🔄 Checking all {len(account_files)} saved account(s) for {service}. This may take a moment...")

        full_message = f"--- 📜 Report for {service.capitalize()} Accounts ---\n"
        for filename in sorted(account_files):
            phone_number = filename.replace(extension, "")
            file_path = os.path.join(sessions_dir, filename)
            full_message += f"\n\n**Checking Account: `{phone_number}`**"

            try:
                if service == 'snappfood':
                    with open(file_path, 'r') as f:
                        account_data = json.load(f)
                    vouchers_message = fetch_snappfood_vouchers(account_data)
                    full_message += vouchers_message

                elif service == 'okala':
                    with open(file_path, 'r') as f:
                        token_info = json.load(f)
                    vouchers_message = fetch_okala_vouchers(token_info)
                    full_message += vouchers_message

                elif service == 'tapsi':
                    with open(file_path, 'r') as f:
                        cookies_list = json.load(f)
                    cookies_dict = {c['name']: c['value'] for c in cookies_list}
                    access_token = cookies_dict.get('accessToken')
                    if access_token:
                        rewards_message = fetch_tapsi_rewards(access_token, cookies_dict)
                        full_message += rewards_message
                    else:
                        full_message += "\n❌ Could not find accessToken in session file."
            except Exception as e:
                full_message += f"\n❌ An error occurred while checking this account: {e}"
                sentry_sdk.capture_exception(e)

        for i in range(0, len(full_message), 4096):
            await update.message.reply_text(full_message[i:i + 4096], parse_mode='Markdown')

    except IndexError:
        await update.message.reply_text("Usage: /check_all <service>")
    except Exception as e:
        sentry_sdk.capture_exception(e)
        await update.message.reply_text(f"An unexpected error occurred: {e}")

async def download_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    try:
        service, phone = context.args[0].lower(), format_phone_number(context.args[1])
        if service not in VALID_SERVICES:
            await update.message.reply_text(f"Invalid service. Please choose from: {', '.join(VALID_SERVICES)}.")
            return

        if service == 'snappfood':
            extension = "_session.json"
        elif service == 'tapsi':
            extension = "_cookies.json"
        else: # okala
            extension = "_tokens.json"

        file_path = os.path.join(get_user_dir(chat_id, service), f"{phone}{extension}")

        if os.path.exists(file_path):
            await update.message.reply_text(f"Found session file ({os.path.basename(file_path)}). Sending it to you...")
            with open(file_path, 'rb') as doc:
                await context.bot.send_document(chat_id=chat_id, document=doc)
        else:
            await update.message.reply_text(f"❌ Could not find a saved session for {phone} on {service}.")
    except IndexError:
        await update.message.reply_text("Usage: /download <service> <phone_number>")
    except Exception as e:
        sentry_sdk.capture_exception(e)
        await update.message.reply_text(f"An error occurred: {e}")

async def download_all_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    try:
        service = context.args[0].lower()
        if service not in VALID_SERVICES:
            await update.message.reply_text(f"Invalid service. Please choose from: {', '.join(VALID_SERVICES)}.")
            return

        sessions_dir = get_user_dir(chat_id, service)
        if not any(os.scandir(sessions_dir)):
             await update.message.reply_text(f"No accounts saved for {service} yet.")
             return

        zip_path = os.path.join(BASE_DATA_DIR, str(chat_id), f"{service}_sessions_backup")
        shutil.make_archive(zip_path, 'zip', sessions_dir)

        await update.message.reply_text(f"Sending a zip file with all your saved {service} sessions...")
        with open(f"{zip_path}.zip", 'rb') as doc:
            await context.bot.send_document(chat_id=chat_id, document=doc, filename=f"{service}_sessions.zip")

        os.remove(f"{zip_path}.zip")

    except IndexError:
        await update.message.reply_text("Usage: /download_all <service>")
    except Exception as e:
        sentry_sdk.capture_exception(e)
        await update.message.reply_text(f"An error occurred while creating the archive: {e}")

# --- Cleanup Thread for Tapsi Sessions ---
def cleanup_old_sessions():
    while True:
        try:
            for chat_id in list(active_tapsi_sessions.keys()):
                session_data = active_tapsi_sessions.get(chat_id)
                if session_data and (datetime.now() - session_data['timestamp']) > SESSION_TIMEOUT:
                    logging.info(f"Cleaning up expired session for chat_id: {chat_id}")
                    try:
                        session_data['driver'].quit()
                    except WebDriverException as e:
                        logging.error(f"Error quitting expired driver for {chat_id}: {e}")
                    active_tapsi_sessions.pop(chat_id, None)
                    user_states.pop(chat_id, None)
        except Exception as e:
            logging.error(f"Error in cleanup thread: {e}")
            sentry_sdk.capture_exception(e)
        time.sleep(60)

# --- Main Bot Function ---
def main():
    if not TELEGRAM_TOKEN:
        logging.error("TELEGRAM_TOKEN environment variable not set! Exiting.")
        return

    cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
    cleanup_thread.start()
    logging.info("Session cleanup thread started.")

    application = Application.builder().token(TELEGRAM_TOKEN).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("add", add_command))
    application.add_handler(CommandHandler("list", list_command))
    application.add_handler(CommandHandler("check_all", check_all_command))
    application.add_handler(CommandHandler("download", download_command))
    application.add_handler(CommandHandler("download_all", download_all_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_otp_message))

    logging.info("Bot is starting...")
    application.run_polling()

if __name__ == '__main__':
    main()
