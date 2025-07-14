import json
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import os

def handle_tapsi_session(cookies):
    SERVICE_DOMAIN = ".tapsi.cab"
    LOGIN_URL = "https://app.tapsi.cab/"

    print("\n-> Tapsi session file detected. Starting browser login...")
    print("-> Setting up web driver...")
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service)

    print(f"-> Navigating to {LOGIN_URL} to set session...")
    driver.get(LOGIN_URL)
    time.sleep(2) # Add a small wait for the page to be ready

    print("-> Adding cookies to the browser session...")
    for cookie in cookies:
        if 'domain' in cookie and SERVICE_DOMAIN in cookie['domain']:
            try:
                driver.add_cookie(cookie)
            except Exception as e:
                # If a cookie fails, just print a warning and continue
                print(f"   [!] Warning: Could not add a cookie. Skipping. Domain: {cookie.get('domain')}")


    print("-> Refreshing page to apply session...")
    driver.refresh()

    print("\n✅ Process complete! Browser should be logged in to Tapsi.")
    print("   Keep this script running to keep the browser open.")

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting.")

    driver.quit()

def handle_snappfood_session(token_data):
    print("\n-> Snappfood session file detected.")
    if access_token := token_data.get('access_token'):
        print("\n✅ Success! Here is your Snappfood Access Token:")
        print("="*50)
        print(access_token)
        print("="*50)
        print("You can use this token in other scripts or API tools.")
    else:
        print("❌ Error: Could not find 'access_token' in the file.")

def load_session_from_file(file_path):
    print(f"-> Reading session file: {os.path.basename(file_path)}")
    try:
        with open(file_path, 'r') as f: data = json.load(f)
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return

    if isinstance(data, list) and any('domain' in c for c in data):
        handle_tapsi_session(data)
    elif isinstance(data, dict) and 'token_type' in data:
        handle_snappfood_session(data)
    else:
        print("❌ Error: Unrecognized session file format.")

if __name__ == "__main__":
    file_path = input("➡️ Drag and drop the downloaded session file here and press Enter: ").strip().replace("'", "").replace('"', '')
    if os.path.exists(file_path):
        load_session_from_file(file_path)
    else:
        print("❌ Error: File not found. Please make sure the path is correct.")
