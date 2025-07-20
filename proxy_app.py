from flask import Flask, request, Response, render_template_string, redirect, url_for
import requests
import json

# This is the address where your ORIGINAL api.py is running.
# Make sure this is correct.
BOT_API_URL = "http://127.0.0.1:5001" 

app = Flask(__name__)

# --- Helper function to get the session data from your bot's API ---
def get_session_from_bot_api(session_id):
    """Fetches session data from your original api.py script."""
    try:
        api_response = requests.get(f"{BOT_API_URL}/get_session", params={'id': session_id}, timeout=5)
        if api_response.status_code == 200:
            return api_response.json()
        return None
    except requests.RequestException as e:
        print(f"Error calling bot API: {e}")
        return None

# --- Route to display the initial page where user enters the ID ---
@app.route('/')
def index():
    """Renders the main page with the input form."""
    # This function now uses a simple HTML string template.
    # See the frontend code in the next step.
    try:
        with open('index.html', 'r') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        return "Error: index.html not found. Make sure it's in the same directory as proxy_app.py", 500


# --- The main proxy route ---
@app.route('/load_session', methods=['POST'])
def load_session():
    """
    This is the core of the proxy. It takes a session ID, fetches the real
    content, and serves it to the user.
    """
    session_id = request.form.get('session_id')
    if not session_id:
        return "Session ID is required.", 400

    # 1. Get session data (cookies) from your bot's api.py
    session_data = get_session_from_bot_api(session_id)
    if not session_data:
        return "Could not find a session with that ID. Please check the ID and make sure the bot API is running.", 404

    service = session_data.get('service')
    
    # --- FIX STARTS HERE ---
    # Handle different session data structures (dict for Snappfood/Okala, list for Tapsi)
    raw_session_object = session_data.get('session', {})
    cookies_for_request = {}

    if isinstance(raw_session_object, list):
        # This is a Tapsi-style session (a list of cookie dictionaries)
        # We convert it to the single dictionary that the 'requests' library needs.
        cookies_for_request = {cookie['name']: cookie['value'] for cookie in raw_session_object}
    elif isinstance(raw_session_object, dict):
        # This is a Snappfood/Okala-style session (a dictionary containing a 'cookies' dictionary)
        cookies_for_request = raw_session_object.get('cookies', {})
    # --- FIX ENDS HERE ---

    # 2. Determine the target URL based on the service
    target_urls = {
        "snappfood": "https://snappfood.ir/profile",
        "okala": "https://okala.com/profile",
        "tapsi": "https://app.tapsi.cab/"
    }
    target_url = target_urls.get(service.lower())

    if not target_url:
        return f"Service '{service}' is not supported.", 400

    # 3. Make the request to the target site on behalf of the user
    try:
        print(f"Proxying request for {service} to {target_url} with cookies.")
        headers = {
            # Mimic a real browser user-agent
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
        }
        
        # The 'requests' library uses a 'cookies' parameter which takes a dictionary
        proxied_response = requests.get(target_url, headers=headers, cookies=cookies_for_request, timeout=10)
        
        # 4. Return the content from the target site to the user's browser
        # We create a Response object to pass along the content and status code.
        return Response(proxied_response.content, status=proxied_response.status_code, content_type=proxied_response.headers['content-type'])

    except requests.RequestException as e:
        return f"Failed to connect to the target service: {e}", 500


if __name__ == '__main__':
    # Run this server on a different port than your api.py, for example, 8080.
    app.run(debug=True, port=8080)
