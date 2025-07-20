from flask import Flask, request, Response, session, redirect, url_for
import requests
import os
from urllib.parse import urlparse
import logging

# --- Basic Logging Setup ---
# This will print log messages to the console, which journalctl will capture.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# This is the address where your ORIGINAL api.py is running.
# Make sure this is correct.
BOT_API_URL = "http://127.0.0.1:5001" 

app = Flask(__name__)
# A secret key is required for Flask to manage user sessions securely.
app.secret_key = os.urandom(24)

# --- Helper function to get the session data from your bot's API ---
def get_session_from_bot_api(session_id):
    """Fetches session data from your original api.py script."""
    logging.info(f"Attempting to fetch session data for ID: {session_id[:8]}...")
    try:
        api_response = requests.get(f"{BOT_API_URL}/get_session", params={'id': session_id}, timeout=5)
        if api_response.status_code == 200:
            logging.info(f"Successfully fetched session data for ID: {session_id[:8]}.")
            return api_response.json()
        logging.warning(f"Failed to fetch session data. API responded with status: {api_response.status_code}")
        return None
    except requests.RequestException as e:
        logging.error(f"Error calling bot API: {e}")
        return None

# --- Route to display the initial page where user enters the ID ---
@app.route('/')
def index():
    """Renders the main page with the input form."""
    try:
        with open('index.html', 'r') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        logging.error("index.html not found in the application directory.")
        return "Error: index.html not found. Make sure it's in the same directory as proxy_app.py", 500

# --- Route to initiate the session ---
@app.route('/load_session', methods=['POST'])
def load_session():
    """
    Takes the session_id, verifies it, stores it in the user's session,
    and then redirects them to the proxied site's homepage.
    """
    session_id = request.form.get('session_id')
    logging.info(f"Received request to load session for ID: {session_id[:8] if session_id else 'None'}")
    if not session_id:
        return "Session ID is required.", 400

    session_data = get_session_from_bot_api(session_id)
    if not session_data:
        return "Could not find a session with that ID. Please check the ID and make sure the bot API is running.", 404

    # Store the necessary info in the user's secure session cookie
    session['session_id'] = session_id
    session['service'] = session_data.get('service')
    logging.info(f"Session for service '{session['service']}' created successfully. Redirecting...")
    
    # Redirect to the root of the proxy, which will be handled by the catch-all route.
    return redirect('/?login=true')


# --- The main catch-all proxy route ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def proxy_request(path):
    """
    This is the core of the proxy. It catches all requests, adds the login
    cookies, and forwards them to the target service.
    """
    logging.info(f"--- New Proxy Request ---")
    logging.info(f"Path requested: /{path}")

    if 'session_id' not in session:
        logging.warning("No session_id found. Redirecting to index.")
        return redirect(url_for('index'))

    session_data = get_session_from_bot_api(session.get('session_id'))
    if not session_data:
        logging.warning("Session ID found, but no data returned from API. Clearing session and redirecting.")
        session.clear()
        return redirect(url_for('index'))

    raw_session_object = session_data.get('session', {})
    cookies_for_request = {}
    if isinstance(raw_session_object, list):
        cookies_for_request = {cookie['name']: cookie['value'] for cookie in raw_session_object}
    elif isinstance(raw_session_object, dict):
        cookies_for_request = raw_session_object.get('cookies', {})

    target_urls = {
        "snappfood": "https://snappfood.ir",
        "okala": "https://okala.com",
        "tapsi": "https://app.tapsi.cab"
    }
    base_url = target_urls.get(session.get('service').lower())
    if not base_url:
        return "Service not supported.", 400
        
    target_url = f"{base_url}/{path}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"

    logging.info(f"Proxying to target URL: {target_url}")

    try:
        parsed_uri = urlparse(base_url)
        host = parsed_uri.netloc
        
        headers = {key: value for (key, value) in request.headers}
        headers['Host'] = host
        headers['Origin'] = base_url
        headers['Referer'] = base_url
        
        logging.info(f"Forwarding with method '{request.method}' and Host header '{host}'")

        proxied_response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=cookies_for_request,
            allow_redirects=False,
            stream=True,
            timeout=20
        )
        
        logging.info(f"Received response from target with status: {proxied_response.status_code}")
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = []
        for name, value in proxied_response.raw.headers.items():
            if name.lower() not in excluded_headers:
                response_headers.append((name, value))

        return Response(proxied_response.iter_content(chunk_size=1024), proxied_response.status_code, response_headers)

    except requests.RequestException as e:
        logging.error(f"Exception during proxy request: {e}")
        return f"Failed to connect to the target service: {e}", 502


if __name__ == '__main__':
    app.run(debug=True, port=8080)
