from flask import Flask, request, Response, session, redirect, url_for
import requests
import os

# This is the address where your ORIGINAL api.py is running.
# Make sure this is correct.
BOT_API_URL = "http://127.0.0.1:5001" 

app = Flask(__name__)
# A secret key is required for Flask to manage user sessions securely.
app.secret_key = os.urandom(24)

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
    try:
        with open('index.html', 'r') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        return "Error: index.html not found. Make sure it's in the same directory as proxy_app.py", 500

# --- Route to initiate the session ---
@app.route('/load_session', methods=['POST'])
def load_session():
    """
    Takes the session_id, verifies it, stores it in the user's session,
    and then redirects them to the proxied site.
    """
    session_id = request.form.get('session_id')
    if not session_id:
        return "Session ID is required.", 400

    session_data = get_session_from_bot_api(session_id)
    if not session_data:
        return "Could not find a session with that ID. Please check the ID and make sure the bot API is running.", 404

    # Store the necessary info in the user's secure session cookie
    session['session_id'] = session_id
    session['service'] = session_data.get('service')
    
    # Redirect to the starting page of the service (e.g., /profile)
    # The catch-all route below will handle this request.
    return redirect('/profile')


# --- The main catch-all proxy route ---
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_request(path):
    """
    This is the core of the proxy. It catches all requests, adds the login
    cookies, and forwards them to the target service.
    """
    # If the user doesn't have a session, send them back to the login page.
    if 'session_id' not in session:
        return redirect(url_for('index'))

    # Get session data for every request using the stored ID
    session_data = get_session_from_bot_api(session.get('session_id'))
    if not session_data:
        session.clear() # Clear the invalid session
        return redirect(url_for('index'))

    # Handle different cookie structures (dict vs. list)
    raw_session_object = session_data.get('session', {})
    cookies_for_request = {}
    if isinstance(raw_session_object, list):
        cookies_for_request = {cookie['name']: cookie['value'] for cookie in raw_session_object}
    elif isinstance(raw_session_object, dict):
        cookies_for_request = raw_session_object.get('cookies', {})

    # Determine the target base URL
    target_urls = {
        "snappfood": "https://snappfood.ir",
        "okala": "https://okala.com",
        "tapsi": "https://app.tapsi.cab"
    }
    base_url = target_urls.get(session.get('service').lower())
    if not base_url:
        return "Service not supported.", 400
        
    # Construct the full URL to request from the target service
    target_url = f"{base_url}/{path}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"

    # Forward the request with the original method, headers, data, and cookies
    try:
        headers = {key: value for (key, value) in request.headers if key.lower() not in ['host', 'cookie']}
        headers['Referer'] = base_url

        proxied_response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=cookies_for_request,
            allow_redirects=False,
            timeout=15
        )
        
        # --- NEW: Handle redirects and rewrite content ---
        
        # If the target site redirects, rewrite the Location header to keep the user on our proxy
        if proxied_response.status_code in [301, 302, 303, 307, 308]:
            location = proxied_response.headers.get('Location')
            if location:
                rewritten_location = location.replace(base_url, '')
                return redirect(rewritten_location, code=proxied_response.status_code)
            
        content = proxied_response.content
        content_type = proxied_response.headers.get('Content-Type', '')

        # Rewrite URLs in text-based content to be relative, so they point back to our proxy
        if any(t in content_type for t in ['text/html', 'text/css', 'application/javascript']):
            try:
                modified_text = content.decode('utf-8').replace(base_url, '')
                content = modified_text.encode('utf-8')
            except UnicodeDecodeError:
                # If decoding fails, just pass the content as is
                pass

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [(name, value) for (name, value) in proxied_response.headers.items() if name.lower() not in excluded_headers]

        return Response(content, proxied_response.status_code, response_headers)

    except requests.RequestException as e:
        return f"Failed to connect to the target service: {e}", 502


if __name__ == '__main__':
    # Run this server on a different port than your api.py, for example, 8080.
    app.run(debug=True, port=8080)
