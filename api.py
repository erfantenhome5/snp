import sqlite3
import json
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing

DB_FILE = "accounts.db" # This API needs access to the bot's database file

@app.route('/get_session', methods=['GET'])
def get_session():
    """
    Retrieves session data for a given account ID.
    Usage: /get_session?id=<ACCOUNT_ID>
    """
    account_id = request.args.get('id')

    if not account_id:
        return jsonify({"error": "Account ID is required"}), 400

    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row # This allows accessing columns by name
            cursor = conn.cursor()
            cursor.execute("SELECT service, session_data FROM accounts WHERE id = ?", (account_id,))
            account = cursor.fetchone()

            if account:
                session_data = json.loads(account['session_data'])
                response_data = {
                    "id": account_id,
                    "service": account['service'],
                    "session": session_data
                }
                return jsonify(response_data), 200
            else:
                return jsonify({"error": "Account not found"}), 404

    except Exception as e:
        print(f"Database error: {e}") # For logging on the server
        return jsonify({"error": "An internal server error occurred"}), 500

if __name__ == '__main__':
    # For local testing only. Use a production server like Gunicorn.
    # Example: gunicorn --bind 0.0.0.0:8000 api:app
    app.run(debug=True, port=5001)
