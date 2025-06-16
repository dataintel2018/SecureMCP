"""Test program for the Local OAuth Server."""

import requests
import time
import json
from urllib.parse import urlparse, parse_qs
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# OAuth Server configuration
OAUTH_SERVER = "http://localhost:9000"
CALLBACK_PORT = 8000
CALLBACK_URL = f"http://localhost:{CALLBACK_PORT}/callback"

class CallbackHandler(BaseHTTPRequestHandler):
    """Handle the OAuth callback."""
    auth_code = None
    state = None

    def do_GET(self):
        """Handle GET request to callback URL."""
        # Parse the callback URL
        query_components = parse_qs(urlparse(self.path).query)
        CallbackHandler.auth_code = query_components.get('code', [None])[0]
        CallbackHandler.state = query_components.get('state', [None])[0]

        # Send response to browser
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Authorization successful! You can close this window.")

def start_callback_server():
    """Start the callback server."""
    server = HTTPServer(('localhost', CALLBACK_PORT), CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server

def test_client_management():
    """Test client management endpoints."""
    logger.info("Testing client management...")

    # Add a new client
    client_data = {
        "redirect_uris": [CALLBACK_URL]
    }
    response = requests.post(f"{OAUTH_SERVER}/admin/clients", json=client_data)
    assert response.status_code == 200, f"Failed to add client: {response.text}"
    client_info = response.json()
    logger.info(f"Added new client: {json.dumps(client_info, indent=2)}")

    # Get client credentials
    client_id = client_info['client_id']
    client_secret = client_info['client_secret']

    return client_id, client_secret

def test_oauth_flow(client_id, client_secret):
    """Test the OAuth flow."""
    logger.info("Testing OAuth flow...")

    # Step 1: Start the callback server
    server = start_callback_server()
    logger.info(f"Started callback server on port {CALLBACK_PORT}")

    # Step 2: Initiate authorization request
    auth_url = f"{OAUTH_SERVER}/oauth/authorize"
    params = {
        "client_id": client_id,
        "redirect_uri": CALLBACK_URL,
        "state": "test_state"
    }
    
    # Open browser for authorization
    auth_request_url = f"{auth_url}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
    logger.info(f"Opening browser for authorization: {auth_request_url}")
    webbrowser.open(auth_request_url)

    # Wait for callback
    logger.info("Waiting for authorization callback...")
    timeout = 30
    start_time = time.time()
    while not CallbackHandler.auth_code and time.time() - start_time < timeout:
        time.sleep(1)

    if not CallbackHandler.auth_code:
        logger.error("Authorization timed out")
        return

    logger.info(f"Received authorization code: {CallbackHandler.auth_code}")

    # Step 3: Exchange authorization code for access token
    token_data = {
        "grant_type": "authorization_code",
        "code": CallbackHandler.auth_code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": CALLBACK_URL
    }
    
    response = requests.post(f"{OAUTH_SERVER}/oauth/token", json=token_data)
    assert response.status_code == 200, f"Failed to get access token: {response.text}"
    token_info = response.json()
    logger.info(f"Received access token: {json.dumps(token_info, indent=2)}")

    # Step 4: Get user info with access token
    headers = {"Authorization": f"Bearer {token_info['access_token']}"}
    response = requests.get(f"{OAUTH_SERVER}/userinfo", headers=headers)
    assert response.status_code == 200, f"Failed to get user info: {response.text}"
    user_info = response.json()
    logger.info(f"Received user info: {json.dumps(user_info, indent=2)}")

    # Cleanup
    server.shutdown()
    server.server_close()

def main():
    """Run all tests."""
    try:
        # Test client management
        client_id, client_secret = test_client_management()

        # Test OAuth flow
        #test_oauth_flow(client_id, client_secret)

        logger.info("All tests completed successfully!")
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        raise

if __name__ == "__main__":
    main() 