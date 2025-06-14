"""Simple Local OAuth Server Implementation."""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
import uvicorn
from pydantic import BaseModel
import secrets
from typing import Optional
import time
import logging

logger = logging.getLogger(__name__)

app = FastAPI()

# Store client credentials
clients = {
    "default_client": {
        "client_id": "local_client_id",
        "client_secret": "local_client_secret",
        "redirect_uris": ["http://localhost:8000/local/callback"]  # Only server-side callback
        #"redirect_uris": ["http://localhost:3000/callback"]
    }
}

# Store authorization codes and tokens
auth_codes = {}
access_tokens = {}

@app.get("/debug/config")
async def debug_config():
    """Debug endpoint to check configuration."""
    return {
        "registered_clients": clients,
        "active_auth_codes": len(auth_codes),
        "active_tokens": len(access_tokens)
    }

@app.get("/debug/check-redirect")
async def check_redirect(redirect_uri: str):
    """Debug endpoint to check if a redirect URI is valid."""
    for client in clients.values():
        if redirect_uri in client['redirect_uris']:
            return {
                "valid": True,
                "client": client['client_id'],
                "message": "Redirect URI is valid for this client"
            }
    return {
        "valid": False,
        "registered_uris": [uri for client in clients.values() for uri in client['redirect_uris']],
        "message": "Redirect URI not found in any client's allowed redirects"
    }

class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    client_id: str
    client_secret: str
    redirect_uri: Optional[str] = None

@app.get("/oauth/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    state: Optional[str] = None,
    scope: Optional[str] = None
):
    logger.info(f"Received authorization request with client_id: {client_id}")
    logger.info(f"Registered clients: {list(clients.keys())}")
    logger.info(f"Valid client IDs: {[client['client_id'] for client in clients.values()]}")
    
    # Validate client and redirect URI
    valid_client = None
    for client in clients.values():
        if client['client_id'] == client_id:
            valid_client = client
            break
    
    if not valid_client:
        logger.error(f"Invalid client_id: {client_id}")
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    logger.info(f"Valid client: {valid_client}")
    #logger.info(f"Valid client redirect_uris: {valid_client['redirect_uris']}")
    logger.info(f"Redirect URI: {redirect_uri}")
    if redirect_uri not in valid_client['redirect_uris']:
        logger.error(f"Invalid redirect_uri: {redirect_uri}")
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    # Generate authorization code
    #global auth_codes
    auth_code = secrets.token_urlsafe(32)
    auth_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "expires_at": time.time() + 600  # 10 minutes expiry
    }
    
    logger.info(f"Generated auth code for client_id: {client_id}")
    
    # Redirect back to client with code
    redirect_params = f"code={auth_code}"
    if state:
        redirect_params += f"&state={state}"
    
    redirect_url = f"{redirect_uri}?{redirect_params}"
    logger.info(f"Redirecting to: {redirect_url}")
    
    return RedirectResponse(url=redirect_url)

@app.post("/oauth/token")
async def token(request: TokenRequest):
    print("mahesh inside token")
    print(f"request.grant_type: {request.grant_type}")
    logger.info(f"Token request received: {request.dict()}")
    global auth_codes
    
    # Validate client credentials
    valid_client = None
    for client in clients.values():
        if client['client_id'] == request.client_id:
            valid_client = client
            break
    
    if not valid_client or valid_client['client_secret'] != request.client_secret:
        logger.error(f"Invalid client credentials for client_id: {request.client_id}")
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    logger.info(f"request.grant_type: {request.grant_type}")
    if request.grant_type == "authorization_code":
        # Validate authorization code
        print("mahesh inside token")
        print(f"request.code: {request.code}")
        print(f"auth_codes: {auth_codes}")
        if request.code not in auth_codes:            
            logger.error(f"Invalid authorization code: {request.code}")
            raise HTTPException(status_code=400, detail="Invalid authorization code")

        
        code_data = auth_codes[request.code]
        if time.time() > code_data["expires_at"]:
            del auth_codes[request.code]
            logger.error("Authorization code expired")
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Generate access token
        access_token = secrets.token_urlsafe(32)
        access_tokens[access_token] = {
            "client_id": request.client_id,
            "scope": code_data["scope"],
            "expires_at": time.time() + 3600  # 1 hour expiry
        }
        
        # Remove used authorization code
        del auth_codes[request.code]
        
        response_data = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": code_data["scope"]
        }
        logger.info(f"Generated access token for client_id: {request.client_id}")
        logger.info(f"Generated access token: {access_token}")
        return response_data
    
    logger.error(f"Unsupported grant type: {request.grant_type}")
    raise HTTPException(status_code=400, detail="Unsupported grant type")

@app.get("/userinfo")
async def userinfo(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.error("Missing or invalid authorization header")
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = auth_header.split(" ")[1]
    if token not in access_tokens:
        logger.error(f"Invalid access token: {token}")
        raise HTTPException(status_code=401, detail="Invalid access token")
    
    token_data = access_tokens[token]
    if time.time() > token_data["expires_at"]:
        del access_tokens[token]
        logger.error("Access token expired")
        raise HTTPException(status_code=401, detail="Access token expired")
    
    logger.info(f"Returning user info for client_id: {token_data['client_id']}")
    # Return mock user info
    return {
        "sub": "123",
        "name": "Local User",
        "email": "user@local.test"
    }

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger.info("Starting OAuth server with registered clients:")
    for client_name, client_data in clients.items():
        logger.info(f"  {client_name}: {client_data['client_id']}")
    
    uvicorn.run(app, host="localhost", port=9000) 