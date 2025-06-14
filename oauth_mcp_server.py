"""Simple MCP Server with Local OAuth Authentication."""

import logging
import secrets
import time
from typing import Any, Literal

import click
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp.server import FastMCP
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

# Global OAuth provider instance
#oauth_provider = None

class ServerSettings(BaseSettings):
    """Settings for the simple Local OAuth MCP server."""

    model_config = SettingsConfigDict(env_prefix="MCP_LOCAL_")

    # Server settings
    host: str = "localhost"
    port: int = 8000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8000")

    # Local OAuth settings
    oauth_server_url: str = "http://localhost:9000"
    client_id: str = "local_client_id"
    client_secret: str = "local_client_secret"
    callback_path: str = "local/callback"  # MCP server callback

    # OAuth endpoints
    auth_url: str = "http://localhost:9000/oauth/authorize"
    token_url: str = "http://localhost:9000/oauth/token"
    userinfo_url: str = "http://localhost:9000/userinfo"

    mcp_scope: str = "user"


class SimpleLocalOAuthProvider(OAuthAuthorizationServerProvider):
    """Simple Local OAuth provider with essential functionality."""

    def __init__(self, settings: ServerSettings):
        self.settings = settings
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str]] = {}
        self.token_mapping: dict[str, str] = {}
        logger.info(f"Initialized OAuth provider with client_id: {settings.client_id}")

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        print("Mahesh:Registering client")
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Generate an authorization URL for Local OAuth flow."""
        state = params.state or secrets.token_hex(16)

        logger.info("=== OAuth Authorize Start ===")
        logger.info(f"Generated state: {state}")
        logger.info(f"Redirect URI: {params.redirect_uri}")
        logger.info(f"Code Challenge: {params.code_challenge}")
        logger.info(f"Client ID: {client.client_id}")
        logger.info(f"Settings call back url: {self.settings.server_url}{self.settings.callback_path}")
        
        # Store the state mapping
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
        }

        logger.info(f"Current state mapping: {self.state_mapping}")
        logger.info(f"Number of states in mapping: {len(self.state_mapping)}")

        callback_url = f"{self.settings.server_url}{self.settings.callback_path}"
        #callback_url = str(params.redirect_uri)
        
        logger.info(f"Using callback URL: {callback_url}")
        
        # Build authorization URL
        auth_url = (
            f"{self.settings.auth_url}"
            f"?client_id={self.settings.client_id}"
            f"&redirect_uri={callback_url}"
            f"&scope={self.settings.mcp_scope}"
            f"&state={state}"
        )

        logger.info(f"Generated authorization URL: {auth_url}")
        logger.info("=== OAuth Authorize End ===")

        return auth_url

    async def handle_oauth_callback(self, code: str, state: str) -> str:
        """Handle OAuth callback and return MCP code."""
        logger.info("=== OAuth Callback Start ===")
        logger.info(f"Received callback with code: {code} and state: {state}")
        logger.info(f"Current state mapping: {self.state_mapping}")
        logger.info(f"Number of states in mapping: {len(self.state_mapping)}")
        
        state_data = self.state_mapping.get(state)

        if not state_data:
            logger.error(f"Invalid state: {state}")
            logger.error(f"Available states: {list(self.state_mapping.keys())}")
            raise HTTPException(400, "Invalid state parameter")

        logger.info(f"Found state data: {state_data}")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
        client_id = state_data["client_id"]

        # Exchange code for token with local OAuth server
        async with create_mcp_http_client() as client:
            token_request = {
                "grant_type": "authorization_code",
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
                "code": code,
                "redirect_uri": f"{self.settings.server_url}{self.settings.callback_path}",
                #"redirect_uri": state_data["redirect_uri"],
            }
            logger.info(f"Token request data: {token_request}")
            
            response = await client.post(
                self.settings.token_url,
                json=token_request,
            )

            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                raise HTTPException(400, "Failed to exchange code for token")

            data = response.json()
            logger.info("Successfully exchanged code for token")
            local_token = data["access_token"]

            # Create MCP authorization code
            new_code = f"mcp_{secrets.token_hex(16)}"
            auth_code = AuthorizationCode(
                code=new_code,
                client_id=client_id,
                redirect_uri=AnyHttpUrl(redirect_uri),
                redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
                expires_at=time.time() + 300,
                scopes=[self.settings.mcp_scope],
                code_challenge=code_challenge,
            )
            logger.info(f"inside handle_oauth_callback Auth code: {auth_code}")

            self.auth_codes[new_code] = auth_code

            # Store local token mapping
            self.tokens[local_token] = AccessToken(
                token=local_token,
                client_id=client_id,
                scopes=[self.settings.mcp_scope]
            )

        logger.info(f"Generated MCP code: {new_code}")
        return new_code

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        logger.info("=== Load Authorization Code Start ===")
        logger.info(f"Loading authorization code: {authorization_code}")
        logger.info(f"Auth codes: {self.auth_codes}")
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        logger.info(f"Exchanging authorization code: {authorization_code.code}")
        logger.info(f"Auth codes: {self.auth_codes}")
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )

        # Find local token for this client
        local_token = next(
            (
                token
                for token, data in self.tokens.items()
                if token.startswith("") and data.client_id == client.client_id
            ),
            None,
        )

        # Store mapping between MCP token and local token
        if local_token:
            self.token_mapping[mcp_token] = local_token

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        """Load a refresh token - not supported."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token - not supported."""
        raise NotImplementedError("Refresh tokens not supported")


def create_simple_mcp_server(settings: ServerSettings) -> FastMCP:
    """Create a simple FastMCP server with Local OAuth."""
    #global oauth_provider
    oauth_provider = SimpleLocalOAuthProvider(settings)
    
    logger.info("=== Creating MCP Server ===")
    logger.info(f"Created OAuth provider: {oauth_provider}")
    logger.info(f"Initial state mapping: {oauth_provider.state_mapping}")

    auth_settings = AuthSettings(
        issuer_url=settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[settings.mcp_scope],
            default_scopes=[settings.mcp_scope],
        ),
        required_scopes=[settings.mcp_scope],
    )

    app = FastMCP(
        name="Simple Local OAuth MCP Server",
        instructions="A simple MCP server with Local OAuth authentication",
        auth_server_provider=oauth_provider,
        host=settings.host,
        port=settings.port,
        debug=True,
        auth=auth_settings,
    )

    @app.custom_route("/local/callback", methods=["GET"])
    async def oauth_callback_handler(request: Request) -> Response:
        """Handle OAuth server callback."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        logger.info("=== OAuth Server Callback Start ===")
        logger.info(f"Received OAuth callback with code: {code} and state: {state}")
        logger.info(f"Using global oauth_provider: {oauth_provider}")
        logger.info(f"Global provider state mapping: {oauth_provider.state_mapping if oauth_provider else 'None'}")

        if not code or not state:
            raise HTTPException(400, "Missing code or state parameter")

        try:
            # Exchange OAuth code for token and get MCP code
            mcp_code = await oauth_provider.handle_oauth_callback(code, state)
            logger.info(f"Generated MCP code: {mcp_code}")
            
            # Redirect to client callback with MCP code
            client_callback_url = f"{settings.server_url}client/callback?code={mcp_code}&state={state}"
            logger.info(f"Redirecting to client callback: {client_callback_url}")
            logger.info("=== OAuth Server Callback End ===")
            return RedirectResponse(status_code=302, url=client_callback_url)
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Unexpected error", exc_info=e)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "server_error",
                    "error_description": "Unexpected error",
                },
            )

    @app.custom_route("/client/callback", methods=["GET"])
    async def client_callback_handler(request: Request) -> Response:
        """Handle client callback with MCP code."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        logger.info("=== Client Callback Start ===")
        logger.info(f"Received client callback with code: {code} and state: {state}")

        if not code or not state:
            raise HTTPException(400, "Missing code or state parameter")

        try:
            # Get the original redirect URI from state mapping
            state_data = oauth_provider.state_mapping.get(state)
            if not state_data:
                logger.error(f"Invalid state: {state}")
                raise HTTPException(400, "Invalid state parameter")

            redirect_uri = state_data["redirect_uri"]
            logger.info(f"Redirecting to original client URI: {redirect_uri}")

            # Clean up state mapping
            #del oauth_provider.state_mapping[state]

            # Redirect to client's original redirect URI
            redirect_url = construct_redirect_uri(redirect_uri, code=code, state=state)
            logger.info(f"Final redirect URL: {redirect_url}")
            logger.info("=== Client Callback End ===")
            return RedirectResponse(status_code=302, url=redirect_url)
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Unexpected error", exc_info=e)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "server_error",
                    "error_description": "Unexpected error",
                },
            )

    @app.tool()
    async def get_user_profile() -> dict[str, Any]:
        """Get the authenticated user's profile information."""
        access_token = get_access_token()
        if not access_token:
            raise ValueError("Not authenticated")

        # Get local token from mapping
        local_token = oauth_provider.token_mapping.get(access_token.token)
        if not local_token:
            raise ValueError("No local token found for user")

        async with create_mcp_http_client() as client:
            response = await client.get(
                settings.userinfo_url,
                headers={"Authorization": f"Bearer {local_token}"},
            )

            if response.status_code != 200:
                raise ValueError(f"API error: {response.status_code} - {response.text}")

            return response.json()

    return app


@click.command()
@click.option("--port", default=8000, help="Port to listen on")
@click.option("--host", default="localhost", help="Host to bind to")
@click.option(
    "--transport",
    default="sse",
    type=click.Choice(["sse", "streamable-http"]),
    help="Transport protocol to use ('sse' or 'streamable-http')",
)
def main(port: int, host: str, transport: Literal["sse", "streamable-http"]) -> int:
    """Run the simple Local OAuth MCP server."""
    # Set up more detailed logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    try:
        settings = ServerSettings(host=host, port=port)
        logger.info(f"Server settings loaded: {settings.dict()}")
    except ValueError as e:
        logger.error(f"Failed to load settings: {e}")
        return 1

    mcp_server = create_simple_mcp_server(settings)
    logger.info(f"Starting server with {transport} transport")
    mcp_server.run(transport=transport)
    return 0

if __name__ == "__main__":
    main()
