#!/usr/bin/env python3
"""
Simple MCP client example with OAuth authentication support.

This client connects to an MCP server using streamable HTTP transport with OAuth.

"""
import json
import asyncio
import os
import threading
import time
import webbrowser
import base64
import hashlib
import secrets
import requests
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken


class InMemoryTokenStorage(TokenStorage):
    """Simple in-memory token storage implementation."""

    def __init__(self):
        self._tokens: OAuthToken | None = None
        self._client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info


class CallbackHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler to capture OAuth callback."""

    def __init__(self, request, client_address, server, callback_data):
        """Initialize with callback data storage."""
        self.callback_data = callback_data
        super().__init__(request, client_address, server)

    def do_GET(self):
        """Handle GET request from OAuth redirect."""
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        if "code" in query_params:
            self.callback_data["authorization_code"] = query_params["code"][0]
            self.callback_data["state"] = query_params.get("state", [None])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <body>
                <h1>Authorization Successful!</h1>
                <p>You can close this window and return to the terminal.</p>
                <script>setTimeout(() => window.close(), 2000);</script>
            </body>
            </html>
            """)
        elif "error" in query_params:
            self.callback_data["error"] = query_params["error"][0]
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"""
            <html>
            <body>
                <h1>Authorization Failed</h1>
                <p>Error: {query_params['error'][0]}</p>
                <p>You can close this window and return to the terminal.</p>
            </body>
            </html>
            """.encode()
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class CallbackServer:
    """Simple server to handle OAuth callbacks."""

    def __init__(self, port=3000):
        self.port = port
        self.server = None
        self.thread = None
        self.callback_data = {"authorization_code": None, "state": None, "error": None}

    def _create_handler_with_data(self):
        """Create a handler class with access to callback data."""
        callback_data = self.callback_data

        class DataCallbackHandler(CallbackHandler):
            def __init__(self, request, client_address, server):
                super().__init__(request, client_address, server, callback_data)

        return DataCallbackHandler

    def start(self):
        """Start the callback server in a background thread."""
        handler_class = self._create_handler_with_data()
        self.server = HTTPServer(("localhost", self.port), handler_class)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        print(f"🖥️  Started callback server on http://localhost:{self.port}")

    def stop(self):
        """Stop the callback server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1)

    def wait_for_callback(self, timeout=300):
        """Wait for OAuth callback with timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.callback_data["authorization_code"]:
                return self.callback_data["authorization_code"]
            elif self.callback_data["error"]:
                raise Exception(f"OAuth error: {self.callback_data['error']}")
            time.sleep(0.1)
        raise Exception("Timeout waiting for OAuth callback")

    def get_state(self):
        """Get the received state parameter."""
        return self.callback_data["state"]


class SimpleAuthClient:
    """Simple MCP client with auth support."""

    def __init__(self, server_url: str, transport_type: str = "streamable_http"):
        self.server_url = server_url
        self.transport_type = transport_type
        self.session: ClientSession | None = None

    async def connect(self):
        """Connect to the MCP server."""
        print(f"🔗 Attempting to connect to {self.server_url}...")

        # Generate PKCE pair
        code_verifier, code_challenge = self.generate_pkce_pair()        

        try:
            #Set up callback server
            callback_server = CallbackServer(port=3000)
            callback_server.start()

            async def callback_handler() -> tuple[str, str | None]:
                """Wait for OAuth callback and return auth code and state."""
                print("⏳ Waiting for authorization callback...")
                try:
                    auth_code = callback_server.wait_for_callback(timeout=300)
                    return auth_code, callback_server.get_state()
                finally:
                    print("Mahesh:Stopping callback server")
                    callback_server.stop()

            client_metadata_dict = {
                "client_name": "Mahesh Auth Client",
                "redirect_uris": ["http://localhost:3000/callback"],
                #"redirect_uris": ["http://localhost:8000/local/callback"],
                # "grant_types": ["authorization_code", "refresh_token"],
                # "response_types": ["code"],
                # "token_endpoint_auth_method": "client_secret_post",
                # "code_challenge_methods_supported": ["S256"],
                #"code_verifier": code_verifier,
                #"code_challenge": code_challenge                
            }

            async def _default_redirect_handler(authorization_url: str) -> None:
                """Default redirect handler that opens the URL in a browser."""
                print(f"Opening browser for authorization: {authorization_url}")
                webbrowser.open(authorization_url)

            client_metadata=OAuthClientMetadata.model_validate(
                client_metadata_dict
            )
            print(f"Mahesh In connect client_metadata: {client_metadata.model_dump()}")
            # Create OAuth authentication handler using the new interface
            oauth_auth = OAuthClientProvider(
                server_url=self.server_url.replace("/mcp", ""),
                client_metadata=OAuthClientMetadata.model_validate(
                    client_metadata_dict
                ),
                storage=InMemoryTokenStorage(),
                redirect_handler=_default_redirect_handler,
                callback_handler=callback_handler,
            )

            # Create transport with auth handler based on transport type
            if self.transport_type == "sse":
                print("📡 Opening SSE transport connection with auth...")
                async with sse_client(
                    url=self.server_url,
                    auth=oauth_auth,
                    timeout=60,
                ) as (read_stream, write_stream):
                    await self._run_session(read_stream, write_stream, None)
            else:
                print("📡 Opening StreamableHTTP transport connection with auth...")
                async with streamablehttp_client(
                    url=self.server_url,
                    auth=oauth_auth,
                    timeout=timedelta(seconds=60),
                ) as (read_stream, write_stream, get_session_id):
                    await self._run_session(read_stream, write_stream, get_session_id)

        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            import traceback

            traceback.print_exc()

    async def _run_session(self, read_stream, write_stream, get_session_id):
        """Run the MCP session with the given streams."""
        print("🤝 Initializing MCP session...")
        async with ClientSession(read_stream, write_stream) as session:
            self.session = session
            print("⚡ Starting session initialization...")
            await session.initialize()
            print("✨ Session initialization complete!")

            print(f"\n✅ Connected to MCP server at {self.server_url}")
            if get_session_id:
                session_id = get_session_id()
                if session_id:
                    print(f"Session ID: {session_id}")

            # Run interactive loop
            await self.interactive_loop()

    async def list_tools(self):
        """List available tools from the server."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            result = await self.session.list_tools()
            if hasattr(result, "tools") and result.tools:
                print("\n📋 Available tools:")
                for i, tool in enumerate(result.tools, 1):
                    print(f"{i}. {tool.name}")
                    if tool.description:
                        print(f"   Description: {tool.description}")
                    print()
            else:
                print("No tools available")
        except Exception as e:
            print(f"❌ Failed to list tools: {e}")

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None):
        """Call a specific tool."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            result = await self.session.call_tool(tool_name, arguments or {})
            print(f"\n🔧 Tool '{tool_name}' result:")
            if hasattr(result, "content"):
                for content in result.content:
                    if content.type == "text":
                        print(content.text)
                    else:
                        print(content)
            else:
                print(result)
        except Exception as e:
            print(f"❌ Failed to call tool '{tool_name}': {e}")

    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge."""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        return code_verifier, code_challenge

    # async def connect(self):
    #     # Generate PKCE pair
    #     code_verifier, code_challenge = self.generate_pkce_pair()
        
    #     # Update client metadata to include PKCE
    #     client_metadata_dict = {
    #         "client_name": "Simple Auth Client",
    #         "redirect_uris": ["http://localhost:3000/callback"],
    #         "grant_types": ["authorization_code"],
    #         "response_types": ["code"],
    #         "token_endpoint_auth_method": "client_secret_post",
    #         "code_challenge_methods_supported": ["S256"]
    #     }

    async def interactive_loop(self):
        """Run interactive command loop."""
        print("\n🎯 Interactive MCP Client")
        print("Commands:")
        print("  list - List available tools")
        print("  call <tool_name> [args] - Call a tool")
        print("  quit - Exit the client")
        print()

        while True:
            try:
                command = input("mcp> ").strip()

                if not command:
                    continue

                if command == "quit":
                    break

                elif command == "list":
                    await self.list_tools()

                elif command.startswith("call "):
                    parts = command.split(maxsplit=2)
                    tool_name = parts[1] if len(parts) > 1 else ""

                    if not tool_name:
                        print("❌ Please specify a tool name")
                        continue

                    # Parse arguments (simple JSON-like format)
                    arguments = {}
                    if len(parts) > 2:
                        import json

                        try:
                            arguments = json.loads(parts[2])
                        except json.JSONDecodeError:
                            print("❌ Invalid arguments format (expected JSON)")
                            continue

                    await self.call_tool(tool_name, arguments)

                else:
                    print(
                        "❌ Unknown command. Try 'list', 'call <tool_name>', or 'quit'"
                    )

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except EOFError:
                break



async def main():
    """Main entry point."""
    # Default server URL - can be overridden with environment variable
    # Most MCP streamable HTTP servers use /mcp as the endpoint
    server_url = os.getenv("MCP_SERVER_PORT", 8000)
    transport_type = os.getenv("MCP_TRANSPORT_TYPE", "streamable_http")
    #transport_type = os.getenv("MCP_TRANSPORT_TYPE", "sse")
    server_url = (
        f"http://localhost:{server_url}/mcp"
        if transport_type == "streamable_http"
        else f"http://localhost:{server_url}/sse"
    )

    print("🚀 Simple MCP Auth Client")
    print(f"Connecting to: {server_url}")
    print(f"Transport type: {transport_type}")

    # Start connection flow - OAuth will be handled automatically
    client = SimpleAuthClient(server_url, transport_type)
    print("Created Client Object")
    await client.connect()
    print("Connected to MCP Server")


def register_client():

    #response = requests.delete(f"http://localhost:9000/oauth/clients")
    #print(f"Mahesh In cli response: {json.dumps(response.json(), indent=4)}")     

    #Register the client with the OAuth server
    client_metadata_dict = {
        "client_name": "First Auth Client",
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
    }
    client_object = OAuthClientInformationFull(
        client_id = "mahesh_client_id",
        client_secret = "Mahesh_client_secret",
        client_id_issued_at = 1718438400,
        client_secret_expires_at = 1718438400,
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code", "refresh_token"],
        token_endpoint_auth_method="client_secret_post",
        response_types=["code"],
        scopes=["user", "profile"]
        )
    print(f"Mahesh In cli client_object: {client_object.model_dump_json()}")
    response = requests.post(f"http://localhost:9000/oauth/register", data=client_object.model_dump_json())
    print(f"Mahesh In cli response: {response.json()}")
    print(f"Mahesh In cli response: {response.json()}")
    print(f"Mahesh In cli response: {response.status_code}")

    #response = requests.get(f"http://localhost:9000/oauth/clients")
    #print(f"Mahesh In cli response: {json.dumps(response.json(), indent=4)}")     



def cli():
    """CLI entry point for uv script."""
    asyncio.run(main())


if __name__ == "__main__":
    #First register this client with the OAuth server
    #register_client()
    cli()