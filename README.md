# Secure MCP with Local OAuth Authentication

This project implements a secure MCP (Model Context Protocol) server with a local OAuth 2.0 authentication server for development and testing purposes. The implementation includes a complete OAuth flow with a local OAuth server, MCP server, and MCP client.

## Setup

1. Install uv (if not already installed):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. Create and activate a virtual environment:
```bash
uv venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies using uv:
```bash
uv pip install -r requirements.txt
```

## Running the Components

1. First, start the Local OAuth Server:
```bash
uv run LocalOAuthServer.py
```
This will start the OAuth server on http://localhost:9000

2. In a new terminal, start the MCP Server:
```bash
uv run oauth_mcp_server.py
```
This will start the MCP server on http://localhost:8000

3. In a third terminal, run the MCP Client:
```bash
uv run oauth_mcp_client.py
```

## Component Details

### Local OAuth Server (LocalOAuthServer.py)
- URL: http://localhost:9000
- Default Client ID: local_client_id
- Default Client Secret: local_client_secret
- Available Endpoints:
  - /oauth/authorize - Authorization endpoint
  - /oauth/token - Token endpoint
  - /userinfo - User information endpoint
  - /debug/config - Debug endpoint for configuration
  - /debug/check-redirect - Debug endpoint for redirect URI validation

### MCP Server (oauth_mcp_server.py)
- URL: http://localhost:8000
- Callback Path: /local/callback
- Available Tools:
  - get_user_profile - Returns the authenticated user's profile information
- Features:
  - OAuth 2.0 authentication
  - Multiple transport options (SSE and streamable-http)
  - Automatic token management
  - Secure callback handling

### MCP Client (oauth_mcp_client.py)
- Features:
  - Interactive command-line interface
  - Automatic browser-based authorization
  - In-memory token storage
  - Tool listing and execution capabilities
  - Support for both SSE and streamable-http transports

## Authentication Flow

1. Client initiates connection to MCP server
2. MCP server redirects to Local OAuth server for authorization
3. Local OAuth server generates authorization code
4. MCP server exchanges code for access token
5. Client receives MCP authorization code
6. Client establishes authenticated session with MCP server

## Configuration

The components can be configured using environment variables:

### MCP Server
- `MCP_LOCAL_HOST`: Server host (default: localhost)
- `MCP_LOCAL_PORT`: Server port (default: 8000)
- `MCP_LOCAL_SERVER_URL`: Server URL (default: http://localhost:8000)
- `MCP_LOCAL_OAUTH_SERVER_URL`: OAuth server URL (default: http://localhost:9000)

### MCP Client
- Server URL: http://localhost:8000
- Callback URL: http://localhost:3000/callback
- Transport options: "sse" or "streamable-http"

## Usage

### Interactive Client Commands

Once connected, the following commands are available:

1. **List Available Tools**
```bash
mcp> list
```

2. **Call a Specific Tool**
```bash
mcp> call <tool_name> [arguments]
```
Example:
```bash
mcp> call get_user_profile
```

3. **Exit the Client**
```bash
mcp> quit
```

## Security Considerations

- This is a development setup with a mock OAuth server
- For production use:
  - Replace the local OAuth server with a proper authentication provider
  - Use secure, randomly generated client credentials
  - Implement proper user authentication
  - Use HTTPS for all endpoints
  - Implement secure token storage
  - Add proper error handling and logging

## Troubleshooting

Common issues and solutions:

1. **Connection Failures**
   - Verify all three components are running
   - Check ports are not in use
   - Ensure correct URLs in configuration

2. **Authentication Issues**
   - Verify OAuth server is running
   - Check client credentials match
   - Ensure callback URLs are properly registered
   - Check browser access is available

3. **Tool Execution Errors**
   - Verify authentication is successful
   - Check tool name exists
   - Ensure proper argument format

## Development

### Code Structure

```
.
├── LocalOAuthServer.py     # Local OAuth server implementation
├── oauth_mcp_server.py     # MCP server with OAuth integration
├── oauth_mcp_client.py     # MCP client with OAuth support
└── requirements.txt        # Project dependencies
```

## License

[Specify your license here]

## Contact

[Add contact information here] 