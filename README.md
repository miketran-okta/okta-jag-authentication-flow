# Okta JAG Token Exchange (Cross App Access) - Consolidated Application

A single-page Node.js application that automates the complete Okta JAG (JWT-Based Access Grant) token exchange flow aka Cross-App Access, from user authentication to final access token acquisition.

## 🎯 What This App Does

This application consolidates the entire token exchange flow into one seamless experience:

1. **User Authentication**: Initiates OIDC login with Okta using PKCE
2. **ID Token Acquisition**: Receives ID token from Okta's Org Authorization Server
3. **JAG Token Exchange**: Automatically exchanges ID token for JAG-ID token
4. **Access Token Exchange**: Automatically exchanges JAG-ID token for final access token
5. **Results Display**: Shows all tokens, decoded payloads, and metadata in a beautiful UI

![Token Exchange Flow](token-exchange.png)

## 🚀 Quick Start

### Prerequisites

- Node.js 14+ installed
- An Okta account with:
  - IGA_RESOURCE_OWNERS feature flag enabled
  - OIDC application configured
  - [AI Agent client registered](https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-register.htm)
  - Custom API AM authorization server configured for the resource
    - Ensure a policy is assigned to the AI agent (not the OIDC app) and a rule with *JWT Bearer* is enabled
  - The AI Agent has a manged connection to the authorization server.  See [Connect an AI agent to an authorization server](https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-auth-server.htm)

See [Okta AI Agent Token Exchange Guide](https://developer.okta.com/docs/guides/ai-agent-token-exchange/service-account/main/) for the complete architecture flow

### Installation

1. **Install dependencies:**
```bash
npm install express axios dotenv jose
```

2. **Configure environment variables:**

Copy `.env.example` to `.env` and update with your values:

```bash
cp .env.example .env
```

Edit `.env` with your Okta configuration:
- `CLIENT_ID` - Your OIDC application client ID
- `CLIENT_SECRET` - Your OIDC application client secret
- `AGENT_CLIENT_ID` - Your AI agent client ID
- `AGENT_PRIVATE_KEY_JWK` - Your agent's private key as JSON string
- `AGENT_KEY_ID` - Your agent's key ID
- `JAG_AUDIENCE` - Resource server token endpoint (for JAG exchange)
- `RESOURCE_AUDIENCE` - Resource server token endpoint (for client assertion)

3. **Run the application:**
```bash
node index.js
```

4. **Open your browser:**
```
http://localhost:3000
```

## 📋 How It Works

### Flow Diagram

```
User → Login Page → Okta Login → Callback
                                     ↓
                        [STEP 1] Exchange code for ID Token
                                     ↓
                        [STEP 2] Exchange ID Token for JAG Token
                                     ↓
                        [STEP 3] Exchange JAG Token for Access Token
                                     ↓
                            Display All Tokens
```

### Detailed Steps

#### Step 1: ID Token Acquisition
- **Endpoint**: `https://demo-takolive.okta.com/oauth2/v1/token`
- **Grant Type**: `authorization_code`
- **Auth Method**: Client secret + PKCE
- **Result**: ID Token with user information

#### Step 2: JAG Token Exchange
- **Endpoint**: `https://demo-takolive.okta.com/oauth2/v1/token`
- **Grant Type**: `urn:ietf:params:oauth:grant-type:token-exchange`
- **Requested Token Type**: `urn:ietf:params:oauth:token-type:id-jag`
- **Subject Token**: ID Token from Step 1
- **Auth Method**: Client assertion JWT (signed with agent private key)
- **Result**: JAG-ID Token

#### Step 3: Access Token Exchange
- **Endpoint**: `https://demo-takolive.okta.com/oauth2/auszwbroacewkklqb697/v1/token`
- **Grant Type**: `urn:ietf:params:oauth:grant-type:jwt-bearer`
- **Assertion**: JAG-ID Token from Step 2
- **Auth Method**: Client assertion JWT (signed with agent private key, different audience)
- **Result**: Final Access Token for resource server

## 🔐 Client Assertion Details

The application creates two different client assertions:

### JAG Client Assertion
Used for exchanging ID token → JAG token
```json
{
  "iss": "wlpzvcwrykwZ1ovaX697",
  "sub": "wlpzvcwrykwZ1ovaX697",
  "aud": "https://demo-takolive.okta.com/oauth2/auszwbroacewkklqb697/v1/token",
  "iat": <timestamp>,
  "exp": <timestamp + 60>
}
```

### Resource Client Assertion
Used for exchanging JAG token → Access token
```json
{
  "iss": "wlpzvcwrykwZ1ovaX697",
  "sub": "wlpzvcwrykwZ1ovaX697",
  "aud": "https://demo-takolive.okta.com/oauth2/auszwbroacewkklqb697/v1/token",
  "iat": <timestamp>,
  "exp": <timestamp + 60>
}
```

Both are signed with RS256 using your agent's private key.

## 📦 Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `CLIENT_ID` | Yes | OIDC application client ID | `0oavyeo2o8SgalDKl697` |
| `CLIENT_SECRET` | Yes | OIDC application client secret | `your_secret_here` |
| `OKTA_ISSUER` | Yes | Your Okta org domain | `https://demo-takolive.okta.com` |
| `REDIRECT_URI` | No | OAuth callback URI | `http://localhost:3000/callback` |
| `AGENT_CLIENT_ID` | Yes | AI agent client ID | `wlpzvcwrykwZ1ovaX697` |
| `AGENT_PRIVATE_KEY_JWK` | Yes | Agent's private key as JSON | `{"kty":"RSA",...}` |
| `AGENT_KEY_ID` | Yes | Agent's key identifier | `5a6feb192aa70941aaeb2de4822767be` |
| `JAG_ISSUER` | No | JAG authorization server | `https://demo-takolive.okta.com/oauth2` |
| `JAG_AUDIENCE` | Yes | JAG token audience (resource token endpoint) | `https://demo-takolive.okta.com/oauth2/.../v1/token` |
| `JAG_SCOPE` | No | Scopes for JAG token | `ai_agent` |
| `RESOURCE_AUDIENCE` | Yes | Resource server audience | `https://demo-takolive.okta.com/oauth2/.../v1/token` |
| `RESOURCE_TOKEN_ENDPOINT` | Yes | Resource token endpoint | `https://demo-takolive.okta.com/oauth2/.../v1/token` |
| `PORT` | No | Server port | `3000` |

## 🎨 Features

### Beautiful UI
- **Step-by-step visualization** of the token flow
- **Expandable token displays** with syntax highlighting
- **One-click copy** buttons for all tokens
- **Decoded JWT payloads** for easy inspection
- **Metadata panels** showing token properties

### Console Logging
- Detailed console output for debugging
- Shows each step as it executes
- Displays token claims and metadata
- Logs all API endpoints being called

### Error Handling
- Comprehensive error pages showing where the flow failed
- Displays server error responses for debugging
- Shows which steps completed successfully
- Preserves partial results for troubleshooting

## 🔧 Troubleshooting

### Error: "Invalid client_assertion"
**Problem**: The client assertion JWT is not valid

**Solutions**:
- Verify `AGENT_PRIVATE_KEY_JWK` is correctly formatted JSON
- Check that `AGENT_KEY_ID` matches the key registered in Okta
- Ensure the audience (`aud`) claim matches the token endpoint

### Error: "Invalid issuer"
**Problem**: The ID token issuer doesn't match expected value

**Solutions**:
- Verify `OKTA_ISSUER` is set to `https://demo-takolive.okta.com` (not `/oauth2/default`)
- Check that you're using the Org Authorization Server, not Custom AS

### Error: "Audience claim must match"
**Problem**: The JAG token audience doesn't match the resource server

**Solutions**:
- Set `JAG_AUDIENCE` to the resource authorization server's token endpoint
- Verify `RESOURCE_AUDIENCE` is also set to the same endpoint
- Both should be: `https://demo-takolive.okta.com/oauth2/auszwbroacewkklqb697/v1/token`

### Error: "Token exchange failed"
**Problem**: General token exchange error

**Solutions**:
- Check console logs for detailed error response
- Verify all credentials are correct
- Ensure the agent client has proper permissions in Okta
- Check that scopes are configured correctly

## 📝 Token Lifetimes

| Token | Default Lifetime | Configurable |
|-------|------------------|--------------|
| ID Token | 1 hour | Yes (in Okta) |
| JAG Token | Varies | Yes (in Okta) |
| Access Token | Varies | Yes (in Okta) |
| Client Assertions | 60 seconds | No (hardcoded) |

## 🔒 Security Notes

- ✅ Uses PKCE for authorization code flow
- ✅ Stores sessions server-side only
- ✅ Client assertions expire after 60 seconds
- ✅ Automatic session cleanup (10 minute expiry)
- ⚠️ In production:
  - Use HTTPS
  - Store private keys in secure vaults (not .env)
  - Use proper session management (Redis, etc.)
  - Add rate limiting
  - Implement CSRF protection

## 🧪 Testing

### Test the Complete Flow
1. Start the server: `node index.js`
2. Visit `http://localhost:3000`
3. Click "Start Authentication"
4. Log in with your Okta credentials
5. View all acquired tokens

### Verify Each Token
- **ID Token**: Check `iss` is `https://demo-takolive.okta.com`
- **JAG Token**: Check `aud` matches resource server
- **Access Token**: Check `iss` is the resource authorization server

## 📚 Additional Resources

- [Okta JWT-Based Authentication for AI Agents](https://developer.okta.com/)
- [OAuth 2.0 Token Exchange RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

## 📄 License

This is example code for demonstration purposes.

## 🤝 Support

For issues related to:
- **This application**: Check console logs and error messages
- **Okta configuration**: Contact Okta support
- **Token exchange flow**: Review the Okta AI Agents documentation
