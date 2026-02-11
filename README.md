# Okta AI Agent Token Exchange Demo

A hands-on demo application designed to help Solutions Engineers learn and demonstrate Okta's new AI Agent capabilities, including the **AI Agent Registry** and **Managed Connections** for secure token exchange using **Cross App Access**.

## 🎯 Purpose

This demo helps you understand and showcase:
- **AI Agent Registry**: How to register and manage AI agents as first-class citizen within Okta's Universal Directory
- **Managed Connections**: Secure authentication between AI agents and downstream tools through authorization servers using JWT client assertions
- **Cross App Access and Token Exchange Flow**: The complete JAG (JWT-Based Access Grant) token exchange from user authentication to resource access

![Token Exchange Flow](token-exchange.png)
*Live demo showing the three-step token exchange process*

## 🏗️ Architecture Overview

This demo implements the complete Okta AI Agent token exchange pattern:

![Okta AI Agent Token Exchange Architecture](https://developer.okta.com/img/auth/ai-agent-token-exchange.png)

**Flow Summary:**
1. User authenticates via OIDC with your Okta org
2. ID token is exchanged for a JAG-ID token (using AI agent credentials)
3. JAG-ID token is exchanged for an access token to the resource server

📖 **Full architecture details**: [Okta AI Agent Token Exchange Guide](https://developer.okta.com/docs/guides/ai-agent-token-exchange/service-account/main/)

---

## 🚀 Setup Guide

### Part 1: Okta Admin Console Configuration

Before running the demo, configure your Okta org with the following components:

#### ✅ Prerequisites
- Okta org with `IGA_RESOURCE_OWNERS` feature flag enabled
- Admin access to configure applications and authorization servers

#### 📋 Configuration Checklist

1. **Create an OIDC Application** (for user authentication)
   - Go to **Applications** > **Applications** > **Create App Integration**
   - Choose **OIDC - OpenID Connect** and **Web Application**
   - Configure redirect URI: `http://localhost:3000/callback`
   - Save the Client ID and Client Secret
   
2. **Register an AI Agent**
   - Navigate to **Directory** > **AI Agents** in your Okta Admin Console
   - Create a new AI agent and generate a public/private key pair
   - Link the OIDC application
   - Save the Client ID, Key ID, and private key (JWK format)
   - 📚 [How to register an AI Agent](https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-register.htm)

3. **Configure a Custom Authorization Server** (for the resource)
   - Go to **Security** > **API** > **Authorization Servers**
   - Create or use an existing custom authorization server
   - Configure an access policy:
     - Assign the policy to the **AI Agent** (not the OIDC app)
     - Add a rule with **JWT Bearer** grant type enabled
     - Add OAuth scopes ie ai_agent
   - 📚 [Connect an AI agent to an authorization server](https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-auth-server.htm)
   - Note the Authorization Server ID and token endpoint

4. **Create a Managed Connection**
   - Connect your AI Agent to the custom authorization server under the Agent's Managed Connections tab   

**Key Learning Point**: The managed connection establishes trust between your AI agent and the authorization server, enabling secure token exchange without traditional OAuth secrets.

---

### Part 2: Demo Application Setup

#### 📦 Installation

1. **Clone and install dependencies:**
```bash
npm install express axios dotenv jose
```

2. **Configure environment variables:**

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Edit `.env` with values from Part 1:
```bash
# OIDC Application (for user login)
CLIENT_ID=your_oidc_client_id
CLIENT_SECRET=your_oidc_client_secret
OKTA_ISSUER=https://your-org.okta.com
REDIRECT_URI=http://localhost:3000/callback

# AI Agent (from registry)
AGENT_CLIENT_ID=your_agent_client_id
AGENT_PRIVATE_KEY_JWK={"kty":"RSA","kid":"...","n":"...","e":"...","d":"...","p":"...","q":"..."}
AGENT_KEY_ID=your_key_id

# Custom Authorization Server (the resource)
RESOURCE_TOKEN_ENDPOINT=https://your-org.okta.com/oauth2/{authServerId}/v1/token
JAG_AUDIENCE=https://your-org.okta.com/oauth2/{authServerId}/v1/token
RESOURCE_AUDIENCE=https://your-org.okta.com/oauth2/{authServerId}/v1/token

# Optional
JAG_ISSUER=https://your-org.okta.com/oauth2
JAG_SCOPE=ai_agent
PORT=3000
```

3. **Run the application:**
```bash
node index.js
```

4. **Open your browser:**
```
http://localhost:3000
```

---

## 🎬 Running the Demo

### Quick Demo Flow
1. Click **"Start Authentication"** to initiate login
2. Authenticate with your Okta credentials
3. Watch the Cross-App access token exchange 
4. Explore the three tokens acquired:
   - **ID Token**: User identity from Okta
   - **JAG-ID Token**: Intermediate token proving agent authorization
   - **Access Token**: Final token for accessing the resource
5. Optionally: demonstrate AI Agent access control by revoking OAuth scopes or modifying user/group assignments within the Okta Custom Authorization Server.

## 📋 How It Works

### Three-Step Token Exchange

```
User → Login → Okta OIDC
                  ↓
        [1] Authorization Code → ID Token
                  ↓
        [2] ID Token → JAG-ID Token (AI Agent authenticates)
                  ↓
        [3] JAG-ID Token → Access Token (AI Agent authenticates)
                  ↓
              Resource Access
```

#### Step 1: User Authentication
- **Grant Type**: `authorization_code` with PKCE
- **Auth Server**: Okta Org Authorization Server
- **Result**: ID Token with user identity

#### Step 2: JAG Token Exchange
- **Grant Type**: `urn:ietf:params:oauth:grant-type:token-exchange`
- **Subject Token**: ID Token from Step 1
- **Client Auth**: JWT assertion signed by AI agent private key
- **Result**: JAG-ID Token proving agent authorization

#### Step 3: Access Token Exchange
- **Grant Type**: `urn:ietf:params:oauth:grant-type:jwt-bearer`
- **Assertion**: JAG-ID Token from Step 2
- **Client Auth**: JWT assertion signed by AI agent private key (different audience)
- **Result**: Access Token for the resource server

### Client Assertion (Key Security Mechanism)

The AI agent authenticates using signed JWTs instead of client secrets:

```json
{
  "iss": "agent_client_id",
  "sub": "agent_client_id",
  "aud": "https://your-org.okta.com/oauth2/{authServerId}/v1/token",
  "iat": 1234567890,
  "exp": 1234567950
}
```

Signed with RS256 using the agent's private key. This proves the agent's identity without shared secrets.

---

## 🎨 Demo Features

- **Visual step-by-step flow** with expandable token displays
- **Decoded JWT payloads** for easy inspection
- **Copy buttons** for all tokens
- **Request/response details** for each API call
- **Error handling** with detailed troubleshooting info

---

## 🔧 Troubleshooting

### "Invalid client_assertion"
- Verify `AGENT_PRIVATE_KEY_JWK` is valid JSON with all required fields
- Ensure `AGENT_KEY_ID` matches the key registered in Okta
- Check that the audience (`aud`) matches the token endpoint exactly

### "Invalid issuer"
- Use `https://your-org.okta.com` (not `/oauth2/default`)
- JAG exchange requires the Org Authorization Server

### "Audience claim must match"
- Set `JAG_AUDIENCE` to the custom authorization server's token endpoint
- Both `JAG_AUDIENCE` and `RESOURCE_AUDIENCE` should point to the same endpoint
- Example: `https://your-org.okta.com/oauth2/auszwbroacewkklqb697/v1/token`

### "Access denied" or "Invalid policy"
- Verify the policy is assigned to the **AI Agent** (not the OIDC app)
- Ensure the rule has **JWT Bearer** grant type enabled
- Check that the managed connection exists between agent and auth server

---

## 📦 Environment Variables Reference

| Variable | Description | Where to Find |
|----------|-------------|---------------|
| `CLIENT_ID` | OIDC app client ID | Applications > Your OIDC App > General |
| `CLIENT_SECRET` | OIDC app client secret | Applications > Your OIDC App > General |
| `OKTA_ISSUER` | Your Okta org URL | `https://your-org.okta.com` |
| `AGENT_CLIENT_ID` | AI agent client ID | Applications > AI Agents > Your Agent |
| `AGENT_PRIVATE_KEY_JWK` | Agent private key | Generated when creating AI agent |
| `AGENT_KEY_ID` | Agent key identifier | Shown in AI agent key management |
| `RESOURCE_TOKEN_ENDPOINT` | Custom auth server token URL | Security > API > Your Auth Server |
| `JAG_AUDIENCE` | Same as `RESOURCE_TOKEN_ENDPOINT` | Security > API > Your Auth Server |
| `RESOURCE_AUDIENCE` | Same as `RESOURCE_TOKEN_ENDPOINT` | Security > API > Your Auth Server |

---

## 📚 Additional Resources

- [Okta AI Agent Token Exchange Guide](https://developer.okta.com/docs/guides/ai-agent-token-exchange/service-account/main/) - Complete architecture and flow details
- [Register an AI Agent](https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-register.htm) - Step-by-step registration guide
- [Connect AI Agent to Authorization Server](https://help.okta.com/oie/en-us/content/topics/ai-agents/ai-agent-auth-server.htm) - Managed connections setup
- [OAuth 2.0 Token Exchange RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) - Token exchange specification

---

## 📄 License

This is example code for demonstration and training purposes.

---

## 🤝 Support

For issues related to:
- **This demo app**: Check console logs and error messages
- **Okta configuration**: Consult the guides above or contact Okta support
- **SE training questions**: Refer to internal SE enablement resources
