require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const querystring = require('querystring');
const { SignJWT } = require('jose');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration from .env
const config = {
  // OIDC Client Configuration
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  issuer: process.env.OKTA_ISSUER,
  redirectUri: process.env.REDIRECT_URI || `http://localhost:${PORT}/callback`,
  scopes: ['openid', 'profile', 'email'],
  
  // AI Agent Configuration
  agentClientId: process.env.AGENT_CLIENT_ID,
  agentPrivateKeyJwk: process.env.AGENT_PRIVATE_KEY_JWK ? JSON.parse(process.env.AGENT_PRIVATE_KEY_JWK) : null,
  agentKeyId: process.env.AGENT_KEY_ID,
  
  // JAG Exchange Configuration
  jagIssuer: process.env.JAG_ISSUER || `${process.env.OKTA_ISSUER}/oauth2`,
  jagAudience: process.env.JAG_AUDIENCE || `${process.env.OKTA_ISSUER}/oauth2/v1/token`,
  jagTargetAudience: process.env.JAG_TARGET_AUDIENCE,
  jagScope: process.env.JAG_SCOPE || 'ai_agent',

  // Resource Server Configuration
  resourceAudience: process.env.RESOURCE_AUDIENCE,
  resourceTokenEndpoint: process.env.RESOURCE_TOKEN_ENDPOINT
};

// Session storage
const sessions = new Map();

// Utility: Generate PKCE challenge
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
}

// Utility: Decode JWT payload
function decodeJWT(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  } catch (e) {
    return null;
  }
}

// Helper: Create client assertion for JAG exchange
async function createJAGClientAssertion() {
  if (!config.agentPrivateKeyJwk) {
    throw new Error('AGENT_PRIVATE_KEY_JWK not configured');
  }

  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({
      alg: config.agentPrivateKeyJwk.alg || 'RS256',
      kid: config.agentKeyId
    })
    .setIssuer(config.agentClientId)
    .setSubject(config.agentClientId)
    .setAudience(config.jagAudience)
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .sign(crypto.createPrivateKey({
      key: config.agentPrivateKeyJwk,
      format: 'jwk'
    }));

  return assertion;
}

// Helper: Create client assertion for resource server
async function createResourceClientAssertion() {
  if (!config.agentPrivateKeyJwk) {
    throw new Error('AGENT_PRIVATE_KEY_JWK not configured');
  }

  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({
      alg: config.agentPrivateKeyJwk.alg || 'RS256',
      kid: config.agentKeyId
    })
    .setIssuer(config.agentClientId)
    .setSubject(config.agentClientId)
    .setAudience(config.resourceAudience)
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .sign(crypto.createPrivateKey({
      key: config.agentPrivateKeyJwk,
      format: 'jwk'
    }));

  return assertion;
}

// Route 1: Home page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Okta JAG Token Flow</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 800px;
          margin: 50px auto;
          padding: 20px;
          background: #f5f5f5;
        }
        .container {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
          color: #333;
          border-bottom: 3px solid #007bff;
          padding-bottom: 10px;
        }
        .info {
          background: #e3f2fd;
          padding: 15px;
          border-radius: 4px;
          margin: 20px 0;
        }
        .info h3 {
          margin-top: 0;
          color: #1976d2;
        }
        .info ol {
          margin: 10px 0;
          padding-left: 20px;
        }
        .info li {
          margin: 5px 0;
        }
        .login-button {
          display: inline-block;
          padding: 12px 30px;
          background: #007bff;
          color: white;
          text-decoration: none;
          border-radius: 4px;
          font-weight: bold;
          transition: background 0.3s;
        }
        .login-button:hover {
          background: #0056b3;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔐 Okta JAG Token Exchange Flow</h1>
        <div class="info">
          <h3>What happens when you click "Start Authentication":</h3>
          <ol>
            <li><strong>User Login:</strong> You'll be redirected to Okta to log in</li>
            <li><strong>ID Token:</strong> After login, receive an ID token from Okta</li>
            <li><strong>JAG Token Exchange:</strong> Automatically exchange ID token for JAG-ID token</li>
            <li><strong>Access Token Exchange:</strong> Automatically exchange JAG-ID token for final access token</li>
            <li><strong>Results:</strong> View all tokens and their decoded payloads</li>
          </ol>
        </div>
        <p><a href="/login" class="login-button">🚀 Start Authentication</a></p>
      </div>
    </body>
    </html>
  `);
});

// Route 2: Initiate login
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const pkce = generatePKCE();
  
  sessions.set(state, {
    codeVerifier: pkce.verifier,
    timestamp: Date.now()
  });
  
  const authParams = {
    client_id: config.clientId,
    response_type: 'code',
    scope: config.scopes.join(' '),
    redirect_uri: config.redirectUri,
    state: state,
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256'
  };
  
  const authUrl = `${config.issuer}/oauth2/v1/authorize?${querystring.stringify(authParams)}`;
  
  console.log('\n[STEP 1] Redirecting to Okta authorization...');
  console.log(`Authorization URL: ${authUrl}`);
  
  res.redirect(authUrl);
});

// Route 3: Handle callback and run complete flow
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code || !state) {
    return res.status(400).send('Missing code or state parameter');
  }
  
  const session = sessions.get(state);
  if (!session) {
    return res.status(400).send('Invalid state parameter');
  }
  
  const results = {
    steps: [],
    tokens: {},
    errors: []
  };
  
  try {
    // ============================================
    // STEP 1: Exchange authorization code for ID token
    // ============================================
    console.log('\n[STEP 2] Exchanging authorization code for ID token...');
    
    const tokenRequestBody = {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: config.redirectUri,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code_verifier: session.codeVerifier
    };
    
    const tokenEndpoint = `${config.issuer}/oauth2/v1/token`;
    
    console.log('Request URL:', tokenEndpoint);
    console.log('Request Body:', { ...tokenRequestBody, client_secret: '[REDACTED]' });
    
    const tokenResponse = await axios.post(
      tokenEndpoint,
      querystring.stringify(tokenRequestBody),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );
    
    console.log('Response:', {
      token_type: tokenResponse.data.token_type,
      expires_in: tokenResponse.data.expires_in,
      scope: tokenResponse.data.scope,
      id_token: tokenResponse.data.id_token.substring(0, 50) + '...'
    });
    
    const idToken = tokenResponse.data.id_token;
    const idTokenPayload = decodeJWT(idToken);

    // Extract host and path from token endpoint
    const tokenHost = new URL(tokenEndpoint).host;
    const tokenPath = new URL(tokenEndpoint).pathname;

    // Build actual HTTP request representation
    const tokenRequestBodyDecoded = Object.entries({
      ...tokenRequestBody,
      client_secret: '[REDACTED]',
      code_verifier: '[REDACTED]'
    }).map(([key, value]) => `${key}=${value}`).join('\n');

    results.steps.push({
      step: 1,
      name: 'ID Token Acquired',
      success: true,
      endpoint: tokenEndpoint,
      timestamp: new Date().toISOString(),
      request: {
        raw: `POST ${tokenPath} HTTP/1.1
Host: ${tokenHost}
Content-Type: application/x-www-form-urlencoded
Content-Length: ${querystring.stringify(tokenRequestBody).length}

${tokenRequestBodyDecoded}`,
        method: 'POST',
        url: tokenEndpoint,
        headers: {
          'Host': tokenHost,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': querystring.stringify(tokenRequestBody).length
        },
        body: tokenRequestBodyDecoded
      },
      response: {
        raw: `HTTP/1.1 200 OK
Content-Type: application/json

${JSON.stringify({
          token_type: tokenResponse.data.token_type,
          expires_in: tokenResponse.data.expires_in,
          scope: tokenResponse.data.scope,
          id_token: '[TOKEN - See below]',
          access_token: tokenResponse.data.access_token ? '[TOKEN]' : undefined,
          refresh_token: tokenResponse.data.refresh_token ? '[TOKEN]' : undefined
        }, null, 2)}`,
        status: 200,
        data: {
          token_type: tokenResponse.data.token_type,
          expires_in: tokenResponse.data.expires_in,
          scope: tokenResponse.data.scope
        }
      }
    });
    
    results.tokens.idToken = {
      token: idToken,
      payload: idTokenPayload
    };
    
    console.log('✓ ID Token acquired');
    console.log('  Issuer:', idTokenPayload.iss);
    console.log('  Subject:', idTokenPayload.sub);
    console.log('  Email:', idTokenPayload.email);
    
    // ============================================
    // STEP 2: Exchange ID token for JAG token
    // ============================================
    console.log('\n[STEP 3] Exchanging ID token for JAG-ID token...');
    
    const jagClientAssertion = await createJAGClientAssertion();
    const jagClientAssertionPayload = decodeJWT(jagClientAssertion);
    
    console.log('Client Assertion Payload:', jagClientAssertionPayload);
    
    results.tokens.jagClientAssertion = {
      token: jagClientAssertion,
      payload: jagClientAssertionPayload
    };
    
    const jagExchangeBody = {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
      subject_token: idToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: jagClientAssertion,
      audience: config.jagTargetAudience,
      scope: config.jagScope
    };
    
    const jagEndpoint = `${config.issuer}/oauth2/v1/token`;
    
    console.log('Request URL:', jagEndpoint);
    console.log('Request Body:', {
      grant_type: jagExchangeBody.grant_type,
      requested_token_type: jagExchangeBody.requested_token_type,
      subject_token_type: jagExchangeBody.subject_token_type,
      audience: jagExchangeBody.audience,
      scope: jagExchangeBody.scope,
      subject_token: jagExchangeBody.subject_token.substring(0, 50) + '...',
      client_assertion: jagExchangeBody.client_assertion.substring(0, 50) + '...'
    });
    
    const jagResponse = await axios.post(
      jagEndpoint,
      querystring.stringify(jagExchangeBody),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );
    
    console.log('Response:', {
      token_type: jagResponse.data.token_type,
      issued_token_type: jagResponse.data.issued_token_type,
      expires_in: jagResponse.data.expires_in,
      scope: jagResponse.data.scope,
      access_token: jagResponse.data.access_token.substring(0, 50) + '...'
    });
    
    const jagToken = jagResponse.data.access_token;
    const jagTokenPayload = decodeJWT(jagToken);

    // Extract host and path from JAG endpoint
    const jagHost = new URL(jagEndpoint).host;
    const jagPath = new URL(jagEndpoint).pathname;

    // Build actual HTTP request representation
    const jagRequestBodyDecoded = Object.entries({
      grant_type: jagExchangeBody.grant_type,
      requested_token_type: jagExchangeBody.requested_token_type,
      subject_token: jagExchangeBody.subject_token.substring(0, 50) + '...[TRUNCATED]',
      subject_token_type: jagExchangeBody.subject_token_type,
      client_assertion_type: jagExchangeBody.client_assertion_type,
      client_assertion: jagExchangeBody.client_assertion.substring(0, 50) + '...[TRUNCATED]',
      audience: jagExchangeBody.audience,
      scope: jagExchangeBody.scope
    }).map(([key, value]) => `${key}=${value}`).join('\n');

    results.steps.push({
      step: 2,
      name: 'JAG-ID Token Acquired',
      success: true,
      endpoint: jagEndpoint,
      timestamp: new Date().toISOString(),
      request: {
        raw: `POST ${jagPath} HTTP/1.1
Host: ${jagHost}
Content-Type: application/x-www-form-urlencoded
Content-Length: ${querystring.stringify(jagExchangeBody).length}

${jagRequestBodyDecoded}`,
        method: 'POST',
        url: jagEndpoint,
        headers: {
          'Host': jagHost,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': querystring.stringify(jagExchangeBody).length
        },
        bodyParams: {
          grant_type: jagExchangeBody.grant_type,
          requested_token_type: jagExchangeBody.requested_token_type,
          subject_token_type: jagExchangeBody.subject_token_type,
          audience: jagExchangeBody.audience,
          scope: jagExchangeBody.scope,
          client_assertion_type: jagExchangeBody.client_assertion_type
        }
      },
      response: {
        raw: `HTTP/1.1 200 OK
Content-Type: application/json

${JSON.stringify({
          token_type: jagResponse.data.token_type,
          issued_token_type: jagResponse.data.issued_token_type,
          expires_in: jagResponse.data.expires_in,
          scope: jagResponse.data.scope,
          access_token: '[JAG-ID TOKEN - See below]'
        }, null, 2)}`,
        status: 200,
        data: {
          token_type: jagResponse.data.token_type,
          issued_token_type: jagResponse.data.issued_token_type,
          expires_in: jagResponse.data.expires_in,
          scope: jagResponse.data.scope
        }
      }
    });
    
    results.tokens.jagToken = {
      token: jagToken,
      payload: jagTokenPayload,
      tokenType: jagResponse.data.token_type,
      issuedTokenType: jagResponse.data.issued_token_type,
      expiresIn: jagResponse.data.expires_in,
      scope: jagResponse.data.scope
    };
    
    console.log('✓ JAG-ID Token acquired');
    console.log('  Issuer:', jagTokenPayload.iss);
    console.log('  Audience:', jagTokenPayload.aud);
    console.log('  Expires In:', jagResponse.data.expires_in, 'seconds');
    
    // ============================================
    // STEP 3: Exchange JAG token for Access token
    // ============================================
    console.log('\n[STEP 4] Exchanging JAG-ID token for Access token...');
    
    const resourceClientAssertion = await createResourceClientAssertion();
    const resourceClientAssertionPayload = decodeJWT(resourceClientAssertion);
    
    console.log('Client Assertion Payload:', resourceClientAssertionPayload);
    
    results.tokens.resourceClientAssertion = {
      token: resourceClientAssertion,
      payload: resourceClientAssertionPayload
    };
    
    const accessExchangeBody = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jagToken,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: resourceClientAssertion
    };
    
    console.log('Request URL:', config.resourceTokenEndpoint);
    console.log('Request Body:', {
      grant_type: accessExchangeBody.grant_type,
      client_assertion_type: accessExchangeBody.client_assertion_type,
      assertion: accessExchangeBody.assertion.substring(0, 50) + '...',
      client_assertion: accessExchangeBody.client_assertion.substring(0, 50) + '...'
    });
    
    const accessResponse = await axios.post(
      config.resourceTokenEndpoint,
      querystring.stringify(accessExchangeBody),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );
    
    console.log('Response:', {
      token_type: accessResponse.data.token_type,
      expires_in: accessResponse.data.expires_in,
      scope: accessResponse.data.scope,
      access_token: accessResponse.data.access_token.substring(0, 50) + '...'
    });
    
    const accessToken = accessResponse.data.access_token;
    const accessTokenPayload = decodeJWT(accessToken);
    
    // Build actual HTTP request representation
    const accessRequestBodyDecoded = Object.entries({
      grant_type: accessExchangeBody.grant_type,
      assertion: accessExchangeBody.assertion.substring(0, 50) + '...[TRUNCATED]',
      client_assertion_type: accessExchangeBody.client_assertion_type,
      client_assertion: accessExchangeBody.client_assertion.substring(0, 50) + '...[TRUNCATED]'
    }).map(([key, value]) => `${key}=${value}`).join('\n');
    
    const resourceHost = config.resourceTokenEndpoint.replace(/^https?:\/\//, '').split('/')[0];
    const resourcePath = config.resourceTokenEndpoint.replace(/^https?:\/\/[^/]+/, '');
    
    results.steps.push({
      step: 3,
      name: 'Access Token Acquired',
      success: true,
      endpoint: config.resourceTokenEndpoint,
      timestamp: new Date().toISOString(),
      request: {
        raw: `POST ${resourcePath} HTTP/1.1
Host: ${resourceHost}
Content-Type: application/x-www-form-urlencoded
Content-Length: ${querystring.stringify(accessExchangeBody).length}

${accessRequestBodyDecoded}`,
        method: 'POST',
        url: config.resourceTokenEndpoint,
        headers: { 
          'Host': resourceHost,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': querystring.stringify(accessExchangeBody).length
        },
        bodyParams: {
          grant_type: accessExchangeBody.grant_type,
          client_assertion_type: accessExchangeBody.client_assertion_type
        }
      },
      response: {
        raw: `HTTP/1.1 200 OK
Content-Type: application/json

${JSON.stringify({
          token_type: accessResponse.data.token_type,
          expires_in: accessResponse.data.expires_in,
          scope: accessResponse.data.scope,
          access_token: '[ACCESS TOKEN - See below]'
        }, null, 2)}`,
        status: 200,
        data: {
          token_type: accessResponse.data.token_type,
          expires_in: accessResponse.data.expires_in,
          scope: accessResponse.data.scope
        }
      }
    });
    
    results.tokens.accessToken = {
      token: accessToken,
      payload: accessTokenPayload,
      tokenType: accessResponse.data.token_type,
      expiresIn: accessResponse.data.expires_in,
      scope: accessResponse.data.scope
    };
    
    console.log('✓ Access Token acquired');
    console.log('  Issuer:', accessTokenPayload.iss);
    console.log('  Subject:', accessTokenPayload.sub);
    console.log('  Expires In:', accessResponse.data.expires_in, 'seconds');
    
    console.log('\n[SUCCESS] ✓ All tokens acquired successfully!\n');
    
    // Store in session
    sessions.set(state, {
      ...session,
      results: results,
      completedAt: Date.now()
    });
    
    // Render results page
    res.send(generateResultsHTML(results));
    
  } catch (error) {
    console.error('\n[ERROR]', error.message);
    if (error.response) {
      console.error('Response Status:', error.response.status);
      console.error('Response Data:', JSON.stringify(error.response.data, null, 2));
    }
    
    results.errors.push({
      message: error.message,
      details: error.response?.data || null,
      timestamp: new Date().toISOString()
    });
    
    sessions.delete(state);
    res.status(500).send(generateErrorHTML(results));
  }
});

// Generate Results HTML
function generateResultsHTML(results) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Token Flow Results</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          padding: 20px;
          min-height: 100vh;
        }
        .container {
          max-width: 1200px;
          margin: 0 auto;
        }
        .header {
          background: white;
          padding: 30px;
          border-radius: 10px;
          margin-bottom: 20px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
          color: #333;
          margin-bottom: 10px;
        }
        .success-badge {
          display: inline-block;
          background: #4caf50;
          color: white;
          padding: 8px 16px;
          border-radius: 20px;
          font-weight: bold;
          font-size: 14px;
        }
        .timeline {
          position: relative;
          padding-left: 40px;
          margin: 20px 0;
        }
        .timeline::before {
          content: '';
          position: absolute;
          left: 15px;
          top: 0;
          bottom: 0;
          width: 2px;
          background: rgba(255,255,255,0.3);
        }
        .step {
          background: white;
          padding: 20px;
          border-radius: 8px;
          margin-bottom: 20px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          position: relative;
        }
        .step::before {
          content: '✓';
          position: absolute;
          left: -32px;
          top: 20px;
          width: 30px;
          height: 30px;
          border-radius: 50%;
          background: #4caf50;
          color: white;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: bold;
          font-size: 16px;
        }
        .step h2 {
          color: #333;
          margin-bottom: 10px;
          font-size: 20px;
        }
        .step-meta {
          color: #666;
          font-size: 13px;
          margin-bottom: 15px;
        }
        .token-section {
          background: #f8f9fa;
          padding: 15px;
          border-radius: 6px;
          margin-top: 15px;
        }
        .token-section h3 {
          color: #495057;
          font-size: 16px;
          margin-bottom: 10px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .copy-btn {
          background: #007bff;
          color: white;
          border: none;
          padding: 4px 12px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 12px;
          transition: background 0.2s;
        }
        .copy-btn:hover {
          background: #0056b3;
        }
        .token-display {
          background: #fff;
          padding: 12px;
          border-radius: 4px;
          border: 1px solid #dee2e6;
          font-family: 'Courier New', monospace;
          font-size: 12px;
          word-break: break-all;
          max-height: 100px;
          overflow-y: auto;
          margin-bottom: 10px;
        }
        .payload-display {
          background: #fff;
          padding: 12px;
          border-radius: 4px;
          border: 1px solid #dee2e6;
          font-family: 'Courier New', monospace;
          font-size: 11px;
          max-height: 200px;
          overflow-y: auto;
        }
        pre {
          margin: 0;
          white-space: pre-wrap;
          word-wrap: break-word;
        }
        .metadata {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 10px;
          margin-top: 10px;
        }
        .metadata-item {
          background: #e9ecef;
          padding: 8px 12px;
          border-radius: 4px;
        }
        .metadata-item strong {
          color: #495057;
          font-size: 12px;
        }
        .metadata-item span {
          display: block;
          color: #6c757d;
          font-size: 11px;
          margin-top: 3px;
        }
        .back-button {
          display: inline-block;
          margin-top: 20px;
          padding: 12px 24px;
          background: white;
          color: #667eea;
          text-decoration: none;
          border-radius: 6px;
          font-weight: bold;
          transition: transform 0.2s;
        }
        .back-button:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🎉 Token Flow Completed Successfully</h1>
          <span class="success-badge">All Steps Completed</span>
        </div>
        
        <div class="timeline">
          <!-- Step 1: ID Token -->
          <div class="step">
            <h2>Step 1: ID Token Acquired</h2>
            <div class="step-meta">
              Endpoint: ${results.steps[0].endpoint}<br>
              Time: ${results.steps[0].timestamp}
            </div>
            
            <div class="token-section">
              <h3>📤 HTTP Request</h3>
              <div class="payload-display"><pre>${results.steps[0].request.raw}</pre></div>
            </div>
            
            <div class="token-section">
              <h3>📥 HTTP Response</h3>
              <div class="payload-display"><pre>${results.steps[0].response.raw}</pre></div>
            </div>
            
            <div class="token-section">
              <h3>
                🔑 ID Token
                <button class="copy-btn" onclick="copyToClipboard('${results.tokens.idToken.token}')">Copy</button>
              </h3>
              <div class="token-display">${results.tokens.idToken.token}</div>
              
              <h3>📄 Decoded Payload</h3>
              <div class="payload-display"><pre>${JSON.stringify(results.tokens.idToken.payload, null, 2)}</pre></div>
              
              <div class="metadata">
                <div class="metadata-item">
                  <strong>Issuer</strong>
                  <span>${results.tokens.idToken.payload.iss}</span>
                </div>
                <div class="metadata-item">
                  <strong>Subject</strong>
                  <span>${results.tokens.idToken.payload.sub}</span>
                </div>
                <div class="metadata-item">
                  <strong>Email</strong>
                  <span>${results.tokens.idToken.payload.email || 'N/A'}</span>
                </div>
              </div>
            </div>
          </div>
          
          <!-- Step 2: JAG Token -->
          <div class="step">
            <h2>Step 2: JAG-ID Token Acquired</h2>
            <div class="step-meta">
              Endpoint: ${results.steps[1].endpoint}<br>
              Time: ${results.steps[1].timestamp}
            </div>
            
            <div class="token-section">
              <h3>📤 HTTP Request</h3>
              <div class="payload-display"><pre>${results.steps[1].request.raw}</pre></div>
            </div>
            
            <div class="token-section">
              <h3>📥 HTTP Response</h3>
              <div class="payload-display"><pre>${results.steps[1].response.raw}</pre></div>
            </div>
            
            <div class="token-section">
              <h3>
                🔐 JAG Client Assertion (used for exchange)
                <button class="copy-btn" onclick="copyToClipboard('${results.tokens.jagClientAssertion.token}')">Copy</button>
              </h3>
              <div class="token-display">${results.tokens.jagClientAssertion.token}</div>
              <div class="payload-display"><pre>${JSON.stringify(results.tokens.jagClientAssertion.payload, null, 2)}</pre></div>
            </div>
            
            <div class="token-section">
              <h3>
                🎫 JAG-ID Token
                <button class="copy-btn" onclick="copyToClipboard('${results.tokens.jagToken.token}')">Copy</button>
              </h3>
              <div class="token-display">${results.tokens.jagToken.token}</div>
              
              <h3>📄 Decoded Payload</h3>
              <div class="payload-display"><pre>${JSON.stringify(results.tokens.jagToken.payload, null, 2)}</pre></div>
              
              <div class="metadata">
                <div class="metadata-item">
                  <strong>Issued Token Type</strong>
                  <span>${results.tokens.jagToken.issuedTokenType}</span>
                </div>
                <div class="metadata-item">
                  <strong>Token Type</strong>
                  <span>${results.tokens.jagToken.tokenType}</span>
                </div>
                <div class="metadata-item">
                  <strong>Expires In</strong>
                  <span>${results.tokens.jagToken.expiresIn} seconds</span>
                </div>
                <div class="metadata-item">
                  <strong>Scope</strong>
                  <span>${results.tokens.jagToken.scope}</span>
                </div>
              </div>
            </div>
          </div>
          
          <!-- Step 3: Access Token -->
          <div class="step">
            <h2>Step 3: Access Token Acquired (Final)</h2>
            <div class="step-meta">
              Endpoint: ${results.steps[2].endpoint}<br>
              Time: ${results.steps[2].timestamp}
            </div>
            
            <div class="token-section">
              <h3>📤 HTTP Request</h3>
              <div class="payload-display"><pre>${results.steps[2].request.raw}</pre></div>
            </div>
            
            <div class="token-section">
              <h3>📥 HTTP Response</h3>
              <div class="payload-display"><pre>${results.steps[2].response.raw}</pre></div>
            </div>
            
            <div class="token-section">
              <h3>
                🔐 Resource Client Assertion (used for exchange)
                <button class="copy-btn" onclick="copyToClipboard('${results.tokens.resourceClientAssertion.token}')">Copy</button>
              </h3>
              <div class="token-display">${results.tokens.resourceClientAssertion.token}</div>
              <div class="payload-display"><pre>${JSON.stringify(results.tokens.resourceClientAssertion.payload, null, 2)}</pre></div>
            </div>
            
            <div class="token-section">
              <h3>
                ✨ Final Access Token
                <button class="copy-btn" onclick="copyToClipboard('${results.tokens.accessToken.token}')">Copy</button>
              </h3>
              <div class="token-display">${results.tokens.accessToken.token}</div>
              
              <h3>📄 Decoded Payload</h3>
              <div class="payload-display"><pre>${JSON.stringify(results.tokens.accessToken.payload, null, 2)}</pre></div>
              
              <div class="metadata">
                <div class="metadata-item">
                  <strong>Token Type</strong>
                  <span>${results.tokens.accessToken.tokenType}</span>
                </div>
                <div class="metadata-item">
                  <strong>Expires In</strong>
                  <span>${results.tokens.accessToken.expiresIn} seconds</span>
                </div>
                <div class="metadata-item">
                  <strong>Scope</strong>
                  <span>${results.tokens.accessToken.scope}</span>
                </div>
                <div class="metadata-item">
                  <strong>Issuer</strong>
                  <span>${results.tokens.accessToken.payload.iss}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <a href="/" class="back-button">← Start New Flow</a>
      </div>
      
      <script>
        function copyToClipboard(text) {
          navigator.clipboard.writeText(text).then(() => {
            alert('Token copied to clipboard!');
          });
        }
      </script>
    </body>
    </html>
  `;
}

// Generate Error HTML
function generateErrorHTML(results) {
  const lastSuccessfulStep = results.steps.length;
  const error = results.errors[0];
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Token Flow Error</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 900px;
          margin: 50px auto;
          padding: 20px;
          background: #f5f5f5;
        }
        .container {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .error-header {
          background: #f44336;
          color: white;
          padding: 20px;
          border-radius: 6px;
          margin-bottom: 20px;
        }
        .error-header h1 {
          margin: 0 0 10px 0;
        }
        .step-status {
          margin: 20px 0;
        }
        .step {
          padding: 15px;
          margin: 10px 0;
          border-radius: 4px;
          border-left: 4px solid #ccc;
        }
        .step.success {
          background: #e8f5e9;
          border-left-color: #4caf50;
        }
        .step.error {
          background: #ffebee;
          border-left-color: #f44336;
        }
        .error-details {
          background: #f5f5f5;
          padding: 15px;
          border-radius: 4px;
          margin: 15px 0;
          font-family: monospace;
          font-size: 12px;
          overflow-x: auto;
        }
        pre {
          margin: 0;
          white-space: pre-wrap;
        }
        .back-button {
          display: inline-block;
          margin-top: 20px;
          padding: 12px 24px;
          background: #007bff;
          color: white;
          text-decoration: none;
          border-radius: 4px;
          font-weight: bold;
        }
        .back-button:hover {
          background: #0056b3;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="error-header">
          <h1>❌ Token Flow Error</h1>
          <p>An error occurred during step ${lastSuccessfulStep + 1}</p>
        </div>
        
        <div class="step-status">
          <h2>Flow Progress:</h2>
          ${results.steps.map((step, i) => `
            <div class="step success">
              <strong>✓ Step ${step.step}: ${step.name}</strong><br>
              <small>${step.timestamp}</small>
            </div>
          `).join('')}
          <div class="step error">
            <strong>✗ Step ${lastSuccessfulStep + 1}: Failed</strong><br>
            <small>${error.timestamp}</small>
          </div>
        </div>
        
        <h2>Error Details:</h2>
        <div class="error-details">
          <strong>Message:</strong> ${error.message}<br>
          ${error.details ? `
            <br><strong>Server Response:</strong>
            <pre>${JSON.stringify(error.details, null, 2)}</pre>
          ` : ''}
        </div>
        
        <a href="/" class="back-button">← Back to Home</a>
      </div>
    </body>
    </html>
  `;
}

// Start server
app.listen(PORT, () => {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║     Okta JAG Token Exchange - Consolidated App            ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log();
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Login URL: http://localhost:${PORT}/login`);
  console.log();
  console.log('Configuration:');
  console.log(`  ├─ Okta Issuer: ${config.issuer}`);
  console.log(`  ├─ Client ID: ${config.clientId}`);
  console.log(`  ├─ Agent Client ID: ${config.agentClientId}`);
  console.log(`  ├─ JAG Audience: ${config.jagAudience}`);
  console.log(`  └─ Resource Endpoint: ${config.resourceTokenEndpoint}`);
  console.log();
  console.log('Ready to authenticate! Visit http://localhost:' + PORT);
  console.log();
});

// Cleanup old sessions
setInterval(() => {
  const now = Date.now();
  for (const [state, session] of sessions.entries()) {
    if (now - session.timestamp > 600000) {
      sessions.delete(state);
    }
  }
}, 60000);
