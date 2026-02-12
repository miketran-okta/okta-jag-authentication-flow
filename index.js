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

// Utility: Generate human-friendly error message based on HTTP status and step
function getHumanFriendlyError(httpStatus, failedStepName, errorDetails, isOAuthError) {
  // Handle OAuth authorization errors (returned via redirect, not HTTP response)
  if (isOAuthError) {
    if (errorDetails?.error === 'access_denied') {
      return {
        title: 'Application Access Not Granted',
        description: 'You do not have permission to access this application. Users must be assigned to the application in Okta before they can authenticate. Please contact your Okta administrator to request access.',
        icon: '🚫'
      };
    }
    // Handle other OAuth errors
    return {
      title: 'Authorization Error',
      description: `The authorization request failed: ${errorDetails?.error_description || errorDetails?.error || 'Unknown error'}. Please try again or contact your administrator.`,
      icon: '⚠️'
    };
  }

  if (!httpStatus) {
    return {
      title: 'Connection Error',
      description: 'Unable to connect to the authorization server. Please check your network connection and configuration.',
      icon: '🔌'
    };
  }

  switch (httpStatus) {
    case 400:
      // Check for specific error types in the response
      if (errorDetails?.error === 'invalid_grant') {
        return {
          title: 'Invalid Token or Grant',
          description: `The ${failedStepName} failed because the provided token or grant was invalid or expired. This could indicate a misconfigured token exchange or an expired assertion.`,
          icon: '⏰'
        };
      }
      return {
        title: 'Bad Request',
        description: `The ${failedStepName} request was malformed or contained invalid parameters. Check your configuration settings.`,
        icon: '⚠️'
      };

    case 401:
      return {
        title: 'Access Denied by Authorization Policy',
        description: `The MCP authorization server denied the ${failedStepName} request due to the client having insufficient permissions while attempting to access the protected resource.`,
        icon: '🚫'
      };

    case 403:
      return {
        title: 'Forbidden',
        description: `The ${failedStepName} was rejected due to insufficient permissions. The client may not be authorized to perform this action.`,
        icon: '🔒'
      };

    case 404:
      return {
        title: 'Endpoint Not Found',
        description: `The ${failedStepName} endpoint was not found. Verify that your OKTA_ISSUER and RESOURCE_TOKEN_ENDPOINT configuration values are correct.`,
        icon: '❓'
      };

    case 500:
    case 502:
    case 503:
    case 504:
      return {
        title: 'Server Error',
        description: `The authorization server encountered an error while processing the ${failedStepName}. This is typically a temporary issue. Please try again.`,
        icon: '🔥'
      };

    default:
      return {
        title: `Error (HTTP ${httpStatus})`,
        description: `The ${failedStepName} failed with HTTP status ${httpStatus}. Check the error details below for more information.`,
        icon: '❌'
      };
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
  const { code, state, error, error_description } = req.query;

  // Check if Okta returned an error (e.g., user not assigned to application)
  if (error) {
    const results = {
      steps: [],
      tokens: {},
      errors: [{
        message: error_description || error,
        details: {
          error: error,
          error_description: error_description
        },
        timestamp: new Date().toISOString(),
        httpStatus: null, // No HTTP status since this is an OAuth error from redirect
        failedStep: 0, // Failed before any token exchange steps
        failedStepName: 'User Authentication',
        failedEndpoint: `${config.issuer}/oauth2/v1/authorize`,
        oauthError: true // Flag to indicate this is an OAuth authorization error
      }]
    };

    // Clean up session if it exists
    if (state && sessions.has(state)) {
      sessions.delete(state);
    }

    return res.status(403).send(generateErrorHTML(results));
  }

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

    // Determine which step failed based on what tokens we have
    let failedStep = 1;
    let failedStepName = 'ID Token Exchange';
    let failedEndpoint = `${config.issuer}/oauth2/v1/token`;

    if (results.tokens.idToken && !results.tokens.jagToken) {
      failedStep = 2;
      failedStepName = 'JAG-ID Token Exchange';
      failedEndpoint = `${config.issuer}/oauth2/v1/token`;
    } else if (results.tokens.jagToken && !results.tokens.accessToken) {
      failedStep = 3;
      failedStepName = 'Access Token Exchange';
      failedEndpoint = config.resourceTokenEndpoint;
    }

    // Capture the failed request details if available
    let failedRequest = null;
    if (error.config) {
      const requestUrl = new URL(error.config.url);
      const requestHost = requestUrl.host;
      const requestPath = requestUrl.pathname;

      failedRequest = {
        method: error.config.method.toUpperCase(),
        url: error.config.url,
        headers: error.config.headers,
        body: error.config.data || '',
        raw: `${error.config.method.toUpperCase()} ${requestPath} HTTP/1.1
Host: ${requestHost}
Content-Type: ${error.config.headers['Content-Type'] || 'application/x-www-form-urlencoded'}

${error.config.data || ''}`
      };
    }

    // Capture the error response
    let errorResponse = null;
    if (error.response) {
      errorResponse = {
        status: error.response.status,
        statusText: error.response.statusText,
        data: error.response.data,
        raw: `HTTP/1.1 ${error.response.status} ${error.response.statusText}
Content-Type: application/json

${JSON.stringify(error.response.data, null, 2)}`
      };
    }

    results.errors.push({
      message: error.message,
      details: error.response?.data || null,
      timestamp: new Date().toISOString(),
      httpStatus: error.response?.status,
      failedStep: failedStep,
      failedStepName: failedStepName,
      failedEndpoint: failedEndpoint,
      request: failedRequest,
      response: errorResponse
    });

    sessions.delete(state);
    res.status(500).send(generateErrorHTML(results));
  }
});

// Generate Results HTML
function generateResultsHTML(results) {
  // Extract contextual information for the success description
  const userEmail = results.tokens.idToken?.payload?.email || results.tokens.idToken?.payload?.sub || 'Unknown User';
  const userSub = results.tokens.idToken?.payload?.sub || 'N/A';
  const agentClientId = config.agentClientId || 'N/A';
  const finalScope = results.tokens.accessToken?.scope || 'N/A';
  const targetAudience = results.tokens.accessToken?.payload?.aud || 'N/A';

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
          border-left: 6px solid #4caf50;
        }
        .header h1 {
          color: #333;
          margin-bottom: 10px;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .success-icon {
          font-size: 36px;
        }
        .success-badge {
          display: inline-block;
          background: #4caf50;
          color: white;
          padding: 8px 16px;
          border-radius: 20px;
          font-weight: bold;
          font-size: 14px;
          margin-top: 10px;
        }
        .success-description {
          background: #d4edda;
          border-left: 4px solid #28a745;
          padding: 15px;
          margin-top: 15px;
          border-radius: 4px;
        }
        .success-description h3 {
          color: #155724;
          margin-bottom: 8px;
          font-size: 16px;
        }
        .success-description p {
          color: #155724;
          line-height: 1.5;
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
        .progress-indicator {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin: 25px 0;
          padding: 0 20px;
          gap: 20px;
        }
        .security-boundary {
          flex: 1;
          background: rgba(102, 126, 234, 0.05);
          border: 2px solid rgba(102, 126, 234, 0.2);
          border-radius: 12px;
          padding: 15px 10px 10px 10px;
          position: relative;
        }
        .security-boundary.resource-server {
          background: rgba(118, 75, 162, 0.05);
          border-color: rgba(118, 75, 162, 0.2);
        }
        .boundary-label {
          position: absolute;
          top: -10px;
          left: 50%;
          transform: translateX(-50%);
          background: white;
          padding: 2px 12px;
          font-size: 11px;
          font-weight: 600;
          color: #667eea;
          border-radius: 10px;
          white-space: nowrap;
          display: flex;
          align-items: center;
          gap: 5px;
        }
        .security-boundary.resource-server .boundary-label {
          color: #764ba2;
        }
        .boundary-steps {
          display: flex;
          justify-content: space-around;
          align-items: center;
          position: relative;
        }
        .progress-step {
          display: flex;
          flex-direction: column;
          align-items: center;
          flex: 1;
          position: relative;
        }
        .token-transition {
          position: absolute;
          right: -25px;
          top: 15px;
          font-size: 20px;
          color: #667eea;
          z-index: 10;
          background: white;
          padding: 2px;
          border-radius: 50%;
        }
        .boundary-steps .progress-step:first-child::after {
          content: '';
          position: absolute;
          top: 20px;
          left: 50%;
          width: 100%;
          height: 3px;
          background: #e0e0e0;
          z-index: 0;
        }
        .boundary-steps .progress-step:first-child.completed::after {
          background: #4caf50;
        }
        .boundary-steps .progress-step:first-child.failed::after {
          background: #f44336;
        }
        .progress-icon {
          width: 40px;
          height: 40px;
          border-radius: 50%;
          background: #e0e0e0;
          color: #999;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 18px;
          font-weight: bold;
          z-index: 1;
          position: relative;
          border: 3px solid white;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .progress-step.completed .progress-icon {
          background: #4caf50;
          color: white;
        }
        .progress-step.failed .progress-icon {
          background: #f44336;
          color: white;
        }
        .progress-step.pending .progress-icon {
          background: #e0e0e0;
          color: #999;
        }
        .progress-label {
          margin-top: 10px;
          font-size: 12px;
          text-align: center;
          color: #333;
          font-weight: 500;
          max-width: 120px;
          line-height: 1.3;
        }
        .progress-step.completed .progress-label {
          color: #4caf50;
          font-weight: 600;
        }
        .progress-step.failed .progress-label {
          color: #f44336;
          font-weight: 600;
        }
        .progress-step.pending .progress-label {
          color: #999;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>
            <span class="success-icon">✅</span>
            Access Granted Successfully
          </h1>
          <span class="success-badge">Success</span>

          <div class="success-description">
            <p>The full Cross App Access token exchange flow was successful. The user was authenticated via Okta by the application, the AI agent exchanged the ID token for a JAG-ID token, and finally received an access token from the MCP authorization server to access the protected resource.</p>

            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #c3e6cb;">
              <strong style="display: block; margin-bottom: 8px;">Context:</strong>
              <div style="display: grid; grid-template-columns: auto 1fr; gap: 8px 12px; font-size: 13px;">
                <span style="font-weight: 600;">👤 User:</span>
                <span>${userEmail}${userSub !== 'N/A' && userSub !== userEmail ? ` (${userSub})` : ''}</span>

                <span style="font-weight: 600;">🤖 Agent:</span>
                <span>${agentClientId}</span>

                ${finalScope !== 'N/A' ? `
                  <span style="font-weight: 600;">🎯 Granted Scope:</span>
                  <span>${finalScope}</span>
                ` : ''}

                ${targetAudience !== 'N/A' ? `
                  <span style="font-weight: 600;">🎫 Token Audience:</span>
                  <span>${targetAudience}</span>
                ` : ''}
              </div>
            </div>
          </div>

          <div class="progress-indicator">
            <div class="security-boundary">
              <div class="boundary-label">🔐 Identity Provider</div>
              <div class="boundary-steps">
                <div class="progress-step completed">
                  <div class="progress-icon">✓</div>
                  <div class="progress-label">User Authentication (ID token)</div>
                </div>
                <div class="progress-step completed">
                  <div class="progress-icon">✓</div>
                  <div class="progress-label">AI Agent Connection (ID-JAG token)</div>
                  <div class="token-transition">→</div>
                </div>
              </div>
            </div>
            <div class="security-boundary resource-server">
              <div class="boundary-label">🏢 Resource Server</div>
              <div class="boundary-steps">
                <div class="progress-step completed">
                  <div class="progress-icon">✓</div>
                  <div class="progress-label">AI Agent Authorization (Access token)</div>
                </div>
                <div class="progress-step completed">
                  <div class="progress-icon">✓</div>
                  <div class="progress-label">Resource Access</div>
                </div>
              </div>
            </div>
          </div>
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
  const error = results.errors[0];
  const friendlyError = getHumanFriendlyError(error.httpStatus, error.failedStepName, error.details, error.oauthError);

  // Extract contextual information for the error description
  const userEmail = results.tokens.idToken?.payload?.email || results.tokens.idToken?.payload?.sub || 'Unknown User';
  const userSub = results.tokens.idToken?.payload?.sub || 'N/A';
  const agentClientId = config.agentClientId || 'N/A';

  // Determine what was being requested based on the failed step
  let requestedScope = 'N/A';
  let requestedAudience = 'N/A';

  if (error.failedStep === 2) {
    // JAG Token Exchange
    requestedScope = config.jagScope || 'ai_agent';
    requestedAudience = config.jagTargetAudience || 'N/A';
  } else if (error.failedStep === 3) {
    // Access Token Exchange
    requestedScope = results.tokens.jagToken?.scope || 'N/A';
    requestedAudience = results.tokens.jagToken?.payload?.aud || 'N/A';
  }

  // Determine progress indicator state based on failed step
  let progressSteps = [
    { label: 'User Authentication (ID token)', icon: '👤', status: 'pending' },
    { label: 'AI Agent Connection (ID-JAG token)', icon: '🔐', status: 'pending' },
    { label: 'AI Agent Authorization (Access token)', icon: '🎫', status: 'pending' },
    { label: 'Resource Access', icon: '✅', status: 'pending' }
  ];

  // Mark steps based on what was completed
  if (error.failedStep === 0) {
    // OAuth authorization error - user authentication failed
    progressSteps[0].status = 'failed';
    progressSteps[0].icon = '✗';
    // All subsequent steps also fail
    progressSteps[1].status = 'failed';
    progressSteps[1].icon = '✗';
    progressSteps[2].status = 'failed';
    progressSteps[2].icon = '✗';
    progressSteps[3].status = 'failed';
    progressSteps[3].icon = '✗';
  } else if (error.failedStep === 1) {
    // ID Token exchange failed - user auth succeeded but token exchange failed
    progressSteps[0].status = 'completed';
    progressSteps[0].icon = '✓';
    progressSteps[1].status = 'failed';
    progressSteps[1].icon = '✗';
    // Subsequent steps also fail
    progressSteps[2].status = 'failed';
    progressSteps[2].icon = '✗';
    progressSteps[3].status = 'failed';
    progressSteps[3].icon = '✗';
  } else if (error.failedStep === 2) {
    // JAG Token exchange failed - user auth succeeded, attempting agent policy check
    progressSteps[0].status = 'completed';
    progressSteps[0].icon = '✓';
    progressSteps[1].status = 'failed';
    progressSteps[1].icon = '✗';
    // Subsequent steps also fail
    progressSteps[2].status = 'failed';
    progressSteps[2].icon = '✗';
    progressSteps[3].status = 'failed';
    progressSteps[3].icon = '✗';
  } else if (error.failedStep === 3) {
    // Access Token exchange failed - JAG succeeded, token grant failed
    progressSteps[0].status = 'completed';
    progressSteps[0].icon = '✓';
    progressSteps[1].status = 'completed';
    progressSteps[1].icon = '✓';
    progressSteps[2].status = 'failed';
    progressSteps[2].icon = '✗';
    // Resource access also fails since we don't have an access token
    progressSteps[3].status = 'failed';
    progressSteps[3].icon = '✗';
  }

  // Generate progress indicator HTML with security boundaries
  const progressHTML = `
    <div class="progress-indicator">
      <div class="security-boundary">
        <div class="boundary-label">🔐 Identity Provider</div>
        <div class="boundary-steps">
          <div class="progress-step ${progressSteps[0].status}">
            <div class="progress-icon">${progressSteps[0].icon}</div>
            <div class="progress-label">${progressSteps[0].label}</div>
          </div>
          <div class="progress-step ${progressSteps[1].status}">
            <div class="progress-icon">${progressSteps[1].icon}</div>
            <div class="progress-label">${progressSteps[1].label}</div>
            <div class="token-transition">→</div>
          </div>
        </div>
      </div>
      <div class="security-boundary resource-server">
        <div class="boundary-label">🏢 Resource Server</div>
        <div class="boundary-steps">
          <div class="progress-step ${progressSteps[2].status}">
            <div class="progress-icon">${progressSteps[2].icon}</div>
            <div class="progress-label">${progressSteps[2].label}</div>
          </div>
          <div class="progress-step ${progressSteps[3].status}">
            <div class="progress-icon">${progressSteps[3].icon}</div>
            <div class="progress-label">${progressSteps[3].label}</div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Build tokens section HTML showing all successfully acquired tokens
  let tokensHTML = '';

  // Show ID Token if acquired
  if (results.tokens.idToken) {
    tokensHTML += `
      <div class="step">
        <h2>Step 1: ID Token Acquired ✓</h2>
        <div class="step-meta">
          Endpoint: ${results.steps[0].endpoint}<br>
          Time: ${results.steps[0].timestamp}
        </div>

        <div class="token-section">
          <h3>
            🔑 ID Token
            <button class="copy-btn" onclick="copyToClipboard('${results.tokens.idToken.token}')">Copy</button>
          </h3>
          <div class="token-display">${results.tokens.idToken.token}</div>

          <h3>📄 Decoded Payload</h3>
          <div class="payload-display"><pre>${JSON.stringify(results.tokens.idToken.payload, null, 2)}</pre></div>
        </div>
      </div>
    `;
  }

  // Show JAG Token if acquired
  if (results.tokens.jagToken) {
    tokensHTML += `
      <div class="step">
        <h2>Step 2: JAG-ID Token Acquired ✓</h2>
        <div class="step-meta">
          Endpoint: ${results.steps[1].endpoint}<br>
          Time: ${results.steps[1].timestamp}
        </div>

        <div class="token-section">
          <h3>
            🔐 JAG Client Assertion
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
        </div>
      </div>
    `;
  }

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Token Flow Error</title>
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
        .error-header {
          background: white;
          padding: 30px;
          border-radius: 10px;
          margin-bottom: 20px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
          border-left: 6px solid #f44336;
        }
        .error-header h1 {
          color: #333;
          margin-bottom: 10px;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .error-icon {
          font-size: 36px;
        }
        .error-badge {
          display: inline-block;
          background: #f44336;
          color: white;
          padding: 8px 16px;
          border-radius: 20px;
          font-weight: bold;
          font-size: 14px;
          margin-top: 10px;
        }
        .error-description {
          background: #fff3cd;
          border-left: 4px solid #ffc107;
          padding: 15px;
          margin-top: 15px;
          border-radius: 4px;
        }
        .error-description h3 {
          color: #856404;
          margin-bottom: 8px;
          font-size: 16px;
        }
        .error-description p {
          color: #856404;
          line-height: 1.5;
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
        .step.failed::before {
          content: '✗';
          background: #f44336;
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
        .error-details {
          background: #f8f9fa;
          padding: 15px;
          border-radius: 6px;
          margin-top: 15px;
        }
        .error-details h3 {
          color: #495057;
          font-size: 16px;
          margin-bottom: 10px;
        }
        pre {
          margin: 0;
          white-space: pre-wrap;
          word-wrap: break-word;
          background: #fff;
          padding: 12px;
          border-radius: 4px;
          border: 1px solid #dee2e6;
          font-family: 'Courier New', monospace;
          font-size: 11px;
          max-height: 300px;
          overflow-y: auto;
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
        .progress-indicator {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin: 25px 0;
          padding: 0 20px;
          gap: 20px;
        }
        .security-boundary {
          flex: 1;
          background: rgba(102, 126, 234, 0.05);
          border: 2px solid rgba(102, 126, 234, 0.2);
          border-radius: 12px;
          padding: 15px 10px 10px 10px;
          position: relative;
        }
        .security-boundary.resource-server {
          background: rgba(118, 75, 162, 0.05);
          border-color: rgba(118, 75, 162, 0.2);
        }
        .boundary-label {
          position: absolute;
          top: -10px;
          left: 50%;
          transform: translateX(-50%);
          background: white;
          padding: 2px 12px;
          font-size: 11px;
          font-weight: 600;
          color: #667eea;
          border-radius: 10px;
          white-space: nowrap;
          display: flex;
          align-items: center;
          gap: 5px;
        }
        .security-boundary.resource-server .boundary-label {
          color: #764ba2;
        }
        .boundary-steps {
          display: flex;
          justify-content: space-around;
          align-items: center;
          position: relative;
        }
        .progress-step {
          display: flex;
          flex-direction: column;
          align-items: center;
          flex: 1;
          position: relative;
        }
        .token-transition {
          position: absolute;
          right: -25px;
          top: 15px;
          font-size: 20px;
          color: #667eea;
          z-index: 10;
          background: white;
          padding: 2px;
          border-radius: 50%;
        }
        .boundary-steps .progress-step:first-child::after {
          content: '';
          position: absolute;
          top: 20px;
          left: 50%;
          width: 100%;
          height: 3px;
          background: #e0e0e0;
          z-index: 0;
        }
        .boundary-steps .progress-step:first-child.completed::after {
          background: #4caf50;
        }
        .boundary-steps .progress-step:first-child.failed::after {
          background: #f44336;
        }
        .progress-icon {
          width: 40px;
          height: 40px;
          border-radius: 50%;
          background: #e0e0e0;
          color: #999;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 18px;
          font-weight: bold;
          z-index: 1;
          position: relative;
          border: 3px solid white;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .progress-step.completed .progress-icon {
          background: #4caf50;
          color: white;
        }
        .progress-step.failed .progress-icon {
          background: #f44336;
          color: white;
        }
        .progress-step.pending .progress-icon {
          background: #e0e0e0;
          color: #999;
        }
        .progress-label {
          margin-top: 10px;
          font-size: 12px;
          text-align: center;
          color: #333;
          font-weight: 500;
          max-width: 120px;
          line-height: 1.3;
        }
        .progress-step.completed .progress-label {
          color: #4caf50;
          font-weight: 600;
        }
        .progress-step.failed .progress-label {
          color: #f44336;
          font-weight: 600;
        }
        .progress-step.pending .progress-label {
          color: #999;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="error-header">
          <h1>
            <span class="error-icon">${friendlyError.icon}</span>
            ${friendlyError.title}
          </h1>
          <span class="error-badge">Access Denied</span>

          <div class="error-description">

            <p>${friendlyError.description}</p>

            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #ffeaa7;">
              <strong style="display: block; margin-bottom: 8px;">Context:</strong>
              <div style="display: grid; grid-template-columns: auto 1fr; gap: 8px 12px; font-size: 13px;">
                <span style="font-weight: 600;">👤 User:</span>
                <span>${userEmail}${userSub !== 'N/A' && userSub !== userEmail ? ` (${userSub})` : ''}</span>

                <span style="font-weight: 600;">🤖 Agent:</span>
                <span>${agentClientId}</span>

                ${requestedScope !== 'N/A' ? `
                  <span style="font-weight: 600;">🎯 Requested Scope:</span>
                  <span>${requestedScope}</span>
                ` : ''}

                ${requestedAudience !== 'N/A' ? `
                  <span style="font-weight: 600;">🎫 Target Audience:</span>
                  <span>${requestedAudience}</span>
                ` : ''}
              </div>
            </div>
          </div>

          ${progressHTML}
        </div>

        <div class="timeline">
          ${tokensHTML}

          <!-- Failed Step -->
          <div class="step failed">
            <h2>${error.failedStep > 0 ? `Step ${error.failedStep}:` : ''} ${error.failedStepName} ✗</h2>
            <div class="step-meta">
              ${error.oauthError ? 'Authorization' : 'Token'} Endpoint: ${error.failedEndpoint}<br>
              Time: ${error.timestamp}
            </div>

            ${error.oauthError ? `
              <div class="error-details">
                <h3>Authorization Error Details</h3>
                <div style="background: #fff; padding: 12px; border-radius: 4px; border: 1px solid #dee2e6; margin-top: 10px;">
                  <div style="margin-bottom: 8px;"><strong>Error:</strong> ${error.details.error}</div>
                  <div><strong>Description:</strong> ${error.details.error_description || 'No additional details provided'}</div>
                </div>
              </div>
            ` : ''}

            ${!error.oauthError && error.request ? `
              <div class="error-details">
                <h3>📤 HTTP Request (Failed)</h3>
                <pre>${error.request.raw}</pre>
              </div>
            ` : ''}

            ${!error.oauthError && error.response ? `
              <div class="error-details">
                <h3>📥 Error Response (HTTP ${error.response.status})</h3>
                <pre>${error.response.raw}</pre>
              </div>
            ` : !error.oauthError ? `
              <div class="error-details">
                <h3>Error Details</h3>
                <pre>${error.message}</pre>
              </div>
            ` : ''}
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
