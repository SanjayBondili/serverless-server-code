const AWS = require('aws-sdk');
const winston = require('winston');
const { CognitoJwtVerifier } = require('aws-jwt-verify');

// Logger configuration
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});

// Cognito client
const cognito = new AWS.CognitoIdentityServiceProvider({ region: process.env.REGION });

// Headers for CORS and security
const headers = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*', // Restrict to specific domains in production
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

// Validate input
const validateInput = (username, password) => {
  if (!username || !password) throw new Error('Username and password are required');
  if (typeof username !== 'string' || typeof password !== 'string') throw new Error('Invalid input type');
};

// Login handler
module.exports.login = async (event) => {
  try {
    logger.debug('Login request received', { event });

    const body = JSON.parse(event.body || '{}');
    const { username, password } = body;

    validateInput(username, password);

    const params = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: process.env.CLIENT_ID,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
      },
    };

    const response = await cognito.initiateAuth(params).promise();

    // Handle NEW_PASSWORD_REQUIRED challenge
    if (response.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
      logger.warn('User requires new password', { username });

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          challenge: 'NEW_PASSWORD_REQUIRED',
          session: response.Session,
          message: 'User must set a new password',
        }),
      };
    }

    const authResult = response.AuthenticationResult;

    if (!authResult) throw new Error('AuthenticationResult missing');

    logger.info('Login successful', { username });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        access_token: authResult.AccessToken,
        id_token: authResult.IdToken,
        refresh_token: authResult.RefreshToken,
        expires_in: authResult.ExpiresIn,
        token_type: authResult.TokenType,
      }),
    };
  } catch (error) {
    logger.error('Login failed', { error: error.message, stack: error.stack });
    return {
      statusCode: error.code === 'NotAuthorizedException' ? 401 : 400,
      headers,
      body: JSON.stringify({ error: error.code || 'InternalError', message: error.message }),
    };
  }
};

// Complete new password challenge handler
module.exports.completeNewPassword = async (event) => {
  try {
    logger.debug('New password challenge request received', { event });

    const body = JSON.parse(event.body || '{}');
    const { username, new_password, session } = body;

    if (!username || !new_password || !session) {
      throw new Error('Username, new_password, and session are required');
    }

    const params = {
      ChallengeName: 'NEW_PASSWORD_REQUIRED',
      ClientId: process.env.CLIENT_ID,
      ChallengeResponses: {
        USERNAME: username,
        NEW_PASSWORD: new_password,
      },
      Session: session,
    };

    const response = await cognito.respondToAuthChallenge(params).promise();
    const authResult = response.AuthenticationResult;

    if (!authResult) throw new Error('AuthenticationResult missing');

    logger.info('New password set and login successful', { username });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        access_token: authResult.AccessToken,
        id_token: authResult.IdToken,
        refresh_token: authResult.RefreshToken,
        expires_in: authResult.ExpiresIn,
        token_type: authResult.TokenType,
      }),
    };
  } catch (error) {
    logger.error('New password challenge failed', { error: error.message, stack: error.stack });
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: error.code || 'InternalError', message: error.message }),
    };
  }
};

// Protected endpoint handler
module.exports.protected = async (event) => {
  try {
    logger.debug('Protected endpoint request', { event });

    const claims = event.requestContext.authorizer?.claims;
    if (!claims) throw new Error('No authorization data');

    logger.info('Access granted', { sub: claims.sub });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        message: 'Welcome to the protected endpoint!',
        user: { sub: claims.sub, email: claims.email },
      }),
    };
  } catch (error) {
    logger.error('Protected endpoint error', { error: error.message, stack: error.stack });
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Forbidden', message: error.message }),
    };
  }
};
