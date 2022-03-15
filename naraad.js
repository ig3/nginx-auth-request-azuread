#!/usr/bin/env node
'use strict';
/**
 * This is the main executable of nginx auth_request server: naraad
 *
 * This provides an interface between nginx and Azure AD OAuth 2.0 for
 * authentication of users accessing nginx.
 */

const getConfig = require('@ig3/config');
const { v4: uuidv4 } = require('uuid');
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const https = require('https');
const querystring = require('querystring');
const validUrl = require('valid-url');

const config = getConfig({
  defaults: {
    server_address: '0.0.0.0',
    server_port: 9090,
    jwtExpiry: '1h'
  }
});
console.log('config: ', JSON.stringify(config, null, 2));

const app = express();

// Add middleware for parsing request bodies when Content-Type is
// application/json or application/x-www-form-urlencoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// JWT tokens are generated with an ephemeral secret. Every time the server
// restarts a new secret is generated and all pre-existing tokens are
// invalidated. A UUID is used as the random secret.
config.jwtSecret = uuidv4();

// Two cookies are set: one to record the original request URI through
// authentication and the other a JWT: effectively a bearer token for the
// authenticated user.
app.use(cookieParser());

//* ***************************
// Add route handlers

// GET /verify handles the primary request from nginx auth_request.
//
// If the user is authenticated, HTTP status 200 is returned. In this case,
// nginx proceeds to server the requested content.
//
// When a user is authenticated, a JWT is stored in cookie authToken. If
// this token can be retrieved and is still valid, the user is
// authenticated. Otherwise, the user is not authenticated.
//
app.get('/verify', (req, res) => {
  console.log('GET /verify ');
  if (!req.cookies.authToken) {
    console.log('No valid authToken');
    return res.sendStatus(401);
  }
  console.log('found an authToken cookie');

  // validate the token: it comes from an untrusted source
  try {
    const payload = jwt.verify(req.cookies.authToken, config.jwtSecret);
    console.log('verified the authToken: ', payload);
    // Generate a new token if the current one will expire soon
    if (!payload.exp || (payload.exp - (Date.now() / 1000)) < 600) {
      console.log('set authToken cookie');
      try {
        // jsonwebtoken won't sign if payload includes exp
        // exp - expiry
        // iat - issued at
        delete payload.iat;
        delete payload.exp;
        const token = jwt.sign(payload, config.jwtSecret,
          { expiresIn: config.jwtExpiry });
        res.cookie('authToken', token, { httpOnly: true });
      } catch (e) {
        console.log('error generating new token: ', e);
      }
    }
  } catch (e) {
    console.log('error validating token: ', e);
    return res.sendStatus(401);
  }

  return res.sendStatus(200);
});

// If the user is not authenticated, /verify will return 401 and that will
// be redirected to this path.
//
// Set a cookie to record the path they were trying to get, as that will not
// survive the redirects through the OAuth protocol.
//
// Redirect to the OAuth authentication URL.
app.get(
  '/authenticate',
  (req, res, next) => {
    if (!req.headers['x-original-uri']) {
      console.log('/callback: missing header x-original-uri');
      return res.sendStatus(500);
    }
    if (!req.headers['x-callback']) {
      console.log('/callback: missing header x-callback');
      return res.sendStatus(500);
    }
    if (!validUrl.isHttpsUri(req.headers['x-callback'])) {
      console.log('/callback: x-callback is not a valid https URI');
      return res.sendStatus(500);
    }
    const uri =
      'https://' + config.oauth_server + config.oauth_authorization_path +
      '?response_type=code' +
      '&client_id=' + config.oauth_client_id +
      '&redirect_uri=' + encodeURIComponent(req.headers['x-callback']) +
      '&scope=' + encodeURIComponent(config.oauth_scope) +
      '&state=mystate';
    res.cookie('authURI', {
      original: req.headers['x-original-uri'],
      callback: req.headers['x-callback']
    }, { httpOnly: true });
    res.redirect(uri);
  }
);

// The OAuth response URI will be proxied here.
// Use the returned access code to get access and id tokens.
// Create a user object from the access and id tokens.
// TODO: check for errors flagged in callback request
// TODO: save the user details somewhere: cookie or session?
//
// On what basis are the access and id tokens trusted?
//
// The tokens are obtained from a trusted source by an HTTPS request.
//
// TODO: validate the tokens 
app.get(
  '/callback',
  (req, res, next) => {
    console.log('GET /callback');
    console.log('cookies: ', req.cookies);

    if (!req.cookies.authURI) {
      console.log('/callback: missing cookie authURI');
      return res.status(500).send('Missing cookie authURI');
    }

    // Redeem the access code for access and id tokens.
    // The token endpoint will validate the access code for us.
    const data = querystring.stringify({
      'client_id': config.oauth_client_id,
      'grant_type': 'authorization_code',
      'scope': config.oauth_scope,
      'code': req.query.code,
      'redirect_uri': req.cookies.authURI.callback,
      'client_secret': config.oauth_client_secret
    });

    const options = {
      hostname: config.oauth_server,
      port: 443,
      method: 'POST',
      path: config.oauth_token_path,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': data.length
      }
    };

    const request = https.request(options, response => {

      let body = '';

      response.on('data', d => {
        body += d.toString();
      });

      response.on('end', () => {
        try {
          const data = JSON.parse(body);
          console.log('data: ', data);
          // No need to validate the tokens: they come from a trusted source
          const accessToken = jwt.decode(data.access_token);
          console.log('accessToken: ', accessToken);
          /*
          const complete = jwt.decode(data.access_token, {complete: true});
          console.log('complete: ', complete);
          */
          const idToken = jwt.decode(data.id_token);
          console.log('idToken: ', idToken);
          const user = {
            id: accessToken.oid,
            username: accessToken.upn,
            displayName: accessToken.name,
            email: idToken.email,
            name: {
              fmailyName: accessToken.family_name,
              givenName: accessToken.given_name
            }
          };
          console.log('user: ', user);
          const token = jwt.sign({ user: user }, config.jwtSecret,
            { expiresIn: config.jwtExpiry });
          console.log('token: ', token);
          res.cookie('authToken', token, { httpOnly: true });
          res.clearCookie('authURI', {
            httpOnly: true
          });
          console.log('redirect to: ', req.cookies.authURI.original);
          res.redirect(req.cookies.authURI.original || '/');
        } catch (e) {
          console.log('error getting access token: ', e);
          res.sendStatus(500);
        }
      });
    });

    request.on('error', err => {
      console.log('error: ', err);
    });

    request.write(data);
    request.end();
  }
);

// When using OpenID Connect or hybrid flow with id_token included in the
// response_type (e.g. "code id_token" or "id_token") then the default
// response_mode doesn't work. When requesting a code, the default is
// 'query' but when requesting an id_token it is fragment. The request to
// the server doesn't include the fragment string. 
//
// See: https://stackoverflow.com/questions/2286402/url-fragment-and-302-redirects
// "It's well known that the URL fragment (the part after the #) is not
// sent to the server.
//
// So, the server doesn't get the accesscode.
//
// The only options for response_mode, for OpenID Connect including
// response_type id_token are fragment or form_post. The query mode which
// is available if only a code is requested, is not an option.
//
// The response_mode form_post results in a POST request to the callback
// URL with the parameters in the body, instead of the URL as with
// response_mode query.
//
// The response should include an id_token, which should be all we need.
// The downside of this is that the token comes from the client, so can't
// be trusted and must be verified.
//
// Need scope profile to get name, oid, etc.
//
app.post(
  '/callback',
  (req, res, next) => {
    console.log('POST /callback');
    console.log('cookies: ', req.cookies);
    console.log('query: ', JSON.stringify(req.query, null, 2));
    console.log('body: ', JSON.stringify(req.body, null, 2));

    if (!req.cookies.authURI) {
      console.log('/callback: missing cookie authURI');
      return res.status(500).send('Missing cookie authURI');
    }

    // TODO: get public key and verify rather than decode
    // This token comes from the client browser, not from the Azure AD
    // authentication or token endpoint directly. Therefore, as-is, it
    // should not be trusted without verification. There are many hoops to
    // jump to verify it:
    //
    //  get configuration https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
    //  get keys from jwks_uri
    //  find the relevant key
    //  verify the token with the public key
    //
    //  The configuration is ephemeral, so it is necessary to fetch it, at
    //  least periodically. Microsoft recommends once per day. They don't
    //  document how or when they make changes. Implication of their advice
    //  is that any configuration issued in the past 24 hours will work.
    //
    //  Anyway, this requires two queries: one for the configuration and
    //  another for the keys. Then a lookup through a list of keys (there
    //  are only 5 in our current configuration).
    //
    //  Using the OAuth 2.0 flow, receiving the access code then redeeming
    //  that for id and access tokens from trusted source and trusting those
    //  (i.e. decode rather than verify, because from trusted source) requires
    //  only 1 additional request, so it seems simpler. 
    //
    //  If we were to verify the token either way, then this would be
    //  simpler.
    // 
    const idToken = jwt.decode(req.body.id_token);
    console.log('idToken: ', JSON.stringify(idToken, null, 2));

    const user = {
      id: idToken.oid,
      username: idToken.upn,
      displayName: idToken.name,
      email: idToken.email,
      name: {
        fmailyName: idToken.family_name,
        givenName: idToken.given_name
      }
    };
    console.log('user: ', user);
    const token = jwt.sign({ user: user }, config.jwtSecret,
      { expiresIn: config.jwtExpiry });
    console.log('token: ', token);
    res.cookie('authToken', token, { httpOnly: true });
    console.log('redirect to: ', req.cookies.authURI.original);
    res.redirect(req.cookies.authURI.original || '/');
  }
);


// Anything else is an error. Log it and return a 404
app.all('*', (req, res) => {
  console.log('got ', req.method, req.path);
  res.sendStatus(404);
});

// End of routes
//* ***************************

// Start the server
const server = app.listen(config.server_port, config.server_address);

server.on('error', err => {
  console.log('express server listen failed: ', err);
});

server.on('listening', () => {
  console.log('express server listening on http://' +
    server.address().address + ':' + server.address().port);
});
