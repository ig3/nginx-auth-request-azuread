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
  console.log('GET /auth ' + req.headers['x-original-uri']);
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
    res.cookie('authURI', req.headers['x-original-uri'], { httpOnly: true });
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

    if (!req.headers['x-callback']) {
      console.log('/callback: missing header x-callback');
      return res.sendStatus(500);
    }
    if (!validUrl.isHttpsUri(req.headers['x-callback'])) {
      console.log('/callback: x-callback is not a valid https URI');
      return res.sendStatus(500);
    }

    // If hybrid flow worked we would have everything we need at this point:
    // authentication and user details. But it doesn't work as documented:
    // keeps giving errors about missing parameter after several redirects.
    // So instead, use the given access code to get an authorization code.
    // It is one more request, but only when authenticating.
    //
    // On the other hand, anyone can send a request to this path. The data
    // recieved should not be trusted. Redeeming the access code with a
    // request to the authorization server validates the code. If the access
    // and id tokens were provided in the request to the callback URI, as in
    // the hybrid flow they are supposed to be, then it would be necessary
    // to validate them before trusting them.
    const data = querystring.stringify({
      'client_id': config.oauth_client_id,
      'grant_type': 'authorization_code',
      'scope': config.oauth_scope,
      'code': req.query.code,
      'redirect_uri': req.headers['x-callback'],
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
          console.log('redirect to: ', req.cookies.authURI);
          res.redirect(req.cookies.authURI || '/');
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
app.post(
  '/callback',
  (req, res, next) => {
    console.log('GET /callback');
    console.log('cookies: ', req.cookies);
    console.log('query: ', JSON.stringify(req.query, null, 2));
    console.log('body: ', JSON.stringify(req.body, null, 2));

    if (!req.headers['x-callback']) {
      console.log('/callback: missing header x-callback');
      return res.sendStatus(500);
    }
    if (!validUrl.isHttpsUri(req.headers['x-callback'])) {
      console.log('/callback: x-callback is not a valid https URI');
      return res.sendStatus(500);
    }

    // If hybrid flow worked we would have everything we need at this point:
    // authentication and user details. But it doesn't work as documented:
    // keeps giving errors about missing parameter after several redirects.
    // So instead, use the given access code to get an authorization code.
    // It is one more request, but only when authenticating.
    //
    // On the other hand, anyone can send a request to this path. The data
    // recieved should not be trusted. Redeeming the access code with a
    // request to the authorization server validates the code. If the access
    // and id tokens were provided in the request to the callback URI, as in
    // the hybrid flow they are supposed to be, then it would be necessary
    // to validate them before trusting them.
    const data = querystring.stringify({
      'client_id': config.oauth_client_id,
      'grant_type': 'authorization_code',
      'scope': config.oauth_scope,
      'code': req.query.code,
      'redirect_uri': req.headers['x-callback'],
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
          console.log('redirect to: ', req.cookies.authURI);
          res.redirect(req.cookies.authURI || '/');
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
