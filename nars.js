#!/usr/bin/env node
'use strict';
/**
 * This is the main executable of nginx auth_request server: nars
 *
 */

const getConfig = require('@ig3/config');
const { v4: uuidv4 } = require('uuid');
const express = require('express');
const jwt = require('jsonwebtoken');
const expressSession = require('express-session');
const cookieParser = require('cookie-parser');
const https = require('https');
const querystring = require('querystring');

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
  if (req.cookies.authToken) {
    console.log('found an authToken cookie');
    try {
      jwt.verify(req.cookies.authToken, config.jwtSecret);
      console.log('verified the authToken');
      const token = jwt.sign({ user: req.user }, config.jwtSecret,
        { expiresIn: config.jwtExpiry });
      res.cookie('authToken', token, { httpOnly: true });
      return res.sendStatus(200);
    } catch (e) {
      // ignore any errors - invalid JWT - continue
    }
  }
  console.log('No valid authToken');
  res.sendStatus(401);
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
app.get(
  '/callback',
  (req, res, next) => {
    console.log('GET /callback');
    console.log('cookies: ', req.cookies);

    // If hybrid flow worked we would have everything we need at this point:
    // authentication and user details. But it doesn't work as documented:
    // keeps giving errors about missing parameter after several redirects.
    // So instead, use the given access code to get an authorization code.
    // It is one more request, but only when authenticating.
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
        const data = JSON.parse(body);
        const accessToken = jwt.decode(data.access_token);
        const idToken = jwt.decode(data.id_token);
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
        const token = jwt.sign({ user: req.user }, config.jwtSecret,
          { expiresIn: config.jwtExpiry });
        res.cookie('authToken', token, { httpOnly: true });
        console.log('redirect to: ', req.cookies.authURI);
        res.redirect(req.cookies.authURI || '/');
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
