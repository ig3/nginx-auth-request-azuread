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
const mustacheExpress = require('mustache-express');
const passport = require('passport');
const PassportOAuth2 = require('passport-oauth2');

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

// Package express-session provides middleware for saving and retreiving
// session data. The default MemoryStore is discouraged for production: it
// leaks memory.
//
// This no longer requires cookie-parser and using cookie-parser with a
// different key might cause problems. Given session state, it may not be
// necessary to set cookies, in which case cookie-parser isn't required.
// On the other hand, it might be better if the server were stateless,
// in which case express-session wouldn't be required.
//
// Currently, both express-session and cookie-parser are used. This is far
// from ideal. At least cookie-parser is used without a secret and both seem
// to be working.
//
// TODO: attempt to make the server stateless and remote express-session.
//
app.use(expressSession({
  secret: uuidv4(),
  resave: false,
  saveUninitialized: false
}));

// We shouldn't use both cookie-parser and express-session. One or the other
// should suffice. But, at the moment, for historical reasons, both are
// used.
app.use(cookieParser());

// Package mustache-express provides an express view engine for rendering
// mustache templates. These were used for the login page but probably
// aren't needed for OAuth 2.0 based authentication.
//
// TODO: determine if these can be removed.
app.set('views', './views');
app.set('view engine', 'mustache');
app.engine('mustache', mustacheExpress());

// Add the Passport strategy for authenticating against Office 365 OAuth 2.0
//
// This is based on passport-oauth2. The parameters must coordinate with the
// application configured in Azure AD.
passport.use('o365', new PassportOAuth2(
  {
    clientID: config.oauth_client_id,
    clientSecret: config.oauth_client_secret,
    callbackURL: config.oauth_callback_url,
    authorizationURL: config.oauth_authorization_url,
    tokenURL: config.oauth_token_url,
    state: true,
    tenant: config.oauth_tenant
  },
  (jwtAccessToken, refreshToken, params, profile, cb) => {
    // TODO: handle errors parsing the tokens
    const accessToken = jwt.decode(jwtAccessToken);
    const idToken = jwt.decode(params.id_token);
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
    if (config.debug) console.log('user: ', JSON.stringify(user, null, 2));
    cb(null, user);
  }
));

passport.serializeUser((user, done) => {
  done(null, JSON.stringify(user));
});
passport.deserializeUser((user, done) => {
  done(null, JSON.parse(user));
});

// passport.initialize() provides express middleware for ???.
// Note that passport.authenticate is called as middleware explicitly.
// This call is probably not required. If option userProperty is true it
// adds property _userProperty to the req object. But here it is called
// without options, so this isn't done. Otherwise, by default, it adds an
// _passport property to the req object but this is only done for
// compatibility with older versions of passport and plugins to them, some
// of which expect this property to exist. Since a recent passport version
// is being used, this shouldn't be required. So, it should be OK to remove
// this.
app.use(passport.initialize());

// passport.session() provides express middleware that recovers user details
// from the session state, setting property req.user. It reads req.session,
// which typically would be set by 'express-session'. In this it looks for
// req.session.passport.user which should contain the serialization of the
// user. It calls the user deserialization function, passing it this value.
// If this returns a user object, this is saved to req.user.
app.use(passport.session());

//* ***************************
// Add route handlers

// GET /verify handles the primary request from nginx auth_request.
//
// If the user is authenticated, HTTP status 200 is returned. In this case,
// nginx proceeds to server the requested content.
//
// If the user is not authenticated, HTTP status 401 is returned. In this
// case, nginx should be configured to direct to GET /authenticate.
//
// If the user is not authenticated, it is not possible to begin the
// authentication immediately because auth_requests expects either status
// 200 or 401 back and treats any other status as an error. Initiation of
// OAuth 2.0 authentication is incompatible as it requires a 301 response to
// redirect to the OAuth 2.0 authorization server. So, a redirect to
// /authorize is required.
//
// Authentication status is determined by the presence of an authToken cookie,
// the value of which is a JWT token. If the cookie is present and the JWT
// token is valied (parsable and not expired) then the user is
// authenticated.
//
// This JWT token is produced by this werver when the user authenticates. It
// is encrypted and has an expiry date.
//
app.get('/verify', (req, res) => {
  // Authentication is based on receiving a JWT
  // TODO: consider keeping authToken in session state rather than a cookie
  console.log('GET /auth');
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

// This is the Passport based authentication route. It initiates the OAuth
// 2.0 authentication via Azure AD. It should return a redirect to the Azure
// AD OAuth 2.0 authentication endpoint, with relevant parameters in the
// query string of the URL. All being well, Azure AD will redirect the user
// back to the callback URL.
app.get(
  '/authenticate',
  passport.authenticate('o365', { scope: 'User.Read openid' })
);

// This is the Azure AD / OAuth 2.0 callback route. It continues the
// Passport based authentication.
// A subset of authentication failures will result in a redirect here, with
// query parameter 'error' set. passport.authenticate will handle this,
// sending a 401 response.
app.get(
  '/callback',
  (req, res, next) => {
    console.log('***********************');
    console.log('url: ', req.url);
    console.log('query: ', req.query);
    next();
  },
  passport.authenticate('o365'),
  (req, res) => {
    console.log('authenticated');
    // Set a cookie that can be tested by the /auth route handler.
    const token = jwt.sign({ user: req.user }, config.jwtSecret,
      { expiresIn: config.jwtExpiry });
    res.cookie('authToken', token, { httpOnly: true });
    res.redirect('/');
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
