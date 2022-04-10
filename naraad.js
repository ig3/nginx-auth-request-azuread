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
const validUrl = require('valid-url');
const expressHandlebars = require('express-handlebars');
const path = require('path');

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

// Setup for Handlebars templates
// const hbs = expressHandlebars.create({});
app.engine('handlebars', expressHandlebars.engine());
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'handlebars');

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

  let jwtSecret = config.jwtSecret;
  let jwtExpiry = config.jwtExpiry;

  if (
    req.cookies.auth &&
    req.cookies.auth.application &&
    config.applications[req.cookies.auth.application] &&
    config.applications[req.cookies.auth.application].jwtSecret
  ) {
    jwtSecret = config.applications[req.cookies.auth.application].jwtSecret;
  }
  if (
    req.cookies.auth &&
    req.cookies.auth.application &&
    config.applications[req.cookies.auth.application] &&
    config.applications[req.cookies.auth.application].jwtExpiry
  ) {
    jwtExpiry = config.applications[req.cookies.auth.application].jwtExpiry;
  }

  // validate the token: it comes from an untrusted source
  try {
    const payload = jwt.verify(req.cookies.authToken, jwtSecret);
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
        const token = jwt.sign(payload, jwtSecret,
          { expiresIn: jwtExpiry });
        res.cookie('authToken', token, { httpOnly: true });
      } catch (e) {
        console.log('error generating new token: ', e);
      }
    }
  } catch (e) {
    if (config.debug) {
      console.log('error validating token: ', e);
    } else {
      console.log('error validating token: ' + e.message);
    }
    return res.sendStatus(401);
  }

  return res.sendStatus(200);
});

app.get(
  '/login',
  (req, res) => {
    console.log('GET /login');
    if (req.query.provider) {
      if (
        !config.providers ||
        !config.providers[req.query.provider]
      ) {
        return res.status(500)
          .send('Unsupported provider: ' + req.query.provider);
      }

      const provider = config.providers[req.query.provider];

      const authCookie = req.cookies.auth || {};
      authCookie.provider = req.query.provider;
      authCookie.originalURL = '/';
      const authRoot = req.headers['x-auth-root'];
      if (!authRoot) {
        return res.code(500).send('Missing header x-auth-root');
      }
      authCookie.authRoot = authRoot;
      res.cookie('auth', authCookie, { httpOnly: true });
      const authenticateURL = authRoot + '/authenticate/' + req.query.provider;
      res.redirect(authenticateURL);
    } else {
      res.render('login', {
        providers: config.providers,
        flash: req.query.flash
      });
    }
  }
);

// If the user is not authenticated, /verify will return 401 and that will
// be redirected to this path.
//
// Set a cookie to record the path they were trying to get, as that will not
// survive the redirects through the OAuth protocol.
//
// Redirect to the OAuth authentication URL.
app.get(
  '/authenticate',
  (req, res) => {
    console.log('get /authenticate');
    const authCookie = req.cookies.auth || {};

    if (!authCookie.originalURL) {
      if (!req.headers['x-original-url']) {
        console.log('missing header x-original-url');
        return res.sendStatus(500);
      }
      authCookie.originalURL = req.headers['x-original-url'];
    }

    if (!req.headers['x-auth-root']) {
      console.log('missing header x-auth-root');
      return res.sendStatus(500);
    }
    if (!validUrl.isHttpsUri(req.headers['x-auth-root'])) {
      console.log('x-auth-root is not a valid https URL');
      return res.sendStatus(500);
    }
    const authRoot = req.headers['x-auth-root'];

    authCookie.authRoot = authRoot;
    res.cookie('auth', authCookie, { httpOnly: true });

    if (authCookie.provider) {
      console.log('authenticate with provider: ', authCookie.provider);
      const redirectURL = authRoot + '/authenticate/' + authCookie.provider;
      res.redirect(redirectURL);
    } else {
      // No provider selected: redirect to the login page
      const redirectURL = authRoot + '/login';
      res.redirect(redirectURL);
    }
  }
);

app.get(
  '/authenticate/:provider',
  (req, res, next) => {
    console.log('GET /authenticate/:provider');
    if (
      !config.providers ||
      !config.providers[req.params.provider]
    ) {
      return res.status(500)
        .send('Unsupported provider: ' + req.params.provider);
    }
    const provider = config.providers[req.params.provider];
    const authCookie = req.cookies.auth || {};

    if (!authCookie.originalURL) {
      if (!req.headers['x-original-url']) {
        console.log('missing header x-original-url');
        return res.sendStatus(500);
      }
      authCookie.originalURL = req.headers['x-original-url'];
    }

    if (!req.headers['x-auth-root']) {
      console.log('missing header x-auth-root');
      return res.sendStatus(500);
    }
    if (!validUrl.isHttpsUri(req.headers['x-auth-root'])) {
      console.log('x-auth-root is not a valid https URL');
      return res.sendStatus(500);
    }
    const authRoot = req.headers['x-auth-root'];
    const callbackURL = authRoot + '/callback/' + req.params.provider;
    // The callback URL may be used later to redeem access tokens
    authCookie.callbackURL = callbackURL;

    if (req.headers['x-app']) {
      console.log('X-App: ', req.headers['x-app']);
      if (config.applications[req.headers['x-app']]) {
        authCookie.application = req.headers['x-app'];
      }
    }

    if (!provider.type) {
      return res.status(500)
        .send('Misconfigured provider: ' + req.params.provider);
    }

    if (provider.type === 'o365') {
      const uri =
        'https://' + provider.oauth_server + provider.oauth_authorization_path +
        '?response_type=code' +
        '&client_id=' + provider.oauth_client_id +
        '&redirect_uri=' + encodeURIComponent(callbackURL) +
        '&scope=' + encodeURIComponent(provider.oauth_scope) +
        '&state=mystate';
      res.cookie('auth', authCookie, { httpOnly: true });
      return res.redirect(uri);
    } else {
      return res.status(500)
        .send('Unsupported provider type: ' + provider.type);
    }
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
  '/callback/:provider',
  (req, res, next) => {
    console.log('GET /callback/:provider');
    console.log('cookies: ', req.cookies);

    if (
      !config.providers ||
      !config.providers[req.params.provider]
    ) {
      return res.status(500)
        .send('Unsupported provider: ' + req.params.provider);
    }
    const provider = config.providers[req.params.provider];

    if (!req.cookies.auth) {
      console.log('missing cookie auth');
      return res.status(500).send('Missing cookie auth');
    }
    const authCookie = req.cookies.auth || {};

    const callbackURL = authCookie.callbackURL;
    if (!callbackURL) {
      res.code(500).send('Missing callbackURL');
    }

    const application = config.applications[authCookie.application];

    if (application) {
      console.log('application: ', application);
    }

    if (provider.type === 'o365') {
      let accessToken;
      let idToken;
      let groups;
      getTokens(provider, req.query.code, callbackURL)
      .then(result => {
        accessToken = result.accessToken;
        idToken = result.idToken;
        return getGroups(provider, accessToken);
      })
      .then(result => {
        // result is an array with details of all the groups the user
        // is a member of ('transitive': direct and indirect membership).
        // Many properties are null: whether that is because the property
        // isn't defined in Microsoft Graph or because the user doesn't have
        // permission to read the property is almost impossible to
        // determine: the documentation doesn't provide field by field
        // specification of permissions require to get a field value.
        // All we really care about is mapping the group ID (a Microsoft
        // surrogate key with no meaning outside the Microsoft database
        // domain) to the group names (the identifiers meaningful to
        // business users). The only identifiers are id and displayName.
        // Presumably id is unique but displayName is not: see
        // [Azure AD allows duplicate group names](https://morgansimonsen.com/2016/06/28/azure-ad-allows-duplicate-group-names/) for some discussion.
        // And in Graph, there is no DN for groups.
        //
        // We can only glean meaning from the id by examining the related
        // attributes (like displayName) and analyzing the permissions
        // granted to the group, but those permissions are only permissions
        // on resources in the Microsoft realm, so there is no practical way
        // to express permissions on entities that exist outside the
        // Microsoft realm (e.g. in a non-Microsoft application), as one
        // would expect to find in a general purpose platform for
        // identification and authorization.
        //
        // While Microsoft AD, via LDAP, provides a means for recording
        // fairly arbitrary authorizations in a robust way, including
        // authorizations to resources not manifest in Microsoft AD,
        // Microsoft Graph and possibly Azure AD do not.
        //
        // Yet this is the elephant we must deal with.
        //
        // So, we either map the IDs to permissions at our end of the
        // displayNames. The IDs are opaque to users, so really not much
        // good. We will use the display names, despite them not being
        // unique.
        //
        // We can't simply include all groups: That gives us JWT token too
        // large for a header. The user context data could be passed to the
        // client in some form other than a Cookie, which would allow larget
        // size (e.g. in the returned page of the app) or the group names
        // could be filtered: the application probably only cares about
        // membership in a small number of groups.
        //
        // This request is only going to (all being well) issue a redirect
        // to the resource the user tried to access before authentication
        // intervened. Other than headers, limited in size, there is no way
        // to pass data back to the user. The URL (including query) can't be
        // changed as that might interfere with the normal function of the
        // application.
        //
        // The data could be added to a server side session store, but that
        // doesn't scale well. At least that session store could keep large
        // data for a short time. And practically speaking, in the current
        // context, it is unlikely there will be more than a few users
        // authenticated at a time. So, maybe a session store is the better
        // way to go.
        //
        // Thus far, the only app we have that cares about group membership
        // is CouchDB. It doesn't care about groups per se, but it does deal
        // with roles, which correspond well enough.
        //
        // We need a mapping of Microsoft Graph groups to CouchDB roles.
        //
        const accessClaims = jwt.decode(accessToken);
        console.log('accessToken: ', accessClaims);
        /*
        const complete = jwt.decode(data.access_token, {complete: true});
        console.log('complete: ', complete);
        */
        const idClaims = jwt.decode(idToken);
        console.log('idToken: ', idClaims);
        const user = {
          id: accessClaims.oid,
          username: accessClaims.upn,
          displayName: accessClaims.name,
          email: idClaims.email,
          fullname: {
            fmailyName: accessClaims.family_name,
            givenName: accessClaims.given_name
          }
        };
        /*
        const user = {
          name: 'admin',
          sub: 'admin',
          '_couchdb.roles': [ '_admin' ],
        };
        */

        let jwtSecret = config.jwtSecret;
        let jwtExpiry = config.jwtExpiry;
        let httpOnly = true;
        if (application) {
          if (application.couchdb) {
            user.sub = accessClaims.upn;
            user.name = accessClaims.upn;
            // const roles = [ '_admin' ];
            const roles = [ ];
            console.log('map: ', application.groupMap);
            result.forEach(group => {
              console.log('group.displayName: ', group.displayName);
              if (application.groupMap[group.displayName]) {
                roles.push(application.groupMap[group.displayName]);
              }
            });
            user['_couchdb.roles'] = roles;
            jwtSecret = application.jwtSecret;
            jwtExpiry = application.jwtExpiry;
            httpOnly = false;
          }
          if (application.groupMap) {
            const groups = {};
            result.forEach(group => {
              if (application.groupMap[group.displayName]) {
                groups[application.groupMap[group.displayName]] = {
                  description: group.description,
                  displayName: group.displayName,
                  groupTypes: group.groupTypes,
                  id: group.id,
                  mail: group.mail,
                  mailEnabled: group.mailEnabled,
                  securityEnabled: group.securityEnabled
                }
              }
            });
            user.groups = groups;
          }
          if (application.requireGroups) {
            console.log('require groups: ', application.requireGroups);
            let member = false;
            result.forEach(group => {
              if (
                typeof application.requireGroups === 'string' &&
                group.displayName === application.requireGroup
                ||
                typeof application.requireGroups === 'object' &&
                application.requireGroups.indexOf(group.displayName) !== -1
              ) {
                member = true;
              }
            });
            if (!member) {
              const redirectURL = authRoot + '/login' +
                '?flash=' + encodeURIComponent('Unauthorized');
              res.redirect(redirectURL);
            }
          }
        }
        console.log('user: ', user);
        const token = jwt.sign(user, jwtSecret,
          { expiresIn: config.jwtExpiry });
        console.log('token: ', token);
        console.log('token size: ', token.length);
        res.cookie('authToken', token, { httpOnly: httpOnly });

        const originalURL = authCookie.originalURL || '/';

        delete authCookie.redirectURL;
        delete authCookie.originalURL;
        res.cookie('auth', authCookie, { httpOnly: true });

        console.log('redirect to: ', originalURL);
        res.redirect(originalURL);
      });
    } else {
      res.status(500)
        .send('Unsupported provider type: ' + provider.type);
    }
  }
);

function getGroups(provider, accessToken) {
  return new Promise((resolve, reject) => {
    // Redeem the access code for access and id tokens.
    // The token endpoint will validate the access code for us.
    const options = {
      hostname: 'graph.microsoft.com',
      port: 443,
      method: 'GET',
      path: '/v1.0/me/transitiveMemberOf',
      headers: {
        'Authorization': 'Bearer ' + accessToken
      }
    };

    const request = https.request(options, response => {

      let body = '';

      response.on('data', d => {
        body += d.toString();
      });

      response.on('end', () => {
        if (response.statusCode === 200) {
          try {
            const data = JSON.parse(body);
            resolve(data.value);
          } catch (e) {
            console.log('error parsing response: ', e);
            reject(e);
          }
        } else {
          reject(new Error('Response code != 200: ' + response.statusCode));
        }
      });
    });

    request.on('error', err => {
      console.log('error: ', err);
    });

    request.end();
    console.log('request headers: ', request.getHeaders());
  });
}

// Given an Azure AD OAuth 2.0 access code, redeem this for an access token
// and an ID token, returning the tokens.
function getTokens (provider, accessCode, callbackURL) {
  return new Promise((resolve, reject) => {
    // Redeem the access code for access and id tokens.
    // The token endpoint will validate the access code for us.
    const data = new URLSearchParams({
      'client_id': provider.oauth_client_id,
      'grant_type': 'authorization_code',
      'scope': provider.oauth_scope,
      'code': accessCode,
      'redirect_uri': callbackURL,
      'client_secret': provider.oauth_client_secret
    }).toString();

    const options = {
      hostname: provider.oauth_server,
      port: 443,
      method: 'POST',
      path: provider.oauth_token_path,
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
          resolve({
            accessToken: data.access_token,
            idToken: data.id_token
          });
        } catch (e) {
          console.log('error getting access token: ', e);
          reject(e);
        }
      });
    });

    request.on('error', err => {
      console.log('error: ', err);
    });

    request.write(data);
    request.end();
  });
}

// When using AzureAD OpenID Connect or hybrid flow with id_token included in
// the response_type (e.g. "code id_token" or "id_token") then the default
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
// The only options for response_mode, for AzureAD OpenID Connect including
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

// This is the original implementation. With support for multiple identity
// providers, this should no longer be used.
app.post(
  '/callback/:provider',
  (req, res, next) => {
    console.log('POST /callback/:provider');
    console.log('cookies: ', req.cookies);
    console.log('query: ', JSON.stringify(req.query, null, 2));
    console.log('body: ', JSON.stringify(req.body, null, 2));

    if (
      !config.providers ||
      !config.providers[req.params.provider]
    ) {
      return res.status(500)
        .send('Unsupported provider: ' + req.params.provider);
    }
    const provider = config.providers[req.params.provider];
    const authCookie = req.cookies.auth || {};

    if (!provider.type) {
      return res.status(500)
        .send('Misconfigured provider: ' + req.params.provider);
    }

    if (provider.type === 'o365') {
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
      const redirectURL = authCookie.originalURL || '/';
      console.log('redirect to: ', redirectURL);
      res.redirect(redirectURL);
    } else {
      res.status(500)
        .send('Unsupported provider type: ' + provider.type);
    }
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
