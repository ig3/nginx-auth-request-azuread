# nginx-auth-request-azuread (naraad)

This is an HTTP server that provides authentication for a website served by
nginx, based on Azure AD OAuth 2.0 service.

## Installation

```
$ npm install -g @ig3/nginx-auth-request-azuread
```

OR

```
$ git clone https://github.com/ig3/nginx-auth-request-azuread.git
$ npm install
$ npm pack
$ npm install -g ig3-nginx-auth-request-azuread-*.tgz
```

Note: `npm pack` creates an installation package and installing this does
an installation similar to installing from the registry, with all the
contents copied to the installation directory, as opposed to `npm install
-g` which will link to the current directory rather than making a copy of
the contents. The latter might be preferable for testing and development,
but not for production.

## Configuration

Coordinated configuration is required for Azure AD, nginx and naraad (this
website).


### Azure AD

Add an application under `App registrations`.

Under `Authentication`, `Platform configurations` add web application
`Web`. Enter the redirect URI. If you use naraad to protect multiple
websites, you can add multiple redirect URIs: one for each site. There is
no provision for signout, so no need to set a logout URL.

Under `Certificates & secrets`, add a Client Secret. Save the value, to be
added to naraad configuration (see below). You cannot view the secret value
later, but you can always add a new secret.

Under `Token configuration` add claims `email`, `family_name`,
`given_name`, `upn` and `verified_primary_email`. 

Under `API permissions` add `openid`

### nginx

The naraad server responds to three paths: /verify, /authenticate and
/callback. The nginx server must be configured to pass requests to these
three routes.

Every request for a protected resource must be passed to the /verify route.
The naraad server will respond with status 200 if the user is authenticated
or 401 if not.

The 401 response must be routed to the /authenticate route to initiate
authenticate. The naraad server will respond with a redirect to the OAuth
authentication endpoint. This must set two headers: X-Original-URL and
X-Callback-URL

The callback from OAuth must be passed to the /callback route. The naraad
server will respond with a redirect to the originally requested URL.

The nginx
[`auth_request`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html#auth_request)
directive must be added to any protected content
(i.e. content for which authentication and authorization are required),
with additional configuration to handle the subrequest from `auth_request`
and the redirect from OAuth 2.0.

Example configuration:

```
server {
  server_name www.example.com;
  listen 443 ssl;

  location / {
    auth_request /auth/verify;
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie;

    root /var/www/htdocs;
  }

  location = /auth/verify {
    proxy_pass http://127.0.0.1:9090/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
  }

  error_page 401 = /auth/authenticate;

  location /auth/authenticate {
    proxy_pass http://127.0.0.1:9090/authenticate;
    proxy_set_header X-Original-URL $request_uri;
    proxy_set_header X-Auth-Root $scheme://$host/auth;
    proxy_set_header X-App myapp;
  }

  location /auth/ {
    proxy_pass http://127.0.0.1:9090/;
    proxy_set_header X-Auth-Root $scheme://$host/auth;
    proxy_set_header X-App myapp;
  }
}
```

The paths for the website and for the naraad server are
independent of each other. In the website, any path that does not conflict
with other paths in the website may be used, instead of `/auth/verify`,
`/auth/authenticate` and `/auth/callback` in this example configuration.

The path for the callback from OAuth must correspond to a Redirect URI
configured in the Azure AD application.

One the proxy to naraad `/authenticate`, the headers X-Oringial-URL and
X-Callback-URL must be set to the URL the user originally requested and the
URL of the OAuth callback / redirect respectively. If X-Original-URL is not
set, on completion of authentication the user will be redirected to the
root of the website (path '/'), regardless of what path was originally
requested. If X-Callback-URL is not set, the authentication will fail:
OAuth requires that the callback URL be specified.

Note that a single instance of naraad can provide authentication for
multiple web sites, each with their own callback / redirect. The callback /
redirect for a specific web site is specified by the Header X-Callback-URL
on the request to /authenticate.

Header `X-Auth-Root` provides the prefix of URL to which various paths are
appended for authentication, callbacks, etc. 

Header `X-App` selects the application configuration used to compose the
token returned by authentication.

Headers `X-Auth-Root` and `X-App` should be set on every request proxied to
this server, except the `/verify` path, where they are ignored.

### naraad

There are a few configuration parameters for the naraad server. These
mostly relate to OAuth and must be coordinated with the application
configured in Azure AD.

Configuration may be JSON5, JSON or INI style, according to the extension
of the configuration file.

Configuration file paths:
 * /etc/naraad
 * /etc/naraad/config
 * ~/.config/naraad
 * ~/.config/naraad/config
 * ~/.naraad
 * ~/.naraad/config
 * .naraad
 * naraad

Each of these paths will be searched, with extensions .json5, .json and
.ini and any configuration file found will be loaded. If multiple files are
found they will all be loaded and their contents merged with files loaded
later overriding those loaded earlier, if they contain configuration
parameters with the same name.

Environment variables with names beginning with  `naraad_` will be added to the
configuration, possibly overriding parameters from the configuration files.
The leading `naraad_` will be removed from the environment variable name. For
example, environment variable `naraad_server_address` would set configuration
parameter `server_address`.

Configuration parameter may also be specified on the command line. For
example: `naraad --server_address 1.2.3.4` would set the server IP address to
1.2.3.4. Configuration parameters set from the command line will override
any settings from configuration files or environment variables.

Example configuration:

```
{
  "debug": true,
  "server_port": 9000,
  "providers": {
    "saasam_o365": {
      "name": "O365",
      "type": "o365",
      "oauth_client_id": "6ab24693-6778-4cba-99f5-cb7fabd98659",
      "oauth_client_secret": "ER57Q~.elWGTnljsCpyfXSK~RG-_ZAAAt3.dg",
      "oauth_scope": "User.Read openid",
      "oauth_callback_url": "https://auth.entrain.nz/auth/office365/callback",
      "oauth_server": "login.microsoftonline.com",
      "oauth_authorization_url": "https://login.microsoftonline.com/da6ffd29-108b-43e2-9b37-0692c58b32e9/oauth2/v2.0/authorize",
      "oauth_authorization_path": "/da6ffd29-108b-43e2-9b37-0692c58b32e9/oauth2/v2.0/authorize",
      "oauth_token_url": "https://login.microsoftonline.com/da6ffd29-108b-43e2-9b37-0692c58b32e9/oauth2/v2.0/token",
      "oauth_token_path": "/da6ffd29-108b-43e2-9b37-0692c58b32e9/oauth2/v2.0/token",
      "oauth_tenant": "saasam.co"
    }
  },
  "applications": {
    "eqa": {
      "couchdb": true,
      "groupMap": {
        "EQA User": "eqa_user",
        "EQA Admin": "eqa_admin"
      },
      "jwtSecret": "hello",
      "jwtExpiry": "1h"
    },
    "withGroups": {
      "groupMap": {
        "All Users": "users",
        "Domain Admins": "admins"
      }
    }
    "adminOnly": {
      "requireGroups": "Domain Admins"
    },
    "adminOrUser": {
      "requireGroups": [ "Domain Admins", "Domain Users" ]
    }
  }
}
```

### Configuration Parameters

#### debug

If debug is true, additional logs will be generated.

#### jwtExpiry

default: `1h`

The expiry time of the JWT token that is generated for an authenticated
user. 

#### server_port

default: 9090

The TCP port on which the naraad server listens.

#### server_address

default: 0.0.0.0

The IP address on which the naraad server listens.

#### providers

A set of identity providers.

The key will be used in URLs, unescaped.

Each provider must have:

 * name - the name of the provider presented to users
 * type - the type of provider: one of ('o365')
 * type specific parameters

At the moment, there is only one provider type supported: o365. It has the
following parameters:

##### oauth_client_id

This is the OAuth 2.0 client ID. It must be consistent with the Client ID
configured in the Azure AD application.

##### oauth_client_secret

This is the secret that verifies the request to the OAuth 2.0 authentication
server. It must be consistent with one of the secrets configured in the
Azure AD application.

##### oauth_callback_url

This is the callback URL that will be included in the OAuth 2.0
authentication request. The Azure AD application must be configured to
accept this callback URL and the nginx server must be configured to proxy
the callback to the `/callback` path of the naraad server.

##### oauth_authorization_url

This is the URL that the user's browser will be directed to, to initiate the
OAuth 2.0 authentication. It must be set to the OAuth 2.0 authentication
endpoint of the Azure AD instance in which the application is configured.

##### oauth_token_rul

This is the URL that the naraad server will access to obtain an access token.

##### oauth_tenant

This is the Azure AD tenant: typically a domain name that is the root of the
Azure AD domain.

#### applications

The keys to application should match the value of the X-App header on the
authentication request.

##### couchdb

This application type is specific to CouchDB backend. It adds properties
`sub`, `name` and `_couchdb.roles` to the generated user object, and uses
the jwtSecret and jwtExpiry properties of the application object to encode
the generated JWT token. The jwtSecret should be as configured on the
CouchDB server: it is the shared secret by which CouchDB trusts the JWT.

##### groupMap

Maps the displayName of groups in Azure AD to group names meaningful to the
application, and adds these to the user object if the user is a member of
the corresponding Azure AD group.

For each mapped group that the user is a member of, the user object will
contain a property in the user.groups object with properties:

 * description
 * displayName
 * groupTypes
 * id
 * mail
 * mailEnabled
 * securityEnabled

These are the values of the corresponding properties of the Azure AD group.

##### requireGroups

The value of this property is the display name of an Azure AD group or an
array of such display names. Access is allowed if the user is a member of
any of the groups.

If the user is not a member of any of the groups, authentication will fail
and the user will be redirected back to the login page.

### systemd

To start the server from systemd, create a service file similar to:

```
[Unit]
Description=HTTP server for nginx auth_request authentication

[Service]
Type=simple
Restart=on-failure
WorkingDirectory=/tmp
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=naraad
ExecStart=/usr/local/bin/naraad

[Install]
WantedBy=multi-user.target
```

## OAuth 2.0 notes

This uses the
[Microsoft identity platform and OAuth 2.0 authorization code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow).

The documentation of the flow indicates that the resource server ('Web API'
in their diagram) must validate the access token but no guidance is provided
as to how to do this.

In fact, the page says:

> Don't attempt to validate or read tokens for any API you don't own, including the tokens in this example, in your code. Tokens for Microsoft services can use a special format that will not validate as a JWT, and may also be encrypted for consumer (Microsoft account) users. While reading tokens is a useful debugging and learning tool, do not take dependencies on this in your code or assume specifics about tokens that aren't for an API you control.

This seems to contradict the indication in the diagram at the top of the
page that the 'Web API' server should validate the token. Or is it that the
access token for the 'Web API' is a token for the API of that server?

Microsoft provides [sample
code](https://docs.microsoft.com/en-us/azure/active-directory/develop/sample-v2-code),
including code for NodeJS/Express. What I have looked at indicates that it
is 'beta' code.

See
[Microsoft identity platform access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens) for some details of the access tokens issued by Azure AD.

[# of days since the last alg=none JWT vulnerability](https://news.ycombinator.com/item?id=24347519) has some interesting comments about using the payload of JWTs without verifying them. I don't entirely agree: one uses data from trusted sources received by secure channels all the time. Do you verify data from your database every time you query it? No, because you trust the source and the channel. Likewise, if you get a token directly from the token server by HTTPS, it is quite reliable data. If, on the other hand, you get the token from a client who submitted an HTTP request to your public server, then certainly it should be verified before it is trusted as being any more reliable than any other of their input.

## Azure AD notes

### Group Membership

Azure AD OAuth 2.0 interface provides limited information about group
membership. The only claim supported is the `groups` claim and this only
provides the set of group IDs but nothing more. In particular, no names are
provided. To get more information it is necessarly to look up the group
details via some other API: LDAP or Graph are options.

While the implicit flow is simple, it returns the token in a URL which has
limited length. Azure AD omits the groups claim if it determines that
including the set of groups would make the resulting URL too long. See
[AAD groups claim missing in JWT token for some users](https://stackoverflow.com/questions/45751985/aad-groups-claim-missing-in-jwt-token-for-some-users), which includes these quotes from Microsoft:

> In the implicit flow, oauth will return the Jwt directly from the intial /authorize call through a query string param. The http spec limits the length of a query string / url, so if AAD detects that the resulting URI would be exceeding this length, they replace the groups with the hasGroups claim.

> This is by design when using implicit grant flow, regardless the "groupMembershipClaims" setting in the manifest. It's to avoid to go over the URL length limit of the browser as the token is returned as a URI fragment. So, more or less after 4 user's groups membership, you'll get "hasgroups:true" in the token. What you can do is to make a separate call to the Graph API to query for the user's group membership.

See
[Security tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/security-tokens) for details.

So, to get useful information about group membership, the OAuth 2.0 API is
insufficient. The current API appears to be
[Microsoft Graph API](https://docs.microsoft.com/en-us/azure/active-directory/develop/microsoft-graph-intro).

But the Microsoft Graph API is obtuse and the documentation moreso. It is
not at all obvious how to get the names of the groups a user is a member of.

See
[How to get group names of the user is a member of using Microsoft Graph API?](https://stackoverflow.com/questions/63502897/how-to-get-group-names-of-the-user-is-a-member-of-using-microsoft-graph-api). 

[Include AAD group name in the JWT token](https://stackoverflow.com/questions/59873599/include-aad-group-name-in-the-jwt-token)

[Get list of Microsoft Azure AD group names using MSAL library in Angular 8](https://stackoverflow.com/questions/65694758/get-list-of-microsoft-azure-ad-group-names-using-msal-library-in-angular-8) shows a MS Graph query to get all group ID and name.

I think what I need is
[List user transitive memberOf](https://docs.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0&tabs=http). This should provide all groups that a user is a member of, directory or indirectly.

Explorting
[graph-explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
it seems the query `https://graph.microsoft.com/v1.0/me/transitiveMemberOf`
returns details of groups for the authenticated user. Now all I have to do
is figure out how to call this given the access token from OAuth 2.0.

But among examples in the explorer there is `all groups I belong to
(director or indirect membership) with count`

`https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group?$count=true`

I suspect the `/microsoft.graph.group?$count=true` adds the count.

But the value without this is an array and it is trivial to get the size of
the array so one wonders what Microsoft things the value of the count field
is.

To access the Graph API see
[Get access on behalf of a user](https://docs.microsoft.com/en-us/graph/auth-v2-user)

Based on this, it seems sufficient to get the access token from OAuth 2.0
API then include this in an 'Authorization: Bearer <token>` header in the
request to the Graph API.

## Changes

### 1.0.0 - 20220429

Enhance logging for application requireGroups

### 0.0.10 - 20220411

Fix reference to authRoot.

### 0.0.9 - 20220411

Stop using cookies for sensitive parameters.

### 0.0.8 - 20220411

Add app flag requireGroups

### 0.0.7 - 20220408

Add support for applications: couchdb

### 0.0.6 - 20220331

Update version of @ig3/config

### 0.0.5 - 20220331

Use URLSearchParams instead of querystring
