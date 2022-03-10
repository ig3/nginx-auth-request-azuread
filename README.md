# nginx-auth-request-oauth2

This is an HTTP server that responds to requests from the nginx auth_request
directive and authenticates against an OAuth 2.0 service. It has been tested
against Azure AD OAuth 2.0, as provided with Office 365.

## nginx configuration

Example configuration:

```
server {
  server_name server.example.com;
  listen 443 ssl;

  location / {
    auth_request /auth/verify;
    auth_request_set $auth_user $upstream_http_x_vouch_user;
    auth_request_set $auth_status $upstream_status;
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie;

    root /var/www/htdocs;
  }

  location = /auth/verify {
    # This address is where Vouch will be listening
    proxy_pass http://127.0.0.1:9090/verify;

    proxy_pass_request_body off; # no need to send the POST body
    proxy_set_header Content-Length "";

    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Remote-Addr $remote_addr;
    proxy_set_header X-Original-Host $host;
  }

  error_page 401 = /auth/authenticate;

  location /auth/authenticate {
    proxy_pass http://127.0.0.1:9090/authenticate;

    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Remote-Addr $remote_addr;
    proxy_set_header X-Original-Host $host;
    proxy_set_header X-Login-Path /auth/login;
    proxy_set_header X-URI $uri;
  }

  location /auth/callback {
    proxy_pass http://127.0.0.1:9090/callback;

    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Remote-Addr $remote_addr;
    proxy_set_header X-Original-Host $host;
    proxy_set_header X-Login-Path /auth/login;
    proxy_set_header X-URI $uri;
  }

}
```

The paths /auth/verify, /auth/authenticate and /auth/callback are arbitrary
and specific to the server configuration. They can be set to anything that
doesn't conflict with paths used by the server generally. It is the paths in
the proxy_pass directives that must be configured according to the paths
supported by the nars server.

Any location to be protected must have the `auth_request` directive. See the
nginx documentation for details of how this directive works. Essentially,
produces a sub-request to the configured path. The nginx server should be
configured to proxy this location to this nars server at path /verify. In
this example, this is done by the `location /auth/verify` block.

If the user is not authenticated, the nars server will return status 401
to the request `GET /verify`.

The directive `error_page 401 /auth/authenticate` redirects this 401 error
to path `/auth/authenticate` and this location is configured to be proxied
to the nars server at path `/authenticate`. This request initiates the OAuth
2.0 authentication with a redirect to the OAuth 2.0 authentication server.

The OAuth 2.0 authentication server will eventually redirect the browser to
the configured callback URL. This location (`/auth/callback`) is proxied to
the nars server at path `/callback`.

If the callback includes valid tokens, then a session token is returned as a
cookie value.

With the cookie returned, the sub-request is complete and nginx serves the
content originally requested.

## Paths

The server responds to GET requests with paths:

  /auth
  /auth/office365
  /auth/office365/callback

Anything else gets a 404.

### /auth

GET /auth returns status 200 if the user is authenticated. Otherwise status
401.

In nginx configuration, protected content should have an auth_request
directive that redirects to this path.

For example, to protect all content on the site:

```
location / {
  auth_request /auth/verify;
  auth_request_set $auth_cookie $upstream_http_set_cookie;
  add_header Set-Cookie $auth_cookie;

  ...
}

location = /auth/verify {
  # Set this to whatever address:port the authentication server is on
  proxy_pass http://127.0.0.1:9090/auth;

  # For these auth requests, the body of the request is irrelevant
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";

  # These are not used at the moment but might help with authentication and
  # access contro.
  proxy_set_header X-Original-URI $request_uri;
  proxy_set_header X-Original-Remote_Addr $remote_addr;
  proxy_set_header X-Original-Host $host;
}
```

Note that the path `/auth/verify` is local to the application and nginx. It
is irrelevant to the authentication server, which only sees the path in the
proxy_pass. So this path can be set to anything that doesn't conflict with
the paths used by the protected site.


## nars configuration

Configuration may be set in configuration files, environment variables or
command line parameters.

Configuration files may be JSON or INI style, with extension .json or .ini
respectively. 

Configuration file paths:
 * /etc/nars
 * /etc/nars/config
 * ~/.config/nars
 * ~/.config/nars/config
 * ~/.nars
 * ~/.nars/config
 * .nars
 * nars

Each of these paths will be searched, with extension .json and .ini and any
configuration file found will be loaded. If multiple files are found they
will all be loaded and their contents merged with files loaded later
overriding those loaded earlier, if they contain configuration parameters
with the same name.

Environment variables with names beginning with  `nars_` will be added to the
configuration, possible overriding parameters from the configuration files.
The leading `nars_` will be removed from the environment variable name. For
example, environment variable `nars_server_address` would set configuration
parameter `server_address`.

Any configuration parameter may also be specified on the command line. For
example: `nars --server_address 1.2.3.4` would set the server IP address to
1.2.3.4. Configuration parameters set from the command line will override
any settings from configuration files or environment variables.

### Configuration Parameters

#### oauth_client_id

This is the OAuth 2.0 client ID. It must be consistent with the Client ID
configured in the Azure AD application.

#### oauth_client_secret

This is the secret that verifies the request to the OAuth 2.0 authentication
server. It must be consistent with one of the secrets configured in the
Azure AD application.

#### oauth_callback_url

This is the callback URL that will be included in the OAuth 2.0
authentication request. The Azure AD application must be configured to
accept this callback URL and the nginx server must be configured to proxy
the callback to the `/callback` path of the nars server.

#### oauth_authorization_url

This is the URL that the user's browser will be directed to, to initiate the
OAuth 2.0 authentication. It must be set to the OAuth 2.0 authentication
endpoint of the Azure AD instance in which the application is configured.

#### oauth_token_rul

This is the URL that the nars server will access to obtain an access token.

#### oauth_tenant

This is the Azure AD tenant: typically a domain name that is the root of the
Azure AD domain.

#### debug

If debug is true, additional logs will be generated.

#### jwtExpiry

default: `1h`

The expiry time of the JWT token that is generated for an authenticated
user. 

#### server_port

default: 9090

The TCP port on which the nars server listens.

#### server_address

default: 0.0.0.0

The IP address on which the nars server listens.
