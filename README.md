# nginx-auth-request-azuread (naraad)

This is an HTTP server that provides authentication for a website served by
nginx, based on Azure AD OAuth 2.0 service.

## Installation

```
$ npm install -g nginx-auth-request-oauth2
```

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
    proxy_set_header X-Callback-URL $scheme://$host/auth/callback;
  }

  location /auth/callback {
    proxy_pass http://127.0.0.1:9090/callback;
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
the callback to the `/callback` path of the naraad server.

#### oauth_authorization_url

This is the URL that the user's browser will be directed to, to initiate the
OAuth 2.0 authentication. It must be set to the OAuth 2.0 authentication
endpoint of the Azure AD instance in which the application is configured.

#### oauth_token_rul

This is the URL that the naraad server will access to obtain an access token.

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

The TCP port on which the naraad server listens.

#### server_address

default: 0.0.0.0

The IP address on which the naraad server listens.

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
