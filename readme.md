This repository includes an traefik middleware plugin `kratos-extend-session`.

## Usage

For a plugin to be active for a given Traefik instance, it must be declared in the static configuration.

Plugins are parsed and loaded exclusively during startup, which allows Traefik to check the integrity of the code and catch errors early on.
If an error occurs during loading, the plugin is disabled.

For security reasons, it is not possible to start a new plugin or modify an existing one while Traefik is running.

Once loaded, middleware plugins behave exactly like statically compiled middlewares.
Their instantiation and behavior are driven by the dynamic configuration.

Plugin dependencies must be [vendored](https://golang.org/ref/mod#vendoring) for each plugin.
Vendored packages should be included in the plugin's GitHub repository. ([Go modules](https://blog.golang.org/using-go-modules) are not supported.)

### Configuration

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

The following declaration (given here in YAML) defines a plugin:

```yaml
# Static configuration

experimental:
  plugins:
    kratos-session-extend:
      moduleName: github.com/leesalminen/kratos-session-extend
      version: v0.2.0
```

Here is an example of a file provider dynamic configuration (given here in YAML), where the interesting part is the `http.middlewares` section:

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - kratos-session-extent

  services:
   service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
  
  middlewares:
    kratos-session-extend:
      plugin:
        kratos-session-extend:
          headers:
            cacheSeconds: 300
            sessionCookie: "my_session"
            lastRefreshedCookie: "my_session_last_refreshed"
            cookieDomain: "127.0.0.1"
            identityApiBaseUrl: "http://127.0.0.1:4433"
            adminApiBaseUrl: "http://127.0.0.1:4434"
            signingKey: "THIS_IS_DANGEROUS_CHANGE_ME"
```