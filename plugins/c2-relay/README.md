# C2 Relay — method/provider configuration

C2 Relay defines named **methods** and reusable **API providers**, including multiple
providers assigned to a single method. The target IP or URL is supplied **at command
time**. It is **not** stored in the providers or methods configuration.

This version does not dispatch network-flood or attack-launching requests. Configured
`/testnetwork` URLs are declarative metadata, with no API keys loaded or sent.
The existing `check` operation can make real, read-only HTTPS `/health` or `/status`
GET requests to fixed administrator-approved endpoints.

## YAML organization

```yaml
relay:
  providers:
    provider_one:
      enabled: true
      endpoints:
        - name: primary
          url: "https://api.example.com/testnetwork?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>&key=<<$api_key>>"
    provider_two:
      enabled: true
      endpoints:
        - name: secondary
          url: "https://api2.example.com/testnetwork?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>&key=<<$api_key>>"
  methods:
    tcp:
      enabled: true
      description: "TCP network testing configuration"
      providers: [provider_one, provider_two]
      minimum_success: 1
      permissions: [user, operator]
    udp:
      enabled: true
      description: "UDP network testing configuration"
      providers: [provider_one]
      minimum_success: 1
      permissions: [user]
```

Providers can be shared by multiple methods. A method can reference up to four provider
entries, and each provider may contain up to three distinct endpoints. The
`minimum_success` field is validated configuration metadata; no test-job outcome
is inferred from it. `permissions` refers to configured group labels for the
non-dispatch method arguments, not independent network-test authorization.

Do not put real API credentials in YAML or source control. The `<<$api_key>>`
marker is a **literal placeholder** and is never resolved by this plugin.

## Dynamic targets

Sentinel V5 already supports **bare plugin command aliases** without the plugin
name prefix when the plugin is enabled:

```text
tcp target=192.0.2.10 duration=120 port=80 group=user
udp target=192.0.2.11 duration=120 port=443 group=user
http target=https://staging.example.com duration=120 port=443 group=operator
methods
providers
c2-relay check
```

The TCP/UDP/HTTP handlers **validate the supplied arguments and return an explicit
non-dispatch status**; they do not send target-directed traffic.

The exact legacy `!tcp 192.0.2.10 120 80` syntax is **not enabled**: the
current Sentinel host parses direct aliases and `key=value` arguments; it does not
yet route punctuation-prefixed positional commands through this plugin.

## Build

```sh
cd plugins/c2-relay
go build -trimpath -o c2-relay .
go vet ./...
```

The manifest defaults to `enabled: false`. Sentinel requires an administrator to
enable trusted-code plugins before any Go-based code plugin can run.
