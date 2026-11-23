# SML Go Showcase — copyable plugin example

This is a small *native Go* counterpart to the preinstalled **SML Showcase**
gallery in the Sentinel core. The bundled gallery needs no executable and is
available through `mode tui` → `plugins open sml-showcase`. This repository
example shows how Go code provides dynamic display-only `data.*` bindings.

## Build and try locally

```sh
go build -o sml-showcase-go ./plugins/sml-showcase-go
```

Copy the plugin folder and the compiled binary into a trusted local Sentinel
developer installation's `assets/plugins/sml-showcase-go/` directory, placing
the executable under `bin/sml-showcase-go` (or `bin/sml-showcase-go.exe` on
Windows). Enable trusted code only after reviewing its source; then enable the
plugin explicitly. It ships with `enabled: false` and should not be silently
activated on production systems.

In a test SSH session:

```text
plugins enable sml-showcase-go
sml-showcase-go preview
mode tui
plugins open sml-showcase-go
```

The sample handler returns synthetic CPU, RAM, disk and time series values,
and a plugin-local SML v3 screen renders gauges, sparklines, metrics and
progress. It never reads host private metrics, invokes shell commands or
contacts remote services.

The Go executable is optional. To browse **all** current SML component
categories without trusting native executable code, use the built-in
`sml-showcase` plugin instead.
