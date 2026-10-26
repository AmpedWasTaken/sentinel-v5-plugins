// Sentinel Sandbox source-only preview. These handlers are informational and
// never execute workloads, create containers or connect to host control APIs.
package main

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

const notReady = "DISABLED — no authenticated core broker or verified Linux sandbox runner"

func noArgs(r sentinelplugin.Request) error {
	if len(r.Args) != 0 {
		return errors.New("this command accepts no arguments")
	}
	return nil
}

func status(req sentinelplugin.Request) (sentinelplugin.Result, error) {
	if err := noArgs(req); err != nil {
		return sentinelplugin.Result{}, err
	}
	return sentinelplugin.Result{View: "status", Values: map[string]string{
		"health": "not configured", "execution": "disabled", "broker": "not implemented", "runtime": "none attached", "security": "no workload execution possible",
	}, Text: "Sentinel Sandbox: " + notReady}, nil
}
func profiles(req sentinelplugin.Request) (sentinelplugin.Result, error) {
	if err := noArgs(req); err != nil {
		return sentinelplugin.Result{}, err
	}
	var out strings.Builder
	out.WriteString("Sentinel Sandbox / policy examples (NOT executable)\n")
	for _, p := range sandboxpolicy.ExampleProfiles() {
		fmt.Fprintf(&out, "- %s: %s / CPU %dm / RAM %dMiB / timeout %ds / network %s\n", p.ID, p.Runtime, p.CPUMilli, p.MemoryMiB, p.WallSeconds, p.Network)
	}
	out.WriteString("Execution is disabled until a verified runner and Sentinel host broker are installed.")
	return sentinelplugin.Result{Text: out.String()}, nil
}
func plan(req sentinelplugin.Request) (sentinelplugin.Result, error) {
	if len(req.Args) != 1 {
		return sentinelplugin.Result{}, errors.New("usage: sentinel-sandbox plan profile=<approved-profile-id>")
	}
	name := req.Args["profile"]
	if name == "" {
		return sentinelplugin.Result{}, errors.New("missing profile argument")
	}
	for _, p := range sandboxpolicy.ExampleProfiles() {
		if p.ID != name {
			continue
		}
		hash, err := p.Digest()
		if err != nil {
			return sentinelplugin.Result{}, err
		}
		return sentinelplugin.Result{View: "profile", Values: map[string]string{
			"id": p.ID, "runtime": string(p.Runtime), "cpu": strconv.FormatInt(p.CPUMilli, 10), "memory": strconv.FormatInt(p.MemoryMiB, 10), "timeout": strconv.FormatInt(p.WallSeconds, 10), "network": p.Network, "digest": hash, "execution": "disabled (design-only)",
		}}, nil
	}
	return sentinelplugin.Result{}, errors.New("unknown approved sandbox profile")
}
func doctor(req sentinelplugin.Request) (sentinelplugin.Result, error) {
	if err := noArgs(req); err != nil {
		return sentinelplugin.Result{}, err
	}
	return sentinelplugin.Result{Text: "Sentinel Sandbox readiness\n[OK] Command handlers require administrator role in the plugin manifest.\n[OK] Baseline profiles reject host networking, privileged mode, host mounts and GPU.\n[BLOCKED] No Sentinel broker/capability API for sandbox jobs.\n[BLOCKED] No verified Linux isolation backend or enforced CPU/memory/disk limits.\n[BLOCKED] No durable job state, quotas, auditing or signed image registry.\n[BLOCKED] Not approved for multi-tenant or untrusted code execution.\nThis report describes the implementation, not a security attestation."}, nil
}
func createApp() *sentinelplugin.App {
	app := sentinelplugin.New()
	for name, handler := range map[string]sentinelplugin.Handler{"status": status, "profiles": profiles, "plan": plan, "doctor": doctor} {
		if err := app.Command(name, handler); err != nil {
			panic(err)
		}
	}
	return app
}
func main() {
	if err := createApp().Serve(); err != nil {
		log.Fatal(err)
	}
}
