// sentinel-sandboxd is a development-only local Linux runner and readiness CLI.
// There is deliberately NO network listener, SSH command dispatch, or plugin
// privileged API. Run-local must only be invoked by a trusted operator on a
// dedicated disposable Linux worker configured with rootless Docker + gVisor.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxcore"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxoci"
)

type Check struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}
type Report struct {
	Platform         string  `json:"platform"`
	ExecutionEnabled bool    `json:"execution_enabled"`
	Checks           []Check `json:"checks"`
	Warning          string  `json:"warning"`
}

func readable(path string) bool { _, err := os.Stat(path); return err == nil }
func inspect() Report {
	linux := runtime.GOOS == "linux"
	return Report{Platform: runtime.GOOS + "/" + runtime.GOARCH, ExecutionEnabled: false,
		Checks: []Check{
			{Name: "linux-host", Available: linux, Detail: "Linux required for gVisor runner"},
			{Name: "cgroup-v2-visible", Available: linux && readable("/sys/fs/cgroup/cgroup.controllers"), Detail: "Visibility alone does not prove delegated writable limits"},
			{Name: "kvm-device-visible", Available: linux && readable("/dev/kvm"), Detail: "Future Firecracker backend only; not used"},
			{Name: "core-broker", Available: false, Detail: "Not implemented; local operator CLI only"},
			{Name: "verified-isolation-backend", Available: false, Detail: "Must verify rootless Docker, runsc, images and actual isolation on worker"},
			{Name: "durable-job-store", Available: false, Detail: "Not implemented; no crash reconciliation"},
		}, Warning: "Development-only local Linux gVisor execution can be explicitly attempted with run-local. Not a public Sentinel sandbox or multi-tenant security attestation"}
}
func configFile(path string) (sandboxoci.Config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return sandboxoci.Config{}, errors.New("config must have clean absolute path")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return sandboxoci.Config{}, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return sandboxoci.Config{}, errors.New("config file must be regular and not group/world writable")
	}
	if err := checkConfigOwner(path); err != nil {
		return sandboxoci.Config{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return sandboxoci.Config{}, err
	}
	defer f.Close()
	return sandboxoci.Load(f)
}
func runLocal(args []string, out io.Writer) error {
	f := flag.NewFlagSet("run-local", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("config", "", "absolute operator-owned config JSON")
	profileID := f.String("profile", "", "preapproved profile")
	fixtureID := f.String("fixture", "", "preapproved fixture")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *path == "" || *profileID == "" || *fixtureID == "" {
		return errors.New("usage: sentinel-sandboxd run-local --config /absolute/config.json --profile approved-id --fixture approved-id")
	}
	cfg, err := configFile(*path)
	if err != nil {
		return err
	}
	profile, ok := cfg.Profile(*profileID)
	if !ok {
		return errors.New("unknown approved profile")
	}
	fixture, ok := cfg.Fixture(*fixtureID)
	if !ok || fixture.ProfileID != profile.ID {
		return errors.New("fixture is not approved for profile")
	}
	backend, err := sandboxoci.New(cfg, sandboxoci.CLI{Binary: "/usr/bin/docker", Socket: cfg.DockerSocket})
	if err != nil {
		return err
	}
	// The profile limits the job, including a wall clock deadline. No network
	// listener is started. This local fixed operator identity is NOT suitable for
	// an SSH/plugin API and must not be reused as external authorization.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	controller := sandboxcore.New(ctx, backend, 1, 1)
	actor := sandboxcore.Identity{Principal: "local-operator", Tenant: "local-worker", CanRun: true}
	job, err := controller.Submit(ctx, actor, sandboxcore.Request{Profile: profile, FixtureID: fixture.ID, FixtureDigest: fixture.Digest()})
	if err != nil {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		current, e := controller.Get(actor, job.ID)
		if e != nil {
			return e
		}
		switch current.State {
		case sandboxcore.Succeeded, sandboxcore.Failed, sandboxcore.Cancelled, sandboxcore.TimedOut:
			encoder := json.NewEncoder(out)
			encoder.SetIndent("", "  ")
			if e := encoder.Encode(current); e != nil {
				return e
			}
			if current.State != sandboxcore.Succeeded {
				return fmt.Errorf("sandbox ended in state %s", current.State)
			}
			return nil
		}
	}
	return errors.New("unexpected scheduler exit")
}
func run(args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "doctor" {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inspect())
	}
	if len(args) > 0 && args[0] == "run-local" {
		return runLocal(args[1:], out)
	}
	return errors.New("usage: sentinel-sandboxd doctor | run-local --config <absolute-file> --profile <approved-id> --fixture <approved-id>")
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-sandboxd:", strings.ReplaceAll(err.Error(), "\n", " "))
		os.Exit(2)
	}
}
