//go:build linux

// sentinel-native is a LOCAL, OPERATOR-ONLY experimental sandbox controller.
// It is NOT reachable from Sentinel SSH and must not run on production hosts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxcore"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxnative"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
)

type operatorConfig struct {
	Profile sandboxpolicy.Profile `json:"profile"`
	Native  sandboxnative.Config  `json:"native"`
}

func readConfig(path string) (operatorConfig, error) {
	var cfg operatorConfig
	st, err := os.Lstat(path)
	if err != nil {
		return cfg, err
	}
	u, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || u.Uid != 0 || st.Mode().Perm()&0022 != 0 || st.Size() > 32<<10 {
		return cfg, errors.New("config must be an ordinary root-owned file not writable by group/others")
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return cfg, errors.New("trailing config data or too large")
	}
	return cfg, nil
}
func run(args []string, w io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("native sandbox requires Linux amd64")
	}
	if os.Geteuid() == 0 {
		return errors.New("refusing root execution: use dedicated non-root operator")
	}
	if len(args) < 1 {
		return errors.New("usage: sentinel-native digest|doctor|run [flags]")
	}
	action := args[0]
	switch action {
	case "digest":
		fs := flag.NewFlagSet("digest", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		rootfs := fs.String("rootfs", "", "operator-owned immutable guest rootfs")
		fixture := fs.String("fixture", "", "guest absolute executable path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if len(fs.Args()) != 0 {
			return errors.New("unexpected digest arguments")
		}
		digest, err := sandboxnative.RootDigest(*rootfs)
		if err != nil {
			return err
		}
		fixtureDigest, err := sandboxnative.FixtureDigest(*rootfs, *fixture)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(map[string]string{"image_digest": digest, "fixture_digest": fixtureDigest})
	case "doctor", "run":
		fs := flag.NewFlagSet(action, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		path := fs.String("config", "", "operator-managed configuration path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if len(fs.Args()) != 0 || *path == "" {
			return errors.New("usage: sentinel-native doctor|run --config /path/approved.json")
		}
		cfg, err := readConfig(*path)
		if err != nil {
			return err
		}
		backend := sandboxnative.Backend{Config: cfg.Native}
		ctx := context.Background()
		if err := backend.Ready(ctx, cfg.Profile); err != nil {
			return err
		}
		if action == "doctor" {
			return json.NewEncoder(w).Encode(map[string]string{"status": "ready-for-disposable-host-testing", "runtime": string(cfg.Profile.Runtime), "security_review": "NOT COMPLETE"})
		}
		policyHash, err := cfg.Profile.Digest()
		if err != nil {
			return err
		}
		subject := sandboxcore.Identity{Principal: "local-operator", Tenant: "local", CanRun: true}
		controller := sandboxcore.New(ctx, backend, 1, 1)
		job, err := controller.Submit(ctx, subject, sandboxcore.Request{Profile: cfg.Profile, FixtureID: cfg.Native.FixtureID, FixtureDigest: cfg.Native.FixtureDigest})
		if err != nil {
			return err
		}
		if job.PolicyHash != policyHash {
			return errors.New("job policy hash mismatch")
		}
		deadline := time.Now().Add(time.Duration(cfg.Profile.WallSeconds+20) * time.Second)
		for time.Now().Before(deadline) {
			state, err := controller.Get(subject, job.ID)
			if err != nil {
				return err
			}
			if state.State == sandboxcore.Succeeded || state.State == sandboxcore.Failed || state.State == sandboxcore.TimedOut || state.State == sandboxcore.Cancelled {
				if err := json.NewEncoder(w).Encode(state); err != nil {
					return err
				}
				if state.State != sandboxcore.Succeeded {
					return fmt.Errorf("native sandbox finished: %s", state.State)
				}
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		_ = controller.Cancel(subject, job.ID)
		return errors.New("job controller response deadline exceeded")
	default:
		return errors.New("usage: sentinel-native digest|doctor|run [flags]")
	}
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-native:", err)
		os.Exit(1)
	}
}
