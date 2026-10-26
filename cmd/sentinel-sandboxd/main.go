// sentinel-sandboxd currently provides read-only host prerequisites reporting.
// It intentionally cannot serve requests or execute guest code until the
// authenticated Sentinel broker and OS isolation runner are implemented.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
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
	return Report{
		Platform:         runtime.GOOS + "/" + runtime.GOARCH,
		ExecutionEnabled: false,
		Checks: []Check{
			{Name: "linux-host", Available: linux, Detail: "Linux required for initial runner"},
			{Name: "cgroup-v2-visible", Available: linux && readable("/sys/fs/cgroup/cgroup.controllers"), Detail: "Visibility only; does not prove writable delegation or enforced limits"},
			{Name: "kvm-device-visible", Available: linux && readable("/dev/kvm"), Detail: "Visibility only; does not prove KVM permissions or secure Firecracker setup"},
			{Name: "core-broker", Available: false, Detail: "Not implemented"},
			{Name: "verified-isolation-backend", Available: false, Detail: "Not implemented"},
			{Name: "durable-job-store", Available: false, Detail: "Not implemented"},
		},
		Warning: "Read-only development diagnostics; no code execution, privileged operations or production isolation available",
	}
}
func run(args []string, out io.Writer) error {
	if len(args) != 1 || args[0] != "doctor" {
		return errors.New("usage: sentinel-sandboxd doctor (inspection only; execution disabled)")
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inspect())
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
