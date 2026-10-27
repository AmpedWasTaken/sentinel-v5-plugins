package sandboxpolicy

import (
	"strings"
	"testing"
)

func TestExampleProfilesValidateAndHash(t *testing.T) {
	for _, p := range ExampleProfiles() {
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", p.ID, err)
		}
		a, err := p.Digest()
		if err != nil {
			t.Fatal(err)
		}
		b, err := p.Digest()
		if err != nil || a != b || !strings.HasPrefix(a, "sha256:") {
			t.Fatalf("unstable digest: %s / %s / %v", a, b, err)
		}
		modified := p
		modified.CPUMilli++
		c, err := modified.Digest()
		if err != nil || c == a {
			t.Fatal("digest must change with policy")
		}
	}
}
func TestDenyUnsafeProfiles(t *testing.T) {
	good := ExampleProfiles()[0]
	cases := map[string]func(*Profile){
		"network":       func(p *Profile) { p.Network = "host" },
		"writable":      func(p *Profile) { p.ReadOnlyRoot = false },
		"privileged":    func(p *Profile) { p.AllowPrivileged = true },
		"mount":         func(p *Profile) { p.AllowHostMounts = true },
		"gpu":           func(p *Profile) { p.AllowGPU = true },
		"oversized":     func(p *Profile) { p.MemoryMiB = 20000 },
		"unbounded":     func(p *Profile) { p.WallSeconds = 0 },
		"runtime":       func(p *Profile) { p.Runtime = "native" },
		"mutable-image": func(p *Profile) { p.ImageDigest = "latest" },
		"entrypoint":    func(p *Profile) { p.EntrypointID = "/bin/sh" },
		"version":       func(p *Profile) { p.Version = 2 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := good
			mutate(&p)
			if p.Validate() == nil {
				t.Fatal("unsafe profile was accepted")
			}
		})
	}
}
