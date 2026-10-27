//go:build linux

package sandboxnative

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
)

func TestNativeFailsClosedWithoutRuntime(t *testing.T) {
	p := sandboxpolicy.ExampleProfiles()[0]
	p.Runtime = sandboxpolicy.Native
	b := Backend{}
	if err := b.Ready(context.Background(), p); err == nil {
		t.Fatal("missing native config must fail closed")
	}
}
func TestRootDigestRejectsSymlinksAndWrites(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned test fixtures")
	}
	d := t.TempDir()
	f := filepath.Join(d, "example")
	if err := os.WriteFile(f, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	initial, err := RootDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(initial, "sha256:") {
		t.Fatal(initial)
	}
	if err := os.WriteFile(f, []byte("updated"), 0644); err != nil {
		t.Fatal(err)
	}
	later, err := RootDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	if initial == later {
		t.Fatal("rootfs content changes must change digest")
	}
	if err := os.Symlink("example", filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := RootDigest(d); err == nil {
		t.Fatal("symlink must be denied")
	}
	if err := os.Remove(filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := RootDigest(d); err == nil {
		t.Fatal("world writable file must be denied")
	}
}
func TestGuestPathValidation(t *testing.T) {
	for _, input := range []string{"", "abc", "/", "/../etc/shadow", "/tmp/../bin/sh", "/dev/null", "/sys/kernel", "/proc/self"} {
		if validGuestPath(input) {
			t.Errorf("accepted unsafe path %q", input)
		}
	}
	if !validGuestPath("/bin/fixture") {
		t.Fatal("expected fixture path to be accepted")
	}
}
func TestOutputCap(t *testing.T) {
	out := &boundedOutput{hash: os.Stdout, cap: 0}
	if n, err := out.Write([]byte("hello")); err != nil || n != 5 || !out.overflow {
		t.Fatal(n, err, out.overflow)
	}
}
