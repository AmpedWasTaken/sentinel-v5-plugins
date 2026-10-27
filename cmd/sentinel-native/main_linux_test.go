//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectRootAndBadCommand(t *testing.T) {
	var buf bytes.Buffer
	err := run([]string{"run"}, &buf)
	if err == nil {
		t.Fatal("must reject incomplete run")
	}
}
func TestConfigRejectsUntrustedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"profile":{}}`), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0666); err != nil {
		t.Fatal(err)
	}
	_, err := readConfig(p)
	if err == nil || !strings.Contains(err.Error(), "root-owned") {
		t.Fatalf("unexpected: %v", err)
	}
}
