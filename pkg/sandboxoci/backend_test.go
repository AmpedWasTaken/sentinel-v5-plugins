package sandboxoci

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxcore"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
)

const testImg = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var testFixture = Fixture{ID: "hello-v1", ProfileID: "python-safe-v1", ImageRef: "example.test/verified/fixture@" + testImg, Args: []string{"--fixture=hello-v1"}}

func validConfig() Config {
	p := sandboxpolicy.ExampleProfiles()[0]
	p.ImageDigest = testImg
	return Config{Version: 1, DockerSocket: "/run/user/1000/docker.sock", Profiles: []sandboxpolicy.Profile{p}, Fixtures: []Fixture{testFixture}}
}

type mockCLI struct {
	mu          sync.Mutex
	calls       [][]string
	errAt       string
	info        string
	startOutput string
	state       string
}

func (m *mockCLI) Run(ctx context.Context, max int64, args ...string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, append([]string(nil), args...))
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(args) == 0 {
		return "", errors.New("empty command")
	}
	if args[0] == m.errAt {
		return "", errors.New("mock failure")
	}
	switch args[0] {
	case "info":
		if m.info != "" {
			return m.info, nil
		}
		return `["name=rootless","name=seccomp,profile=builtin"]|2|systemd|{"runsc":{}}`, nil
	case "image":
		b, _ := json.Marshal([]string{testFixture.ImageRef})
		return string(b) + "|null", nil
	case "create":
		return strings.Repeat("a", 64), nil
	case "start":
		return m.startOutput, nil
	case "inspect":
		if len(args) > 2 && args[2] == `{{json .HostConfig}}` {
			return effectiveConfig(), nil
		}
		if m.state != "" {
			return m.state, nil
		}
		return `{"Running":false,"OOMKilled":false,"ExitCode":0}`, nil
	case "rm":
		return args[len(args)-1], nil
	}
	return "", errors.New("unhandled fake command")
}
func effectiveConfig() string {
	h := map[string]any{"Runtime": "runsc", "NetworkMode": "none", "ReadonlyRootfs": true, "Privileged": false, "Memory": int64(512) * 1048576, "MemorySwap": int64(512) * 1048576, "NanoCpus": int64(1000) * 1000000, "PidsLimit": 64, "CapDrop": []string{"ALL"}, "CapAdd": []string{}, "SecurityOpt": []string{"no-new-privileges:true"}, "Binds": []string{}, "Mounts": []string{}, "Devices": []string{}, "DeviceRequests": []string{}, "Tmpfs": map[string]string{"/workspace": "rw,nosuid,nodev,uid=65534,gid=65534,mode=0700,size=192m", "/tmp": "rw,nosuid,nodev,uid=65534,gid=65534,mode=0700,size=64m"}, "LogConfig": map[string]any{"Type": "json-file"}}
	b, _ := json.Marshal(h)
	return string(b)
}
func runFixture(t *testing.T, m *mockCLI) (sandboxcore.Result, error) {
	t.Helper()
	cfg := validConfig()
	b, err := New(cfg, m)
	if err != nil {
		t.Fatal(err)
	}
	b.checkHost = func(string) error { return nil }
	hash, err := cfg.Profiles[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	return b.Run(context.Background(), sandboxcore.Spec{ID: strings.Repeat("1", 32), Profile: cfg.Profiles[0], PolicyHash: hash, FixtureID: testFixture.ID, FixtureDigest: testFixture.Digest()})
}
func TestRealRunnerArgumentsAndCleanup(t *testing.T) {
	m := &mockCLI{startOutput: "ok\n"}
	result, err := runFixture(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || !strings.HasPrefix(result.OutputDigest, "sha256:") {
		t.Fatalf("invalid result %+v", result)
	}
	var create []string
	for _, call := range m.calls {
		if call[0] == "create" {
			create = call
		}
	}
	required := []string{"--runtime=runsc", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=65534:65534", "--pids-limit", "--cpus", "--memory", "--memory-swap", "--shm-size=16m", "--pull=never"}
	for _, flag := range required {
		found := false
		for _, arg := range create {
			if arg == flag {
				found = true
			}
		}
		if !found {
			t.Errorf("missing safeguard %q in %v", flag, create)
		}
	}
	if !reflect.DeepEqual(create[len(create)-2:], []string{testFixture.ImageRef, "--fixture=hello-v1"}) {
		t.Fatal("fixture not pinned to approved image and argv")
	}
	if got := m.calls[len(m.calls)-1]; got[0] != "rm" || got[1] != "--force" {
		t.Fatalf("missing forced cleanup: %v", got)
	}
}
func TestRunnerDoesNotDowngradeGVisor(t *testing.T) {
	m := &mockCLI{info: `["name=rootless","name=seccomp,profile=builtin"]|2|systemd|{"runc":{}}`}
	if _, err := runFixture(t, m); err == nil {
		t.Fatal("unsafe runtime downgrade permitted")
	}
	for _, call := range m.calls {
		if call[0] == "create" {
			t.Fatal("created container despite missing runsc")
		}
	}
}
func TestRunnerRefusesRootfulAndCgroupUnenforced(t *testing.T) {
	for _, info := range []string{`["name=seccomp"]|2|systemd|{"runsc":{}}`, `["name=rootless","name=seccomp"]|1|systemd|{"runsc":{}}`, `["name=rootless","name=seccomp"]|2|none|{"runsc":{}}`} {
		m := &mockCLI{info: info}
		if _, err := runFixture(t, m); err == nil {
			t.Fatalf("accepted unsafe docker info %s", info)
		}
	}
}
func TestRunnerFailureStillRemovesContainer(t *testing.T) {
	m := &mockCLI{errAt: "start"}
	_, err := runFixture(t, m)
	if err == nil {
		t.Fatal("failure not reported")
	}
	if got := m.calls[len(m.calls)-1]; got[0] != "rm" {
		t.Fatalf("missing cleanup after failure: %v", got)
	}
}
func TestRunnerRejectsOOMAndNonzeroStatus(t *testing.T) {
	for _, state := range []string{`{"Running":false,"OOMKilled":true,"ExitCode":137}`, `{"Running":false,"OOMKilled":false,"ExitCode":42}`, `{"Running":true,"OOMKilled":false,"ExitCode":0}`} {
		m := &mockCLI{state: state}
		_, err := runFixture(t, m)
		if err == nil {
			t.Fatalf("accepted state %s", state)
		}
		if got := m.calls[len(m.calls)-1]; got[0] != "rm" {
			t.Fatal("missing cleanup")
		}
	}
}
func TestConfigurationDenials(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Profiles[0].Network = "host"
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted host network")
	}
	cfg = validConfig()
	cfg.Profiles[0].Runtime = sandboxpolicy.Firecracker
	if err := cfg.Validate(); err == nil {
		t.Fatal("silently downgraded Firecracker")
	}
	cfg = validConfig()
	cfg.Fixtures[0].ImageRef = "ubuntu:latest"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unverified image tag accepted")
	}
	cfg = validConfig()
	cfg.Fixtures[0].Args = []string{"../../etc/shadow"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("traversal-like fixture argument accepted")
	}
	cfg = validConfig()
	cfg.Fixtures = append(cfg.Fixtures, cfg.Fixtures[0])
	if err := cfg.Validate(); err == nil {
		t.Fatal("duplicate fixture accepted")
	}
	cfg = validConfig()
	cfg.DockerSocket = "tcp://127.0.0.1:2375"
	if err := cfg.Validate(); err == nil {
		t.Fatal("remote Docker endpoint accepted")
	}
}
func TestFixtureDigestChangesWithArguments(t *testing.T) {
	f := testFixture
	f.Args = []string{"--fixture=other"}
	if f.Digest() == testFixture.Digest() {
		t.Fatal("fixture identity did not bind arguments")
	}
}
func TestMalformedJSONRejected(t *testing.T) {
	for _, raw := range []string{`{"version":1,"unknown":true}`, `[]`, `{"version":1} {"version":1}`} {
		if _, err := Load(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted malformed configuration: %s", raw)
		}
	}
}
func TestMockRunnerNeverCalledForBadFixture(t *testing.T) {
	cfg := validConfig()
	m := &mockCLI{}
	b, err := New(cfg, m)
	if err != nil {
		t.Fatal(err)
	}
	b.checkHost = func(string) error { return nil }
	hash, _ := cfg.Profiles[0].Digest()
	_, err = b.Run(context.Background(), sandboxcore.Spec{ID: strings.Repeat("1", 32), Profile: cfg.Profiles[0], PolicyHash: hash, FixtureID: "not-approved", FixtureDigest: testFixture.Digest()})
	if err == nil || len(m.calls) != 0 {
		t.Fatal("unapproved fixture reached runtime")
	}
}

func TestRefusesUnappliedDockerLimits(t *testing.T) {
	cfg := validConfig()
	h := effectiveConfig()
	var obj map[string]any
	if err := json.Unmarshal([]byte(h), &obj); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"Runtime", "NetworkMode", "ReadonlyRootfs", "Privileged", "Memory", "MemorySwap", "NanoCpus", "PidsLimit", "CapDrop", "SecurityOpt", "Tmpfs", "LogConfig"} {
		altered := map[string]any{}
		for k, v := range obj {
			altered[k] = v
		}
		delete(altered, key)
		bytes, _ := json.Marshal(altered)
		if err := verifyHostConfig(string(bytes), cfg.Profiles[0]); err == nil {
			t.Fatalf("missing HostConfig field %s was accepted", key)
		}
	}
}
