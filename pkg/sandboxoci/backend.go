// Package sandboxoci runs preapproved, immutable OCI fixtures inside a separately
// configured rootless Docker daemon with the gVisor runsc runtime. It is not a
// plugin-facing API; only a privileged, authenticated host broker may dispatch
// jobs in a production deployment. No fallback runtime is permitted.
package sandboxoci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxcore"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
)

const MaxConfigBytes = 64 * 1024
const placeholderDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

var refName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,220}@sha256:[a-f0-9]{64}$`)
var jobName = regexp.MustCompile(`^[a-f0-9]{32}$`)
var safeArg = regexp.MustCompile(`^[a-zA-Z0-9_./:=+,-]{1,128}$`)

// Config is written by a trusted local operator, never supplied by an SSH user
// or arbitrary plugin. Each fixture is shipped INSIDE a digest-pinned image.
// No host paths, shell execution, volume mounts, or arbitrary network targets.
type Config struct {
	Version      int                     `json:"version"`
	DockerSocket string                  `json:"docker_socket"`
	Profiles     []sandboxpolicy.Profile `json:"profiles"`
	Fixtures     []Fixture               `json:"fixtures"`
}
type Fixture struct {
	ID        string   `json:"id"`
	ProfileID string   `json:"profile_id"`
	ImageRef  string   `json:"image_ref"`
	Args      []string `json:"args"`
}

func Load(r io.Reader) (Config, error) {
	var cfg Config
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return cfg, err
	}
	if len(data) > MaxConfigBytes {
		return cfg, errors.New("sandbox config exceeds size limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid sandbox config: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return cfg, errors.New("sandbox config must contain exactly one JSON object")
	}
	if err = cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
func (c Config) Validate() error {
	if c.Version != 1 {
		return errors.New("unsupported sandbox config version")
	}
	if c.DockerSocket == "" || !filepath.IsAbs(c.DockerSocket) || filepath.Clean(c.DockerSocket) != c.DockerSocket {
		return errors.New("docker socket must be an absolute clean path")
	}
	if len(c.Profiles) == 0 || len(c.Profiles) > 16 || len(c.Fixtures) == 0 || len(c.Fixtures) > 64 {
		return errors.New("require 1..16 profiles and 1..64 fixtures")
	}
	profiles := map[string]sandboxpolicy.Profile{}
	for _, p := range c.Profiles {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("invalid profile %q: %w", p.ID, err)
		}
		if p.Runtime != sandboxpolicy.GVisor {
			return errors.New("only gVisor backend supported, no runtime fallback")
		}
		if p.DiskMiB >= p.MemoryMiB {
			return errors.New("tmpfs disk quota must be smaller than memory limit")
		}
		if p.ImageDigest == placeholderDigest {
			return errors.New("example image digest cannot execute")
		}
		if _, ok := profiles[p.ID]; ok {
			return errors.New("duplicate profile")
		}
		profiles[p.ID] = p
	}
	fixtures := map[string]bool{}
	for _, f := range c.Fixtures {
		if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`).MatchString(f.ID) {
			return errors.New("invalid fixture ID")
		}
		if fixtures[f.ID] {
			return errors.New("duplicate fixture")
		}
		fixtures[f.ID] = true
		p, ok := profiles[f.ProfileID]
		if !ok {
			return errors.New("fixture references unknown profile")
		}
		if !refName.MatchString(f.ImageRef) || !strings.HasSuffix(f.ImageRef, "@"+p.ImageDigest) {
			return errors.New("fixture image ref does not match pinned profile image digest")
		}
		if len(f.Args) > 12 {
			return errors.New("fixture arguments exceed limit")
		}
		for _, arg := range f.Args {
			if !safeArg.MatchString(arg) || strings.Contains(arg, "..") {
				return errors.New("invalid or traversal-like fixture argument")
			}
		}
	}
	return nil
}
func (c Config) Profile(id string) (sandboxpolicy.Profile, bool) {
	for _, p := range c.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return sandboxpolicy.Profile{}, false
}
func (c Config) Fixture(id string) (Fixture, bool) {
	for _, f := range c.Fixtures {
		if f.ID == id {
			return f, true
		}
	}
	return Fixture{}, false
}

// Digest binds the approved fixture arguments, profile and immutable image.
// It is content identity, NOT a signature or user authorization token.
func (f Fixture) Digest() string {
	data, _ := json.Marshal(struct {
		ID        string   `json:"id"`
		ProfileID string   `json:"profile_id"`
		ImageRef  string   `json:"image_ref"`
		Args      []string `json:"args"`
	}{f.ID, f.ProfileID, f.ImageRef, f.Args})
	sum := sha256.Sum256(append([]byte("sentinel-sandbox-fixture-v1\x00"), data...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Executor lets tests inspect subprocess invocations without Docker present.
// Production uses the immutable absolute Docker CLI path, never a shell.
type Executor interface {
	Run(ctx context.Context, limit int64, args ...string) (string, error)
}
type CLI struct{ Binary, Socket string }

func (c CLI) Run(ctx context.Context, limit int64, args ...string) (string, error) {
	if limit < 1 || limit > 8<<20 {
		return "", errors.New("invalid docker response limit")
	}
	// Suppress inherited DOCKER_HOST/CONTEXT/CONFIG and proxies. A preloaded image
	// is mandatory; network download is never performed by this runner.
	command := exec.CommandContext(ctx, c.Binary, append([]string{"--host", "unix://" + c.Socket}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "DOCKER_CONFIG=/nonexistent"}
	writer := &boundedWriter{remaining: limit}
	command.Stdout = writer
	command.Stderr = writer
	err := command.Run()
	if writer.exceeded {
		return "", errors.New("docker output exceeded limit")
	}
	return writer.buffer.String(), err
}

type boundedWriter struct {
	buffer    strings.Builder
	remaining int64
	exceeded  bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if int64(len(p)) > w.remaining {
		w.exceeded = true
		return 0, errors.New("output limit exceeded")
	}
	w.remaining -= int64(len(p))
	_, err := w.buffer.Write(p)
	return n, err
}

// Backend executes fixtures only after verifying the rootless gVisor runtime.
// This is a restricted *local operator* backend, not proof of multi-tenant
// safety and not an authenticated Sentinel service.
type Backend struct {
	Config    Config
	CLI       Executor
	checkHost func(string) error
}

func New(cfg Config, cli Executor) (*Backend, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cli == nil {
		return nil, errors.New("missing docker CLI executor")
	}
	return &Backend{Config: cfg, CLI: cli, checkHost: CheckLocalSocket}, nil
}
func CheckLocalSocket(path string) error {
	if err := checkUIDAndSocketOwner(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("socket unavailable: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("docker endpoint must be a Unix socket, not a symlink")
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if parent.Mode().Perm()&0022 != 0 {
		return errors.New("docker socket directory is writable by untrusted users")
	}
	return nil
}
func CheckDockerBinary(binary string) error {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return errors.New("docker binary must be an absolute path")
	}
	info, err := os.Stat(binary)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("docker binary must be regular and not group/world writable")
	}
	return nil
}
func (b *Backend) Ready(ctx context.Context, p sandboxpolicy.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	approved, ok := b.Config.Profile(p.ID)
	if !ok || approved != p {
		return errors.New("requested profile does not match operator-approved policy")
	}
	if p.Runtime != sandboxpolicy.GVisor {
		return errors.New("refusing runtime downgrade")
	}
	if real, ok := b.CLI.(CLI); ok {
		if err := CheckDockerBinary(real.Binary); err != nil {
			return err
		}
	}
	if err := b.checkHost(b.Config.DockerSocket); err != nil {
		return err
	}
	// Parse runtime configuration; never assume docker default runtime is gVisor.
	output, err := b.CLI.Run(ctx, 8192, "info", "--format", `{{json .SecurityOptions}}|{{.CgroupVersion}}|{{.CgroupDriver}}|{{json .Runtimes}}`)
	if err != nil {
		return fmt.Errorf("cannot inspect rootless Docker runtime: %w", err)
	}
	fields := strings.Split(strings.TrimSpace(output), "|")
	if len(fields) != 4 {
		return errors.New("unexpected Docker capabilities output")
	}
	var opts []string
	if json.Unmarshal([]byte(fields[0]), &opts) != nil {
		return errors.New("invalid Docker security options")
	}
	rootless, seccomp := false, false
	for _, opt := range opts {
		if strings.HasPrefix(opt, "name=rootless") {
			rootless = true
		}
		if strings.HasPrefix(opt, "name=seccomp") {
			seccomp = true
		}
	}
	if !rootless || !seccomp || fields[1] != "2" || fields[2] != "systemd" {
		return errors.New("Docker must be rootless with seccomp and delegated cgroup v2/systemd limits")
	}
	var runtimes map[string]json.RawMessage
	if json.Unmarshal([]byte(fields[3]), &runtimes) != nil {
		return errors.New("invalid Docker runtime catalogue")
	}
	if _, ok := runtimes["runsc"]; !ok {
		return errors.New("gVisor runsc runtime not registered with rootless Docker")
	}
	return nil
}
func (b *Backend) Run(ctx context.Context, spec sandboxcore.Spec) (result sandboxcore.Result, err error) {
	p := spec.Profile
	if err = p.Validate(); err != nil {
		return result, err
	}
	hash, e := p.Digest()
	if e != nil {
		return result, e
	}
	if hash != spec.PolicyHash {
		return result, errors.New("policy hash mismatch")
	}
	if !jobName.MatchString(spec.ID) {
		return result, errors.New("invalid job ID")
	}
	f, ok := b.Config.Fixture(spec.FixtureID)
	if !ok || f.ProfileID != p.ID || f.Digest() != spec.FixtureDigest {
		return result, errors.New("fixture is not approved")
	}
	if err = b.Ready(ctx, p); err != nil {
		return result, err
	}
	refs, inspectErr := b.CLI.Run(ctx, 4096, "image", "inspect", "--format", `{{json .RepoDigests}}|{{json .Config.Volumes}}`, f.ImageRef)
	if inspectErr != nil {
		return result, errors.New("approved pinned image not present locally")
	}
	parts := strings.Split(strings.TrimSpace(refs), "|")
	if len(parts) != 2 {
		return result, errors.New("invalid local image inspection response")
	}
	var volumes map[string]json.RawMessage
	if json.Unmarshal([]byte(parts[1]), &volumes) != nil || len(volumes) != 0 {
		return result, errors.New("image declares filesystem volumes; refuse implicit mounts")
	}
	var digests []string
	if json.Unmarshal([]byte(parts[0]), &digests) != nil {
		return result, errors.New("invalid local image metadata")
	}
	found := false
	for _, ref := range digests {
		if ref == f.ImageRef {
			found = true
		}
	}
	if !found {
		return result, errors.New("local image does not match exact pinned repository digest")
	}
	name := "sentinel-sbx-" + spec.ID
	// The daemon must not accidentally leave a guest running on CLI cancellation.
	// We attempt cleanup on create errors too in case Docker did accept a request.
	created := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if !created {
			return
		}
		if _, e := b.CLI.Run(cleanupCtx, 4096, "rm", "--force", name); e != nil {
			err = errors.Join(err, errors.New("sandbox teardown failed; worker must be quarantined and reconciled"))
		}
	}()
	mem := fmt.Sprintf("%dm", p.MemoryMiB)
	workSize := p.DiskMiB * 3 / 4
	tmpSize := p.DiskMiB - workSize
	if workSize == 0 || tmpSize == 0 || p.DiskMiB >= p.MemoryMiB {
		return result, errors.New("sandbox tmpfs budget must be smaller than memory limit")
	}
	args := []string{"create", "--pull=never", "--name", name, "--runtime=runsc", "--no-healthcheck", "--log-driver=json-file", "--log-opt=max-size=1m", "--log-opt=max-file=1", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit", strconv.FormatInt(p.PIDs, 10), "--memory", mem, "--memory-swap", mem, "--cpus", fmt.Sprintf("%.3f", float64(p.CPUMilli)/1000), "--user=65534:65534", "--ipc=private", "--pid=private", "--shm-size=16m", "--ulimit=nofile=256:256", "--ulimit=core=0:0", "--tmpfs", fmt.Sprintf("/workspace:rw,nosuid,nodev,uid=65534,gid=65534,mode=0700,size=%dm", workSize), "--tmpfs", fmt.Sprintf("/tmp:rw,nosuid,nodev,uid=65534,gid=65534,mode=0700,size=%dm", tmpSize), "--workdir=/workspace", "--label=sentinel.sandbox.managed=true", f.ImageRef}
	args = append(args, f.Args...)
	createOut, createErr := b.CLI.Run(ctx, 4096, args...)
	if createErr != nil {
		// An asynchronous daemon may have created the named container before the CLI
		// returned an error. Attempt cleanup; never claim a successful run.
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		_, cleanupErr := b.CLI.Run(recoveryCtx, 4096, "rm", "--force", name)
		if cleanupErr != nil {
			return result, errors.Join(createErr, errors.New("sandbox create may have left orphan; worker must be quarantined"))
		}
		return result, fmt.Errorf("sandbox create failed: %w", createErr)
	}
	created = true
	cid := strings.TrimSpace(createOut)
	if !regexp.MustCompile(`^[a-f0-9]{12,64}$`).MatchString(cid) {
		return result, errors.New("sandbox create returned invalid container ID")
	}
	output, startErr := b.CLI.Run(ctx, p.MaxOutputBytes, "start", "--attach", name)
	if startErr != nil {
		return result, fmt.Errorf("sandbox start or execution failed: %w", startErr)
	}
	digest := sha256.Sum256([]byte(output))
	result.OutputDigest = "sha256:" + hex.EncodeToString(digest[:])
	exitOut, inspectErr := b.CLI.Run(ctx, 2048, "inspect", "--format", `{{json .State}}`, name)
	if inspectErr != nil {
		return result, errors.New("cannot verify sandbox exit state")
	}
	var state struct {
		Running   bool `json:"Running"`
		OOMKilled bool `json:"OOMKilled"`
		ExitCode  int  `json:"ExitCode"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(exitOut)), &state) != nil {
		return result, errors.New("invalid sandbox exit state")
	}
	if state.Running || state.OOMKilled || state.ExitCode < 0 || state.ExitCode > 255 {
		return result, errors.New("sandbox did not exit cleanly or exceeded memory budget")
	}
	exitCode := state.ExitCode
	result.ExitCode = exitCode
	if exitCode != 0 {
		return result, fmt.Errorf("sandbox fixture exited with status %d", exitCode)
	}
	return result, nil
}

// verifyHostConfig prevents Docker daemons from silently ignoring mandatory
// flags. This is a configuration check, not a proof against kernel escapes.
func verifyHostConfig(raw string, p sandboxpolicy.Profile) error {
	var h struct {
		Runtime        string            `json:"Runtime"`
		NetworkMode    string            `json:"NetworkMode"`
		ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
		Privileged     bool              `json:"Privileged"`
		Memory         int64             `json:"Memory"`
		MemorySwap     int64             `json:"MemorySwap"`
		NanoCpus       int64             `json:"NanoCpus"`
		PidsLimit      int64             `json:"PidsLimit"`
		CapDrop        []string          `json:"CapDrop"`
		CapAdd         []string          `json:"CapAdd"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		Binds          []string          `json:"Binds"`
		Mounts         []json.RawMessage `json:"Mounts"`
		Devices        []json.RawMessage `json:"Devices"`
		DeviceRequests []json.RawMessage `json:"DeviceRequests"`
		Tmpfs          map[string]string `json:"Tmpfs"`
		LogConfig      struct {
			Type string `json:"Type"`
		} `json:"LogConfig"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &h) != nil {
		return errors.New("invalid Docker HostConfig")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &fields) != nil {
		return errors.New("invalid HostConfig shape")
	}
	for _, key := range []string{"Runtime", "NetworkMode", "ReadonlyRootfs", "Privileged", "Memory", "MemorySwap", "NanoCpus", "PidsLimit", "CapDrop", "CapAdd", "SecurityOpt", "Binds", "Mounts", "Devices", "DeviceRequests", "Tmpfs", "LogConfig"} {
		if _, ok := fields[key]; !ok {
			return errors.New("Docker did not report required security setting: " + key)
		}
	}
	contains := func(items []string, want string) bool {
		for _, v := range items {
			if strings.EqualFold(v, want) {
				return true
			}
		}
		return false
	}
	if h.Runtime != "runsc" || h.NetworkMode != "none" || !h.ReadonlyRootfs || h.Privileged || h.Memory != p.MemoryMiB*1048576 || h.MemorySwap != h.Memory || h.NanoCpus != p.CPUMilli*1000000 || h.PidsLimit != p.PIDs || !contains(h.CapDrop, "ALL") || len(h.CapAdd) != 0 || !contains(h.SecurityOpt, "no-new-privileges:true") || len(h.Binds) != 0 || len(h.Mounts) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || h.LogConfig.Type != "json-file" {
		return errors.New("required isolation flag not applied")
	}
	workSize := p.DiskMiB * 3 / 4
	tmpSize := p.DiskMiB - workSize
	if len(h.Tmpfs) != 2 || !strings.Contains(h.Tmpfs["/workspace"], fmt.Sprintf("size=%dm", workSize)) || !strings.Contains(h.Tmpfs["/tmp"], fmt.Sprintf("size=%dm", tmpSize)) {
		return errors.New("tmpfs quota not applied")
	}
	return nil
}

// SelfTestSocket creates no container; used by operators before enabling work.
func SelfTestSocket(socket string) error {
	if err := CheckLocalSocket(socket); err != nil {
		return err
	}
	c, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return fmt.Errorf("cannot dial rootless docker socket: %w", err)
	}
	return c.Close()
}
