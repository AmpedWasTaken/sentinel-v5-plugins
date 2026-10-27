//go:build linux

// Package sandboxnative implements a Linux-native experimental sandbox backend.
// It is not a production isolation boundary or an authenticated service.
package sandboxnative

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxcore"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
)

var ErrUnavailable = errors.New("native sandbox unavailable; fail closed")

// Config is operator-owned, never populated from plugin/SSH request arguments.
// RootFS is a directory of small, root-owned, immutable files, NOT an OCI image.
// Entrypoint is a fixed absolute in-guest executable; no caller-supplied argv.
type Config struct {
	Launcher      string `json:"launcher"`
	RootFS        string `json:"rootfs"`
	CgroupRoot    string `json:"cgroup_root"`
	Entrypoint    string `json:"entrypoint"`
	FixtureID     string `json:"fixture_id"`
	FixtureDigest string `json:"fixture_digest"`
}
type Backend struct{ Config Config }

func validGuestPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return false
	}
	if path == "/" || strings.HasPrefix(path, "/proc/") || strings.HasPrefix(path, "/sys/") || strings.HasPrefix(path, "/dev/") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}
func hexDigest(raw [32]byte) string { return "sha256:" + hex.EncodeToString(raw[:]) }

func checkRootOwned(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if dir && !info.IsDir() {
		return errors.New("not a directory")
	}
	if !dir && !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 && !dir {
		return errors.New("setuid, setgid and sticky regular files are unsupported")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("rootfs must be root-owned and not writable by group/others")
	}
	if !dir && stat.Nlink != 1 {
		return errors.New("rootfs hardlinks are unsupported")
	}
	return nil
}

// RootDigest hashes paths, file bytes and mode of a small rootfs, rejecting
// symlinks and special files. This is a *snapshot comparison*, not a signature;
// operator must prevent modification while a job is launching/running.
func RootDigest(root string) (string, error) {
	if !validGuestPath(root) {
		return "", errors.New("invalid rootfs location")
	}
	if err := checkRootOwned(root, true); err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = io.WriteString(h, "sentinel-native-rootfs-v1\x00")
	count, bytes := 0, int64(0)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 3000 {
			return errors.New("rootfs file limit exceeded")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("rootfs symlinks not supported")
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return errors.New("rootfs special files not supported")
		}
		if err := checkRootOwned(path, d.IsDir()); err != nil {
			return err
		}
		kind := "F"
		if d.IsDir() {
			kind = "D"
		}
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%04o\x00", kind, rel, info.Mode().Perm())
		if !d.IsDir() {
			bytes += info.Size()
			if bytes > 256<<20 {
				return errors.New("rootfs byte limit exceeded")
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			n, readErr := io.Copy(h, io.LimitReader(f, info.Size()+1))
			closeErr := f.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if n != info.Size() {
				return errors.New("rootfs changed during hashing")
			}
		}
		_, _ = io.WriteString(h, "\x00")
		return nil
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func FixtureDigest(root, guestPath string) (string, error) {
	if !validGuestPath(guestPath) {
		return "", errors.New("invalid guest executable path")
	}
	abs := filepath.Join(root, strings.TrimPrefix(guestPath, "/"))
	if err := checkRootOwned(abs, false); err != nil {
		return "", err
	}
	f, err := os.Open(abs)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 256<<20)); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func (b Backend) Ready(ctx context.Context, p sandboxpolicy.Profile) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || p.Runtime != sandboxpolicy.Native {
		return ErrUnavailable
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if p.DiskMiB > 1024 {
		return fmt.Errorf("%w: native /tmp budget maximum is 1024 MiB", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg := b.Config
	if !validGuestPath(cfg.RootFS) || !validGuestPath(cfg.Launcher) || !validGuestPath(cfg.Entrypoint) ||
		!filepath.IsAbs(cfg.CgroupRoot) || cfg.CgroupRoot == "/sys/fs/cgroup" ||
		!strings.HasPrefix(filepath.Clean(cfg.CgroupRoot), "/sys/fs/cgroup/") ||
		cfg.FixtureID != p.EntrypointID {
		return fmt.Errorf("%w: invalid fixed operator configuration", ErrUnavailable)
	}
	if err := checkRootOwned(cfg.Launcher, false); err != nil {
		return fmt.Errorf("%w: launcher: %v", ErrUnavailable, err)
	}
	digest, err := RootDigest(cfg.RootFS)
	if err != nil {
		return fmt.Errorf("%w: rootfs: %v", ErrUnavailable, err)
	}
	if digest != p.ImageDigest {
		return fmt.Errorf("%w: rootfs digest mismatch", ErrUnavailable)
	}
	fixture, err := FixtureDigest(cfg.RootFS, cfg.Entrypoint)
	if err != nil {
		return fmt.Errorf("%w: fixture: %v", ErrUnavailable, err)
	}
	if fixture != cfg.FixtureDigest {
		return fmt.Errorf("%w: fixture digest mismatch", ErrUnavailable)
	}
	if err := checkControllers(cfg.CgroupRoot); err != nil {
		return fmt.Errorf("%w: cgroups: %v", ErrUnavailable, err)
	}
	return nil
}

func checkControllers(path string) error {
	if err := checkRootOrDelegatedDir(path); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(path, "cgroup.subtree_control"))
	if err != nil {
		return err
	}
	for _, controller := range []string{"cpu", "memory", "pids"} {
		found := false
		for _, x := range strings.Fields(string(data)) {
			if x == controller {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("cgroup %s controller not delegated", controller)
		}
	}
	return nil
}
func checkRootOrDelegatedDir(path string) error {
	f, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !f.IsDir() {
		return errors.New("cgroup root not directory")
	}
	return nil
}
func writeSetting(dir, key, value string) error {
	path := filepath.Join(dir, key)
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		return fmt.Errorf("setting %s: %w", key, err)
	}
	return nil
}

// boundedOutput drains every chunk but retains no untrusted stdout bytes.
// The hash is computed over the first N bytes only; overflow invalidates the result.
type boundedOutput struct {
	mu       sync.Mutex
	hash     io.Writer
	cap      int64
	total    int64
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	allowed := b.cap - b.total
	if allowed < 0 {
		allowed = 0
	}
	n := len(p)
	if int64(n) > allowed {
		b.overflow = true
		n = int(allowed)
	}
	if n > 0 {
		_, _ = b.hash.Write(p[:n])
		b.total += int64(n)
	}
	return len(p), nil
}

func (b Backend) Run(ctx context.Context, s sandboxcore.Spec) (sandboxcore.Result, error) {
	if err := b.Ready(ctx, s.Profile); err != nil {
		return sandboxcore.Result{}, err
	}
	if s.FixtureID != b.Config.FixtureID || s.FixtureDigest != b.Config.FixtureDigest {
		return sandboxcore.Result{}, errors.New("unapproved fixture")
	}
	policy, err := s.Profile.Digest()
	if err != nil || policy != s.PolicyHash {
		return sandboxcore.Result{}, errors.New("policy hash mismatch")
	}
	if len(s.ID) != 32 {
		return sandboxcore.Result{}, errors.New("invalid job ID")
	}
	if _, err := hex.DecodeString(s.ID); err != nil {
		return sandboxcore.Result{}, err
	}
	base := b.Config.CgroupRoot
	cg := filepath.Join(base, "sentinel-"+s.ID)
	if err := os.Mkdir(cg, 0700); err != nil {
		return sandboxcore.Result{}, err
	}
	defer func() {
		_ = os.WriteFile(filepath.Join(cg, "cgroup.kill"), []byte("1"), 0644)
		for attempt := 0; attempt < 30; attempt++ {
			if err := os.Remove(cg); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	cpuQuota := s.Profile.CPUMilli * 100000 / 1000
	for _, setting := range [][2]string{
		{"cpu.max", fmt.Sprintf("%d 100000", cpuQuota)},
		{"memory.max", strconv.FormatInt(s.Profile.MemoryMiB*1024*1024, 10)},
		{"memory.swap.max", "0"},
		{"pids.max", strconv.FormatInt(s.Profile.PIDs, 10)},
	} {
		if err := writeSetting(cg, setting[0], setting[1]); err != nil {
			return sandboxcore.Result{}, err
		}
	}
	if _, err := os.Stat(filepath.Join(cg, "cgroup.kill")); err != nil {
		return sandboxcore.Result{}, errors.New("kernel cgroup.kill is required")
	}
	wallCtx, cancel := context.WithTimeout(ctx, time.Duration(s.Profile.WallSeconds)*time.Second)
	defer cancel()
	args := []string{"--rootfs", b.Config.RootFS, "--tmp-mib", strconv.FormatInt(s.Profile.DiskMiB, 10), "--wall-sec", strconv.FormatInt(s.Profile.WallSeconds, 10), "--", b.Config.Entrypoint}
	command := exec.Command(b.Config.Launcher, args...)
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		return sandboxcore.Result{}, err
	}
	command.ExtraFiles = []*os.File{gateRead}
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	hash := sha256.New()
	log := &boundedOutput{hash: hash, cap: s.Profile.MaxOutputBytes}
	command.Stdout = log
	command.Stderr = log
	if err := command.Start(); err != nil {
		gateRead.Close()
		gateWrite.Close()
		return sandboxcore.Result{}, err
	}
	gateRead.Close()
	// The C helper is waiting on FD3. Do not release it until quota applies.
	attachErr := writeSetting(cg, "cgroup.procs", strconv.Itoa(command.Process.Pid))
	if attachErr == nil {
		_, attachErr = gateWrite.Write([]byte("!"))
	}
	_ = gateWrite.Close()
	if attachErr != nil {
		_ = os.WriteFile(filepath.Join(cg, "cgroup.kill"), []byte("1"), 0644)
		_ = command.Process.Kill()
		_ = command.Wait()
		return sandboxcore.Result{}, fmt.Errorf("cgroup admission failed: %w", attachErr)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-wallCtx.Done():
		_ = os.WriteFile(filepath.Join(cg, "cgroup.kill"), []byte("1"), 0644)
		_ = command.Process.Kill()
		<-done
		return sandboxcore.Result{}, wallCtx.Err()
	}
	log.mu.Lock()
	overflow := log.overflow
	log.mu.Unlock()
	if overflow {
		return sandboxcore.Result{}, errors.New("sandbox output exceeded limit")
	}
	if waitErr != nil {
		return sandboxcore.Result{}, fmt.Errorf("sandbox exited with error: %w", waitErr)
	}
	return sandboxcore.Result{ExitCode: 0, OutputDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil))}, nil
}
