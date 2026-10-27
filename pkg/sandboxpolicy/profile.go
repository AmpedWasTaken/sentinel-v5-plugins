// Package sandboxpolicy defines the immutable, deny-by-default sandbox admission
// contract. It does not create processes, containers or virtual machines.
package sandboxpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

type Runtime string

const (
	GVisor      Runtime = "gvisor"
	Firecracker Runtime = "firecracker"
	// Native is a development-only, non-production Linux isolation backend.
	Native Runtime = "native"
)

type Profile struct {
	ID              string  `json:"id"`
	Version         uint32  `json:"version"`
	Runtime         Runtime `json:"runtime"`
	ImageDigest     string  `json:"image_digest"`
	EntrypointID    string  `json:"entrypoint_id"`
	CPUMilli        int64   `json:"cpu_millicores"`
	MemoryMiB       int64   `json:"memory_mib"`
	PIDs            int64   `json:"pids"`
	DiskMiB         int64   `json:"disk_mib"`
	WallSeconds     int64   `json:"wall_seconds"`
	MaxOutputBytes  int64   `json:"max_output_bytes"`
	MaxArtifacts    int64   `json:"max_artifacts"`
	Network         string  `json:"network"`
	ReadOnlyRoot    bool    `json:"read_only_root"`
	AllowPrivileged bool    `json:"allow_privileged"`
	AllowHostMounts bool    `json:"allow_host_mounts"`
	AllowGPU        bool    `json:"allow_gpu"`
}

var slug = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var pinnedImage = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (p Profile) Validate() error {
	if !slug.MatchString(p.ID) || !slug.MatchString(p.EntrypointID) || p.Version != 1 {
		return errors.New("invalid profile ID, entrypoint or version")
	}
	if p.Runtime != GVisor && p.Runtime != Firecracker && p.Runtime != Native {
		return errors.New("unsupported sandbox runtime")
	}
	if !pinnedImage.MatchString(p.ImageDigest) {
		return errors.New("image must have an immutable sha256 digest")
	}
	if p.CPUMilli < 100 || p.CPUMilli > 8000 || p.MemoryMiB < 64 || p.MemoryMiB > 16384 ||
		p.PIDs < 1 || p.PIDs > 512 || p.DiskMiB < 16 || p.DiskMiB > 16384 ||
		p.WallSeconds < 1 || p.WallSeconds > 1800 || p.MaxOutputBytes < 1 || p.MaxOutputBytes > 8<<20 ||
		p.MaxArtifacts < 0 || p.MaxArtifacts > 64 {
		return errors.New("resource values exceed sandbox admission limits")
	}
	if p.Network != "none" || !p.ReadOnlyRoot || p.AllowHostMounts || p.AllowPrivileged || p.AllowGPU {
		return errors.New("unsafe sandbox settings: baseline allows no networking, GPU, privileged mode or host mounts")
	}
	return nil
}

// Digest is a stable hash of the *resolved* policy, including runtime and
// image. The digest is NOT a signature or an authorization token.
func (p Profile) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	value, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode profile: %w", err)
	}
	hash := sha256.Sum256(append([]byte("sentinel-sandbox-profile-v1\x00"), value...))
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// ExampleProfiles are policy-shape demonstrations. The all-zero image hash is
// explicitly NOT a usable runtime image; admission must replace and verify it.
func ExampleProfiles() []Profile {
	emptyDigest := "sha256:" + string(makeHexZeros(64))
	return []Profile{
		{ID: "python-safe-v1", Version: 1, Runtime: GVisor, ImageDigest: emptyDigest, EntrypointID: "python-eval-v1", CPUMilli: 1000, MemoryMiB: 512, PIDs: 64, DiskMiB: 256, WallSeconds: 60, MaxOutputBytes: 1 << 20, MaxArtifacts: 8, Network: "none", ReadOnlyRoot: true},
		{ID: "agent-code-v1", Version: 1, Runtime: Firecracker, ImageDigest: emptyDigest, EntrypointID: "agent-eval-v1", CPUMilli: 2000, MemoryMiB: 2048, PIDs: 128, DiskMiB: 1024, WallSeconds: 180, MaxOutputBytes: 1 << 20, MaxArtifacts: 8, Network: "none", ReadOnlyRoot: true},
	}
}
func makeHexZeros(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return b
}
