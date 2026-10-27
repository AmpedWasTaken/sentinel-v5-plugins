//go:build !linux

package sandboxnative

import (
	"context"
	"errors"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxcore"
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
)

var ErrUnavailable = errors.New("native sandbox is supported only on Linux amd64")

type Config struct {
	Launcher      string `json:"launcher"`
	RootFS        string `json:"rootfs"`
	CgroupRoot    string `json:"cgroup_root"`
	Entrypoint    string `json:"entrypoint"`
	FixtureID     string `json:"fixture_id"`
	FixtureDigest string `json:"fixture_digest"`
}
type Backend struct{ Config Config }

func (Backend) Ready(context.Context, sandboxpolicy.Profile) error { return ErrUnavailable }
func (Backend) Run(context.Context, sandboxcore.Spec) (sandboxcore.Result, error) {
	return sandboxcore.Result{}, ErrUnavailable
}
func RootDigest(string) (string, error)            { return "", ErrUnavailable }
func FixtureDigest(string, string) (string, error) { return "", ErrUnavailable }
