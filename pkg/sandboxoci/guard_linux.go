//go:build linux

package sandboxoci

import (
	"errors"
	"os"
	"syscall"
)

func checkUIDAndSocketOwner(path string) error {
	if os.Geteuid() == 0 {
		return errors.New("sandbox controller must not run as root")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("rootless docker socket must belong to controller user")
	}
	return nil
}
