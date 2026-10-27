//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
)

func checkConfigOwner(path string) error {
	if os.Geteuid() == 0 {
		return errors.New("sandboxd refuses root execution")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return errors.New("sandbox config must belong to executing operator")
	}
	return nil
}
