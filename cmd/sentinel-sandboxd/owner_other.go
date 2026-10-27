//go:build !linux

package main

import "errors"

func checkConfigOwner(string) error { return errors.New("sandbox execution requires Linux") }
