//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "sentinel-native: custom Linux sandbox unavailable on this OS")
	os.Exit(1)
}
