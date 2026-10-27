//go:build !linux

package sandboxoci

import "errors"

func checkUIDAndSocketOwner(_ string) error { return errors.New("sandbox execution requires Linux") }
