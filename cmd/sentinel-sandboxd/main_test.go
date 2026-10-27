package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDoctorDoesNotClaimExecution(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"doctor"}, &output); err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(output.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.ExecutionEnabled {
		t.Fatal("sandbox must fail closed")
	}
	if len(r.Checks) < 3 {
		t.Fatal("missing readiness checks")
	}
}
func TestNoServeOrExec(t *testing.T) {
	for _, command := range []string{"serve", "run", "start"} {
		if err := run([]string{command}, &bytes.Buffer{}); err == nil {
			t.Fatal("execution command accepted")
		}
	}
}
