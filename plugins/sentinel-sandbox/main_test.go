package main

import (
	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
	"strings"
	"testing"
)

func request(command string, args map[string]string) sentinelplugin.Request {
	return sentinelplugin.Request{Version: 1, Command: command, Actor: "admin", Role: "admin", Args: args}
}
func TestStatusFailClosed(t *testing.T) {
	r, err := status(request("status", nil))
	if err != nil || r.Values["execution"] != "disabled" {
		t.Fatalf("unexpected: %#v %v", r, err)
	}
}
func TestProfilesAndPlan(t *testing.T) {
	r, err := profiles(request("profiles", nil))
	if err != nil || !strings.Contains(r.Text, "NOT executable") {
		t.Fatalf("%#v %v", r, err)
	}
	r, err = plan(request("plan", map[string]string{"profile": "agent-code-v1"}))
	if err != nil || r.View != "profile" || r.Values["runtime"] != "firecracker" {
		t.Fatalf("%#v %v", r, err)
	}
	if _, err = plan(request("plan", map[string]string{"profile": "../../../etc"})); err == nil {
		t.Fatal("path-like name accepted")
	}
	if _, err = plan(request("plan", map[string]string{"profile": "python-safe-v1", "shell": "true"})); err == nil {
		t.Fatal("arbitrary runtime options accepted")
	}
}
func TestDoctorNoExecution(t *testing.T) {
	r, err := doctor(request("doctor", nil))
	if err != nil || !strings.Contains(r.Text, "[BLOCKED]") {
		t.Fatalf("%v %#v", err, r)
	}
}
