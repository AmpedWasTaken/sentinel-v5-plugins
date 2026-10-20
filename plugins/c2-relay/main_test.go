package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `version: 1
relay:
  command_prefix: "!"
  kv_prefix: "-"
  timeout_unit: second
  timeout_seconds: 15
  default_duration_seconds: 60
  user_agent: ""
  callback_preview: true
  groups:
    - name: user
      max_duration_seconds: 600
      max_concurrent: 15
  dns:
    enabled: true
    resolvers: ["1.1.1.1", "8.8.8.8"]
  scenarios:
    tcp:
      enabled: true
      description: "TCP simulation only"
    dns:
      enabled: false
      description: "Disabled DNS simulation"
`

func fileWithConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func configForTest(t *testing.T) Config {
	t.Helper()
	cfg, err := readConfig(fileWithConfig(t, testConfig))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLoadConfig(t *testing.T) {
	c := configForTest(t)
	if c.Relay.CommandPrefix != "!" || len(c.Relay.DNS.Resolvers) != 2 ||
		c.Relay.Groups[0].MaxConcurrent != 15 {
		t.Fatalf("parsed unexpected config: %+v", c)
	}
}

func TestRejectUnsafeConfig(t *testing.T) {
	cases := []string{
		strings.Replace(testConfig, "timeout_seconds: 15", "timeout_seconds: 0", 1),
		strings.Replace(testConfig, "max_concurrent: 15", "max_concurrent: 9999", 1),
		strings.Replace(testConfig, "1.1.1.1", "127.0.0.1", 1),
		strings.Replace(testConfig, "command_prefix: \"!\"", "command_prefix: \"whoops\"", 1),
		strings.Replace(testConfig, "max_duration_seconds: 600", "max_duration_seconds: 6000", 1),
		strings.Replace(testConfig, "user_agent: \"\"", "user_agent: \"bad\\nagent\"", 1),
		testConfig + "\nextra: true\n",
		testConfig + "\n---\nversion: 1\n",
		strings.Replace(testConfig, "timeout_seconds: 15", "timeout_seconds: 15\n  timeout_seconds: 20", 1),
	}
	for i, content := range cases {
		if _, err := readConfig(fileWithConfig(t, content)); err == nil {
			t.Errorf("unsafe configuration case %d was accepted", i)
		}
	}
}

func TestPreviewHonorsGroupTime(t *testing.T) {
	cfg := configForTest(t)
	req := Request{Version: 1, Command: "preview", Args: map[string]string{
		"scenario": "tcp", "group": "user", "duration": "30",
	}}
	result, err := handle(req, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.View != "relay-preview-sent" || result.Values["duration"] != "30 seconds (simulated)" ||
		result.Values["target"] != "not applicable (offline scenario)" {
		t.Fatalf("unexpected preview result: %+v", result)
	}
}

func TestPreviewRejectsUnsupportedInputs(t *testing.T) {
	cfg := configForTest(t)
	args := []map[string]string{
		{"scenario": "tcp", "group": "user", "duration": "601"},
		{"scenario": "tcp", "group": "user", "duration": "invalid"},
		{"scenario": "dns", "group": "user"},
		{"scenario": "tcp", "group": "missing"},
		{"scenario": "tcp", "group": "user", "target": "example.org"},
	}
	for _, entry := range args {
		if _, err := handle(Request{Version: 1, Command: "preview", Args: entry}, cfg); err == nil {
			t.Errorf("unexpectedly allowed %#v", entry)
		}
	}
}

func TestCommandDispatchAndProtocol(t *testing.T) {
	path := fileWithConfig(t, testConfig)
	for _, command := range []string{"info", "methods", "help"} {
		req, err := json.Marshal(Request{Version: 1, Command: command})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := serve(bytes.NewReader(req), &output, path); err != nil {
			t.Fatal(err)
		}
		var response Response
		if err := json.Unmarshal(output.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Error != "" || response.Version != 1 || response.Result.View == "" {
			t.Fatalf("bad %s protocol response: %+v", command, response)
		}
	}
}

func TestProtocolRejectsUnknownCommandAndExtraJSON(t *testing.T) {
	path := fileWithConfig(t, testConfig)
	for _, input := range []string{
		`{"version":1,"command":"launch"}`,
		`{"version":1,"command":"info"} {"version":1,"command":"info"}`,
		`{"version":1,"command":"info","unknown":"extra"}`,
	} {
		var output bytes.Buffer
		if err := serve(strings.NewReader(input), &output, path); err != nil {
			t.Fatal(err)
		}
		var response Response
		if err := json.Unmarshal(output.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Error == "" {
			t.Errorf("invalid request was accepted: %s", input)
		}
	}
}
