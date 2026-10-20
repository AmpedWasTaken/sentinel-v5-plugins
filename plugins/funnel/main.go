// Funnel is a bounded, offline simulation plugin for Sentinel V5.
// It implements the documented one-shot JSON code-plugin protocol (v1).
// No network operations, shell execution, or attack APIs exist in this process.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	protocolVersion = 1
	maxRequestBytes = 16 * 1024
	maxConfigBytes  = 64 * 1024
	configFile      = "config.yaml"
)

var safeSlug = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

type Request struct {
	Version int               `json:"version"`
	Command string            `json:"command"`
	Actor   string            `json:"actor"`
	Role    string            `json:"role"`
	Args    map[string]string `json:"args"`
}

type Result struct {
	Text   string            `json:"text,omitempty"`
	View   string            `json:"view,omitempty"`
	Values map[string]string `json:"values,omitempty"`
}

type Response struct {
	Version int    `json:"version"`
	Result  Result `json:"result"`
	Error   string `json:"error,omitempty"`
}

type Config struct {
	Version int          `yaml:"version"`
	Funnel  FunnelConfig `yaml:"funnel"`
}
type FunnelConfig struct {
	CommandPrefix          string              `yaml:"command_prefix"`
	KVPrefix               string              `yaml:"kv_prefix"`
	TimeoutUnit            string              `yaml:"timeout_unit"`
	TimeoutSeconds         int                 `yaml:"timeout_seconds"`
	DefaultDurationSeconds int                 `yaml:"default_duration_seconds"`
	UserAgent              string              `yaml:"user_agent"`
	CallbackPreview        bool                `yaml:"callback_preview"`
	Groups                 []Group             `yaml:"groups"`
	DNS                    DNSConfig           `yaml:"dns"`
	Scenarios              map[string]Scenario `yaml:"scenarios"`
}
type Group struct {
	Name               string `yaml:"name"`
	MaxDurationSeconds int    `yaml:"max_duration_seconds"`
	MaxConcurrent      int    `yaml:"max_concurrent"`
}
type DNSConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Resolvers []string `yaml:"resolvers"`
}
type Scenario struct {
	Enabled     bool   `yaml:"enabled"`
	Description string `yaml:"description"`
}

func readConfig(path string) (Config, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("configuration not available: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigBytes || info.Size() < 1 {
		return Config{}, errors.New("configuration must be a regular YAML file up to 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(io.LimitReader(file, maxConfigBytes+1))
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("invalid YAML configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("only one YAML configuration document is allowed")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (cfg Config) Validate() error {
	f := cfg.Funnel
	if cfg.Version != 1 {
		return errors.New("unsupported Funnel config version")
	}
	if len(f.CommandPrefix) != 1 || !strings.Contains("!@#$%^&*?", f.CommandPrefix) {
		return errors.New("command_prefix must be one supported punctuation mark")
	}
	if f.KVPrefix != "-" && f.KVPrefix != "--" {
		return errors.New("kv_prefix must be '-' or '--'")
	}
	if f.TimeoutUnit != "second" || f.TimeoutSeconds < 1 || f.TimeoutSeconds > 60 {
		return errors.New("timeout_unit must be second and timeout_seconds 1..60")
	}
	if f.DefaultDurationSeconds < 1 || f.DefaultDurationSeconds > 600 {
		return errors.New("default_duration_seconds must be 1..600")
	}
	if len(f.UserAgent) > 128 || strings.ContainsAny(f.UserAgent, "\r\n\x1b") {
		return errors.New("user_agent metadata must be single-line and at most 128 bytes")
	}
	if len(f.Groups) == 0 || len(f.Groups) > 16 {
		return errors.New("configure 1..16 groups")
	}
	seen := map[string]bool{}
	for _, group := range f.Groups {
		if !safeSlug.MatchString(group.Name) || seen[group.Name] {
			return errors.New("group names must be unique safe slugs")
		}
		seen[group.Name] = true
		if group.MaxDurationSeconds < 1 || group.MaxDurationSeconds > 600 ||
			group.MaxConcurrent < 1 || group.MaxConcurrent > 15 {
			return fmt.Errorf("group %q exceeds the bounded simulation limits", group.Name)
		}
	}
	if len(f.DNS.Resolvers) > 4 {
		return errors.New("configure at most four DNS resolver labels")
	}
	for _, resolver := range f.DNS.Resolvers {
		ip := net.ParseIP(resolver)
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
			ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("invalid public resolver label %q", resolver)
		}
	}
	if len(f.Scenarios) == 0 || len(f.Scenarios) > 8 {
		return errors.New("configure 1..8 simulation scenarios")
	}
	for name, scenario := range f.Scenarios {
		if !safeSlug.MatchString(name) || len(scenario.Description) > 180 ||
			strings.ContainsAny(scenario.Description, "\r\n\x1b") {
			return fmt.Errorf("invalid scenario %q", name)
		}
	}
	return nil
}

func summary(f FunnelConfig) string {
	enabled := 0
	for _, scenario := range f.Scenarios {
		if scenario.Enabled {
			enabled++
		}
	}
	return fmt.Sprintf("%d groups / %d simulation scenarios / %d enabled", len(f.Groups), len(f.Scenarios), enabled)
}

func sortedScenarios(f FunnelConfig) []string {
	names := make([]string, 0, len(f.Scenarios))
	for name := range f.Scenarios {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func values(mode string) map[string]string {
	return map[string]string{
		"mode": mode, "notice": "SIMULATION ONLY — no traffic or callbacks sent.",
		"scenario": "—", "group": "—", "duration": "—", "concurrency": "—",
		"timeout": "—", "dns": "—", "summary": "—",
	}
}

func handle(req Request, cfg Config) (Result, error) {
	if req.Version != protocolVersion {
		return Result{}, errors.New("unsupported plugin protocol")
	}
	f := cfg.Funnel
	out := values("Configuration")
	if req.Args == nil {
		req.Args = map[string]string{}
	}
	switch req.Command {
	case "info":
		if len(req.Args) != 0 {
			return Result{}, errors.New("info does not accept arguments")
		}
		out["summary"] = summary(f)
		out["timeout"] = strconv.Itoa(f.TimeoutSeconds) + " seconds"
		out["duration"] = strconv.Itoa(f.DefaultDurationSeconds) + " seconds (default)"
		out["dns"] = strconv.FormatBool(f.DNS.Enabled) + " / " + strings.Join(f.DNS.Resolvers, ", ")
		out["notice"] = fmt.Sprintf("Prefix %q / key-value prefix %q. Preview only; no runtime command router override.", f.CommandPrefix, f.KVPrefix)
	case "methods":
		if len(req.Args) != 0 {
			return Result{}, errors.New("methods does not accept arguments")
		}
		names := sortedScenarios(f)
		enabled := make([]string, 0, len(names))
		for _, name := range names {
			if f.Scenarios[name].Enabled {
				enabled = append(enabled, name)
			}
		}
		out["mode"] = "Scenarios"
		out["summary"] = strings.Join(enabled, ", ")
	case "preview":
		for key := range req.Args {
			if key != "scenario" && key != "group" && key != "duration" {
				return Result{}, fmt.Errorf("unsupported preview argument %q", key)
			}
		}
		name := req.Args["scenario"]
		scenario, exists := f.Scenarios[name]
		if !exists || !scenario.Enabled {
			return Result{}, errors.New("select an enabled scenario using scenario=<name>")
		}
		groupName := req.Args["group"]
		if groupName == "" {
			return Result{}, errors.New("select group=<name>")
		}
		var group *Group
		for i := range f.Groups {
			if f.Groups[i].Name == groupName {
				group = &f.Groups[i]
				break
			}
		}
		if group == nil {
			return Result{}, errors.New("unknown simulation group")
		}
		seconds := f.DefaultDurationSeconds
		if raw := req.Args["duration"]; raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil {
				return Result{}, errors.New("duration must be a positive number of seconds")
			}
			seconds = n
		}
		if seconds < 1 || seconds > group.MaxDurationSeconds {
			return Result{}, fmt.Errorf("duration must be 1..%d seconds for group %s", group.MaxDurationSeconds, group.Name)
		}
		out["mode"] = "Scenario preview"
		out["scenario"] = name
		out["group"] = group.Name
		out["duration"] = strconv.Itoa(seconds) + " seconds (simulated)"
		out["concurrency"] = strconv.Itoa(group.MaxConcurrent) + " configured limit (no connections opened)"
		out["timeout"] = strconv.Itoa(f.TimeoutSeconds) + " seconds (configuration only)"
		out["summary"] = scenario.Description
	default:
		return Result{}, errors.New("unknown Funnel command; use info, methods or preview")
	}
	return Result{View: "funnel-report", Values: out}, nil
}

func serve(in io.Reader, out io.Writer, configPath string) error {
	response := Response{Version: protocolVersion}
	bytes, err := io.ReadAll(io.LimitReader(in, maxRequestBytes+1))
	if err != nil || len(bytes) > maxRequestBytes {
		response.Error = "invalid plugin request size"
	} else {
		decoder := json.NewDecoder(strings.NewReader(string(bytes)))
		decoder.DisallowUnknownFields()
		var req Request
		if decoder.Decode(&req) != nil {
			response.Error = "invalid plugin request JSON"
		} else {
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				response.Error = "multiple plugin requests are not allowed"
			} else {
				cfg, configErr := readConfig(configPath)
				if configErr != nil {
					response.Error = fmt.Sprintf("invalid Funnel configuration: %.180s", configErr.Error())
				} else if result, handleErr := handle(req, cfg); handleErr != nil {
					response.Error = handleErr.Error()
				} else {
					response.Result = result
				}
			}
		}
	}
	return json.NewEncoder(out).Encode(response)
}

func main() {
	if err := serve(os.Stdin, os.Stdout, configFile); err != nil {
		log.Fatal(err)
	}
}
