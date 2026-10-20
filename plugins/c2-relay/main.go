// C2 Relay registers provider/method mappings and read-only health checks.
// It implements the documented one-shot JSON code-plugin protocol (v1).
// Only fixed HTTPS health checks can access the network; no target-directed API calls.
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
	Relay   RelayConfig `yaml:"relay"`
}
type RelayConfig struct {
	CommandPrefix          string              `yaml:"command_prefix"`
	KVPrefix               string              `yaml:"kv_prefix"`
	TimeoutUnit            string              `yaml:"timeout_unit"`
	TimeoutSeconds         int                 `yaml:"timeout_seconds"`
	DefaultDurationSeconds int                 `yaml:"default_duration_seconds"`
	UserAgent              string              `yaml:"user_agent"`
	CallbackPreview        bool                `yaml:"callback_preview"`
	Groups                 []Group             `yaml:"groups"`
	DNS                    DNSConfig           `yaml:"dns"`
	Providers              map[string]ProviderConfig `yaml:"providers"`
	Methods                map[string]MethodConfig   `yaml:"methods"`
	HealthAPI              HealthAPI           `yaml:"health_api"`
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
	f := cfg.Relay
	if cfg.Version != 1 {
		return errors.New("unsupported C2 Relay config version")
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
	if err := f.HealthAPI.Validate(); err != nil { return err }
	if err:=validateProviderMethods(f);err!=nil{return err}

	return nil
}

func summary(f RelayConfig) string {
 enabled:=0
 for _,m:=range f.Methods{if m.Enabled{enabled++}}
 return fmt.Sprintf("%d groups / %d providers / %d methods / %d enabled",len(f.Groups),len(f.Providers),len(f.Methods),enabled)
}

func values(mode string) map[string]string {
	return map[string]string{
		"mode": mode, "notice": "Provider mapping only — no remote launch URLs are requested.",
		"scenario": "—", "group": "—", "duration": "—", "concurrency": "—",
		"timeout": "—", "dns": "—", "summary": "—",
	}
}

func handle(req Request, cfg Config) (Result, error) {
	if req.Version != protocolVersion {
		return Result{}, errors.New("unsupported plugin protocol")
	}
	f := cfg.Relay
	out := values("Configuration")
	viewName := "relay-overview"
	if req.Args == nil {
		req.Args = map[string]string{}
	}
	switch req.Command {
	case "views":
		return gallery(req)
	case "help":
		if len(req.Args)!=0 {return Result{},errors.New("help accepts no arguments")}
		return viewResult("relay-help",map[string]string{
			"hint":"c2-relay info | providers | methods | check | views",
			"input":"tcp target=192.0.2.10 duration=120 port=80 group=user",
			"detail":"Only approved health GET calls are live. No attack dispatch.",
		}),nil
	case "info":
		if len(req.Args) != 0 {
			return Result{}, errors.New("info does not accept arguments")
		}
		out["summary"] = summary(f)
		viewName = "relay-overview"
		out["timeout"] = strconv.Itoa(f.TimeoutSeconds) + " seconds"
		out["duration"] = strconv.Itoa(f.DefaultDurationSeconds) + " seconds (default)"
		out["dns"] = strconv.FormatBool(f.DNS.Enabled) + " / " + strings.Join(f.DNS.Resolvers, ", ")
		out["notice"] = fmt.Sprintf("Prefix %q / key-value prefix %q. Provider registry only; host command routing unchanged.", f.CommandPrefix, f.KVPrefix)
	case "methods":
        if len(req.Args)!=0{return Result{},errors.New("methods accepts no arguments")}
        names:=make([]string,0,len(f.Methods))
        for name:=range f.Methods{names=append(names,name)}
        sort.Strings(names)
        lines:=[]string{}
        for _,name:=range names{
          m:=f.Methods[name]
          if m.Enabled{lines=append(lines,fmt.Sprintf("%s: providers=%s; minimum_success=%d; groups=%s",name,strings.Join(m.Providers,","),m.MinimumSuccess,strings.Join(m.Permissions,",")))}
        }
        return viewResult("relay-methods",map[string]string{
          "summary":strings.Join(lines,"; "),
          "detail":"Multiple providers may be configured for each method; no remote launch occurs.",
        }),nil
	case "providers":
        if len(req.Args)!=0{return Result{},errors.New("providers accepts no arguments")}
        names:=make([]string,0,len(f.Providers))
        for name:=range f.Providers{names=append(names,name)}
        sort.Strings(names)
        lines:=[]string{}
        for _,name:=range names{p:=f.Providers[name];lines=append(lines,fmt.Sprintf("%s: enabled=%t, endpoints=%d",name,p.Enabled,len(p.Endpoints)))}
        return viewResult("relay-methods",map[string]string{"summary":strings.Join(lines,"; "),"detail":"Provider endpoint registry; no credentials or remote dispatch."}),nil
    case "tcp","udp","http":
        return configuredMethodInfo(req,f)
	case "check":
		if len(req.Args) != 0 { return Result{}, errors.New("check does not accept arguments") }
		status, err := checkHealthAPI(f.HealthAPI, f.UserAgent)
		if err != nil { return Result{}, err }
		out["mode"] = "Read-only health API"
		if strings.HasPrefix(status,"HEALTHY:") {viewName="relay-health-ok"} else if strings.Contains(status,"disabled") {viewName="relay-api-disabled"} else {viewName="relay-health-degraded"}
		out["hint"]="Review relay.health_api in config.yaml."
		out["summary"] = status
		out["timeout"] = "1.2 seconds per approved endpoint"
		out["notice"] = "Fixed HTTPS /health or /status GET only; no attack dispatch, targets or callbacks."
	default:
		return Result{}, errors.New("unknown C2 Relay command; use help, info, providers, methods, tcp, udp, http, check or views")
	}
	return viewResult(viewName,out), nil
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
					response.Error = fmt.Sprintf("invalid C2 Relay configuration: %.180s", configErr.Error())
				} else if result, handleErr := handle(req, cfg); handleErr != nil {
					if view, ok := commandErrorView(req, handleErr); ok {
						response.Result = view
					} else {
						response.Error = handleErr.Error()
					}
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
