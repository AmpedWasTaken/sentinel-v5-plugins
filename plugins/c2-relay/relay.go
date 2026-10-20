// C2 Relay: lightweight, source-only Sentinel V5 plugin.
// All method/provider entries are metadata; no traffic launch endpoints are called.
// Only fixed, read-only HTTPS health/status endpoints can be requested.
package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "net/netip"
 "net/url"
 "os"
 "regexp"
 "sort"
 "strconv"
 "strings"
 "context"
 "time"
 "gopkg.in/yaml.v3"
)

const (
 protocolVersion = 1
 maxRequestBytes = 16*1024
 maxConfigBytes = 64*1024
 configFile = "config.yml"
)

var safeSlug = regexp.MustCompile("^[a-z][a-z0-9_-]{0,31}$")
var hostnamePattern = regexp.MustCompile("^[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)+$")

type Request struct {
 Version int `json:"version"`
 Command string `json:"command"`
 Actor string `json:"actor"`
 Role string `json:"role"`
 Args map[string]string `json:"args"`
}
type Result struct {Text string `json:"text,omitempty"`}
type Response struct {
 Version int `json:"version"`
 Result Result `json:"result"`
 Error string `json:"error,omitempty"`
}
type Config struct {
 Version int `yaml:"version"`
 Relay RelayConfig `yaml:"relay"`
}
type RelayConfig struct {
 CommandPrefix string `yaml:"command_prefix"`
 KVPrefix string `yaml:"kv_prefix"`
 TimeoutUnit string `yaml:"timeout_unit"`
 TimeoutSeconds int `yaml:"timeout_seconds"`
 DefaultDurationSeconds int `yaml:"default_duration_seconds"`
 UserAgent string `yaml:"user_agent"`
 CallbackPreview bool `yaml:"callback_preview"`
 Groups []Group `yaml:"groups"`
 DNS DNSConfig `yaml:"dns"`
 HealthAPI HealthAPI `yaml:"health_api"`
 Providers map[string]Provider `yaml:"providers"`
 Methods map[string]Method `yaml:"methods"`
}
type Group struct {
 Name string `yaml:"name"`
 MaxDurationSeconds int `yaml:"max_duration_seconds"`
 MaxConcurrent int `yaml:"max_concurrent"`
}
type DNSConfig struct {
 Enabled bool `yaml:"enabled"`
 Resolvers []string `yaml:"resolvers"`
}
type Provider struct {
 Enabled bool `yaml:"enabled"`
 Endpoints []ProviderEndpoint `yaml:"endpoints"`
}
type ProviderEndpoint struct {
 Name string `yaml:"name"`
 URL string `yaml:"url"`
}
type Method struct {
 Enabled bool `yaml:"enabled"`
 Description string `yaml:"description"`
 Providers []string `yaml:"providers"`
 Permissions []string `yaml:"permissions"`
 MinimumSuccess int `yaml:"minimum_success"`
}

func readConfig(path string)(Config,error){
 var cfg Config
 info,err:=os.Lstat(path)
 if err!=nil{return cfg,fmt.Errorf("config.yml is unavailable: %w",err)}
 if !info.Mode().IsRegular()||info.Size()<1||info.Size()>maxConfigBytes{
  return cfg,errors.New("config.yml must be a regular file between 1 B and 64 KiB")
 }
 file,err:=os.Open(path);if err!=nil{return cfg,err}
 defer file.Close()
 decoder:=yaml.NewDecoder(io.LimitReader(file,maxConfigBytes+1))
 decoder.KnownFields(true)
 if err:=decoder.Decode(&cfg);err!=nil{return Config{},fmt.Errorf("invalid YAML: %w",err)}
 var extra any
 if err:=decoder.Decode(&extra);err!=io.EOF{return Config{},errors.New("only one YAML document is permitted")}
 if err:=cfg.Validate();err!=nil{return Config{},err}
 return cfg,nil
}

func(cfg Config)Validate()error{
 f:=cfg.Relay
 if cfg.Version!=1{return errors.New("unsupported config version")}
 if f.CommandPrefix!="!"{return errors.New("command_prefix must be ! (host does not interpret it automatically)")}
 if f.KVPrefix!="-"&&f.KVPrefix!="--"{return errors.New("invalid kv_prefix")}
 if f.TimeoutUnit!="second"||f.TimeoutSeconds<1||f.TimeoutSeconds>60{return errors.New("invalid timeout")}
 if f.DefaultDurationSeconds<1||f.DefaultDurationSeconds>600{return errors.New("invalid default duration")}
 if len(f.UserAgent)>128||strings.ContainsAny(f.UserAgent,"\r\n\x1b"){return errors.New("invalid user_agent")}
 if len(f.Groups)==0||len(f.Groups)>16{return errors.New("configure 1..16 groups")}
 groups:=map[string]bool{}
 for _,g:=range f.Groups {
  if !safeSlug.MatchString(g.Name)||groups[g.Name]||g.MaxDurationSeconds<1||g.MaxDurationSeconds>600||g.MaxConcurrent<1||g.MaxConcurrent>15{
   return fmt.Errorf("invalid group %q",g.Name)
  }
  groups[g.Name]=true
 }
 if len(f.DNS.Resolvers)>4{return errors.New("too many resolver labels")}
 for _,resolver:=range f.DNS.Resolvers {
  ip:=net.ParseIP(resolver)
  if ip==nil||!allowedPublicIP(ip){return fmt.Errorf("invalid public DNS resolver %q",resolver)}
 }
 if err:=f.HealthAPI.Validate();err!=nil{return err}
 if len(f.Providers)==0||len(f.Providers)>12{return errors.New("configure 1..12 providers")}
 if len(f.Methods)==0||len(f.Methods)>8{return errors.New("configure 1..8 methods")}
 for id,p:=range f.Providers {
  if !safeSlug.MatchString(id)||len(p.Endpoints)==0||len(p.Endpoints)>3{return fmt.Errorf("invalid provider %q",id)}
  seen:=map[string]bool{}
  for _,ep:=range p.Endpoints{
   if !safeSlug.MatchString(ep.Name)||seen[ep.Name]{return fmt.Errorf("invalid provider endpoint in %q",id)}
   seen[ep.Name]=true
   if err:=validateProviderURL(ep.URL);err!=nil{return fmt.Errorf("provider %s endpoint %s: %w",id,ep.Name,err)}
  }
 }
 for id,m:=range f.Methods{
  if !safeSlug.MatchString(id)||len(m.Description)>180||strings.ContainsAny(m.Description,"\r\n\x1b"){
   return fmt.Errorf("invalid method %q",id)
  }
  if len(m.Providers)==0||len(m.Providers)>4||len(m.Permissions)==0||len(m.Permissions)>16{
   return fmt.Errorf("method %q has invalid provider or permission list",id)
  }
  seen:=map[string]bool{}
  count:=0
  for _,p:=range m.Providers {
   provider,exists:=f.Providers[p]
   if !exists||!provider.Enabled||seen[p]{return fmt.Errorf("method %s: provider %q unavailable",id,p)}
   seen[p]=true
   count+=len(provider.Endpoints)
  }
  if m.MinimumSuccess<1||m.MinimumSuccess>count{return fmt.Errorf("method %s: invalid minimum_success",id)}
  seen=map[string]bool{}
  for _,permission:=range m.Permissions {
   if !groups[permission]||seen[permission]{return fmt.Errorf("method %s: invalid group permission %q",id,permission)}
   seen[permission]=true
  }
 }
 return nil
}

// The URL registry is static metadata, never dispatched or interpolated.
func validateProviderURL(raw string)error{
 if len(raw)==0||len(raw)>600||strings.ContainsAny(raw,"\r\n\x1b"){return errors.New("invalid provider URL")}
 u,err:=url.Parse(raw)
 if err!=nil||u.Scheme!="https"||u.Host==""||u.User!=nil||u.Opaque!=""||u.Fragment!=""||u.RawFragment!=""||
    (u.Port()!=""&&u.Port()!="443")||(u.Path!="/testnetwork"&&u.Path!="/attack")||u.RawPath!=""{
  return errors.New("provider URL must be static HTTPS /testnetwork or /attack")
 }
 if !hostnamePattern.MatchString(u.Hostname())||net.ParseIP(u.Hostname())!=nil||strings.HasSuffix(u.Hostname(),".local"){
  return errors.New("provider requires DNS hostname")
 }
 expected:=map[string]string{
  "target":"<<$target>>","port":"<<$port>>","duration":"<<$duration>>",
  "method":"<<$method>>","key":"<<$api_key>>",
 }
 seen:=map[string]bool{}
 for _,part:=range strings.Split(u.RawQuery,"&"){
  key,value,ok:=strings.Cut(part,"=")
  want,allowed:=expected[key]
  if !ok||!allowed||seen[key]||value!=want{return errors.New("provider URLs accept only exact placeholder query fields; never store API keys")}
  seen[key]=true
 }
 for _,required:=range []string{"target","port","duration","method"}{
  if !seen[required]{return fmt.Errorf("missing provider query field %s",required)}
 }
 return nil
}

func sortedKeys[T any](values map[string]T)[]string{
 keys:=make([]string,0,len(values))
 for key:=range values{keys=append(keys,key)}
 sort.Strings(keys)
 return keys
}
func validateTarget(raw string)error{
 if raw==""||len(raw)>253||strings.ContainsAny(raw,"\r\n\x1b"){return errors.New("target must be an IP, DNS hostname or HTTPS URL")}
 if strings.Contains(raw,"://"){
  u,err:=url.Parse(raw)
  if err!=nil||u.Scheme!="https"||u.Hostname()==""||u.User!=nil||u.Fragment!=""{
   return errors.New("target URL must use HTTPS without embedded credentials")
  }
 }else if net.ParseIP(raw)==nil&&!hostnamePattern.MatchString(raw){
  return errors.New("target must be an IP, DNS hostname or HTTPS URL")
 }
 return nil
}
func methodInfo(req Request,relay RelayConfig)(Result,error){
 method,exists:=relay.Methods[req.Command]
 if !exists||!method.Enabled{return Result{},errors.New("unknown or disabled method")}
 for key:=range req.Args {
  if key!="target"&&key!="duration"&&key!="port"&&key!="group"{return Result{},fmt.Errorf("unsupported method argument %q",key)}
 }
 target:=req.Args["target"]
 if err:=validateTarget(target);err!=nil{return Result{},err}
 port,err:=strconv.Atoi(req.Args["port"])
 if err!=nil||port<1||port>65535{return Result{},errors.New("port must be between 1 and 65535")}
 group:=req.Args["group"]
 if group==""{group="user"}
 permitted:=false
 for _,p:=range method.Permissions{if p==group{permitted=true;break}}
 if !permitted{return Result{},errors.New("group is not permitted for this method")}
 maxSeconds:=0
 for _,g:=range relay.Groups{if g.Name==group{maxSeconds=g.MaxDurationSeconds;break}}
 if maxSeconds==0{return Result{},errors.New("group is not configured")}
 seconds:=relay.DefaultDurationSeconds
 if raw:=req.Args["duration"];raw!=""{
  seconds,err=strconv.Atoi(raw);if err!=nil{return Result{},errors.New("duration must be whole seconds")}
 }
 if seconds<1||seconds>maxSeconds{return Result{},fmt.Errorf("duration must be between 1 and %d seconds",maxSeconds)}
 return Result{Text:fmt.Sprintf("Method: %s\nTarget: %s\nDuration: %d seconds\nPort: %d\nProviders: %s\nStatus: configuration validated; no remote launch was sent.",req.Command,target,seconds,port,strings.Join(method.Providers,", "))},nil
}
func handle(req Request,cfg Config)(Result,error){
 if req.Version!=protocolVersion{return Result{},errors.New("unsupported plugin protocol version")}
 relay:=cfg.Relay
 if req.Args==nil{req.Args=map[string]string{}}
 switch req.Command{
 case "info":
  if len(req.Args)>0{return Result{},errors.New("info accepts no arguments")}
  enabled:=0
  for _,m:=range relay.Methods{if m.Enabled{enabled++}}
  return Result{Text:fmt.Sprintf("C2 Relay\nProviders: %d\nMethods: %d (%d enabled)\nReal network access: fixed health endpoints only.",len(relay.Providers),len(relay.Methods),enabled)},nil
 case "methods":
  if len(req.Args)>0{return Result{},errors.New("methods accepts no arguments")}
  lines:=[]string{"Methods:"}
  for _,id:=range sortedKeys(relay.Methods){
   m:=relay.Methods[id]
   if m.Enabled{lines=append(lines,fmt.Sprintf("  %s: providers=[%s], groups=[%s]",id,strings.Join(m.Providers,","),strings.Join(m.Permissions,",")))}
  }
  return Result{Text:strings.Join(lines,"\n")},nil
 case "providers":
  if len(req.Args)>0{return Result{},errors.New("providers accepts no arguments")}
  lines:=[]string{"Providers (no credentials displayed):"}
  for _,id:=range sortedKeys(relay.Providers){
   p:=relay.Providers[id]
   lines=append(lines,fmt.Sprintf("  %s: enabled=%t endpoints=%d",id,p.Enabled,len(p.Endpoints)))
  }
  return Result{Text:strings.Join(lines,"\n")},nil
 case "tcp","udp","http":
  return methodInfo(req,relay)
 case "check":
  if len(req.Args)>0{return Result{},errors.New("check accepts no arguments")}
  status,err:=checkHealthAPI(relay.HealthAPI,relay.UserAgent)
  if err!=nil{return Result{},err}
  return Result{Text:status},nil
 default:return Result{},errors.New("unknown C2 Relay command")
 }
}
func serve(input io.Reader,output io.Writer)error{
 reply:=Response{Version:protocolVersion}
 payload,err:=io.ReadAll(io.LimitReader(input,maxRequestBytes+1))
 if err!=nil||len(payload)>maxRequestBytes{
  reply.Error="invalid plugin request size"
 }else{
  decoder:=json.NewDecoder(strings.NewReader(string(payload)))
  decoder.DisallowUnknownFields()
  var req Request
  if decoder.Decode(&req)!=nil{reply.Error="invalid JSON request"}else{
   var extra any
   if decoder.Decode(&extra)!=io.EOF{reply.Error="multiple requests are forbidden"}else{
    cfg,readErr:=readConfig(configFile)
    if readErr!=nil{reply.Error=readErr.Error()}else{
     response,handleErr:=handle(req,cfg)
     if handleErr!=nil{reply.Error=handleErr.Error()}else{reply.Result=response}
    }
   }
  }
 }
 return json.NewEncoder(output).Encode(reply)
}
func main(){
 if err:=serve(os.Stdin,os.Stdout);err!=nil{log.Fatal(err)}
}

// Health checks only. These requests use fixed approved HTTPS paths.
// Only explicitly configured, read-only health endpoints are supported.
// This is not a general HTTP relay, request templater, or traffic launcher.
type HealthAPI struct {
 Enabled bool `yaml:"enabled"`
 MinimumSuccess int `yaml:"minimum_success"`
 Endpoints []HealthEndpoint `yaml:"endpoints"`
}
type HealthEndpoint struct {
 Name string `yaml:"name"`
 URL string `yaml:"url"`
}

var healthHostPattern=regexp.MustCompile(`^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`)
var blockedRanges=[]netip.Prefix{
 netip.MustParsePrefix("100.64.0.0/10"),
 netip.MustParsePrefix("198.18.0.0/15"),
 netip.MustParsePrefix("192.0.0.0/24"),
 netip.MustParsePrefix("192.0.2.0/24"),
 netip.MustParsePrefix("198.51.100.0/24"),
 netip.MustParsePrefix("203.0.113.0/24"),
 netip.MustParsePrefix("2001:db8::/32"),
}
func allowedPublicIP(ip net.IP)bool{
 if ip==nil||!ip.IsGlobalUnicast()||ip.IsPrivate()||ip.IsLoopback()||ip.IsLinkLocalUnicast(){return false}
 addr,err:=netip.ParseAddr(ip.String())
 if err!=nil{return false}
 for _,prefix:=range blockedRanges{if prefix.Contains(addr.Unmap()){return false}}
 return true
}

func validateHealthURL(raw string)error{
 if len(raw)==0||len(raw)>300||strings.ContainsAny(raw,"\r\n\x1b"){return errors.New("invalid health URL")}
 u,err:=url.Parse(raw)
 if err!=nil {return errors.New("invalid health API URL")}
 if u.Scheme!="https"||u.Host==""||u.User!=nil||u.Opaque!=""||u.RawQuery!=""||
  u.ForceQuery||u.Fragment!=""||u.RawFragment!=""||
  (u.Port()!=""&&u.Port()!="443"){
  return errors.New("health API requires HTTPS without credentials, query parameters, fragments or custom ports")
 }
 host:=strings.ToLower(u.Hostname())
 if len(host)>253||!healthHostPattern.MatchString(host)||strings.HasSuffix(host,".local")||
  strings.HasSuffix(host,".internal")||strings.HasSuffix(host,".localhost")||
  strings.HasSuffix(host,".test")||net.ParseIP(host)!=nil {
  return errors.New("health API requires a public DNS name")
 }
 if (u.Path!="/health"&&u.Path!="/status")||u.RawPath!=""{
  return errors.New("health API only supports GET /health and GET /status")
 }
 return nil
}
func(api HealthAPI)Validate()error{
 if len(api.Endpoints)>3{return errors.New("health API supports a maximum of three endpoints")}
 if api.Enabled&&(len(api.Endpoints)==0||api.MinimumSuccess<1||api.MinimumSuccess>len(api.Endpoints)){
  return errors.New("enabled health API requires a valid endpoint list and minimum_success")
 }
 seen:=map[string]bool{}
 for _,ep:=range api.Endpoints{
  if !safeSlug.MatchString(ep.Name)||seen[ep.Name]{return errors.New("health endpoint names must be unique slugs")}
  seen[ep.Name]=true
  if err:=validateHealthURL(ep.URL);err!=nil{return fmt.Errorf("health endpoint %q: %w",ep.Name,err)}
 }
 return nil
}

// Resolve and validate the complete DNS answer at connection time, then dial
// the vetted IP. The default environment proxy is never used.
func dialPublicHealth(ctx context.Context,network,address string)(net.Conn,error){
 host,port,err:=net.SplitHostPort(address)
 if err!=nil||port!="443"{return nil,errors.New("unexpected health destination")}
 ips,err:=net.DefaultResolver.LookupIPAddr(ctx,host)
 if err!=nil||len(ips)==0{return nil,errors.New("health DNS lookup failed")}
 for _,record:=range ips {
  if !allowedPublicIP(record.IP){return nil,errors.New("health DNS contains a blocked IP")}
 }
 dialer:=net.Dialer{Timeout:800*time.Millisecond}
 return dialer.DialContext(ctx,"tcp",net.JoinHostPort(ips[0].IP.String(),port))
}

func checkHealthAPI(api HealthAPI,userAgent string)(string,error){
 if !api.Enabled{return "Health API disabled; no outbound requests.",nil}
 if err:=api.Validate();err!=nil{return "",err}
 if userAgent==""{userAgent="Sentinel-C2-Relay/1.0"}
 client:=http.Client{
  Timeout:1200*time.Millisecond,
  CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse},
  Transport:&http.Transport{
   Proxy:nil,
   DisableKeepAlives:true,
   DialContext:dialPublicHealth,
   TLSHandshakeTimeout:900*time.Millisecond,
  },
 }
 successes:=0
 for _,ep:=range api.Endpoints{
  ctx,cancel:=context.WithTimeout(context.Background(),1200*time.Millisecond)
  req,err:=http.NewRequestWithContext(ctx,http.MethodGet,ep.URL,nil)
  if err==nil{
   req.Header.Set("User-Agent",userAgent)
   req.Header.Set("Accept","application/json")
   resp,callErr:=client.Do(req)
   if callErr==nil{
    _,_=io.Copy(io.Discard,io.LimitReader(resp.Body,256))
    _=resp.Body.Close()
    if resp.StatusCode==200||resp.StatusCode==204{successes++}
   }
  }
  cancel()
 }
 if successes<api.MinimumSuccess{
  return fmt.Sprintf("DEGRADED: %d/%d read-only health endpoints responded successfully",successes,len(api.Endpoints)),nil
 }
 return fmt.Sprintf("HEALTHY: %d/%d read-only health endpoints responded successfully",successes,len(api.Endpoints)),nil
}
