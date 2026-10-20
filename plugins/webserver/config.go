package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/netip"
 "os"
 "path"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"

 "gopkg.in/yaml.v3"
)

const configPath = "config.yml"
const maxConfigSize = 64 << 10

type Config struct {
 Version int `yaml:"version"`
 Listen string `yaml:"listen"`
 AllowPublic bool `yaml:"allow_public"`
 TLS TLSConfig `yaml:"tls"`
 Rate RateConfig `yaml:"rate_limit"`
 Sites []SiteConfig `yaml:"sites"`
 Routes []RouteConfig `yaml:"routes"`
}
type TLSConfig struct {
 Enabled bool `yaml:"enabled"`
 CertFile string `yaml:"cert_file"`
 KeyFile string `yaml:"key_file"`
}
type RateConfig struct {
 RequestsPerMinute int `yaml:"requests_per_minute"`
 Burst int `yaml:"burst"`
}
type SiteConfig struct {
 Host string `yaml:"host"`
 Root string `yaml:"root"`
 SPAFallback bool `yaml:"spa_fallback"`
}
type RouteConfig struct {
 Path string `yaml:"path"`
 Kind string `yaml:"kind"`
 Status int `yaml:"status"`
 Body string `yaml:"body"`
}
type liveConfig struct {
 raw Config
 sites map[string]SiteConfig
 routes map[string]RouteConfig
}
var hostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func loadConfig() (*liveConfig,error) {
 info,err:=os.Lstat(configPath)
 if err!=nil{return nil,fmt.Errorf("read config.yml: %w",err)}
 if !info.Mode().IsRegular() || info.Size()==0 || info.Size()>maxConfigSize {return nil,errors.New("config.yml must be a regular file, 1..65536 bytes")}
 f,err:=os.Open(configPath);if err!=nil{return nil,err};defer f.Close()
 dec:=yaml.NewDecoder(io.LimitReader(f,maxConfigSize+1))
 dec.KnownFields(true)
 var c Config
 if err:=dec.Decode(&c);err!=nil{return nil,fmt.Errorf("invalid config.yml: %w",err)}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return nil,errors.New("config.yml must contain exactly one document")}
 return validateConfig(c)
}
func validateConfig(c Config)(*liveConfig,error){
 if c.Version!=1{return nil,errors.New("config version must be 1")}
 host,port,err:=net.SplitHostPort(c.Listen)
 if err!=nil{return nil,errors.New("listen must be an IP:port pair")}
 ip,err:=netip.ParseAddr(host)
 if err!=nil || ip.Zone()!="" {return nil,errors.New("listen must use a numeric IPv4/IPv6 address without a zone")}
 n,err:=strconv.Atoi(port)
 if err!=nil || n<1024 || n>65535{return nil,errors.New("listen port must be 1024..65535")}
 if !ip.IsLoopback() {
  if !c.AllowPublic || !c.TLS.Enabled {return nil,errors.New("non-loopback listening requires allow_public: true AND TLS")}
 } else if c.AllowPublic {
  return nil,errors.New("allow_public must be false for a loopback listener")
 }
 if c.TLS.Enabled {
  if c.TLS.CertFile=="" || c.TLS.KeyFile=="" {return nil,errors.New("TLS requires cert_file and key_file")}
  if c.TLS.CertFile==c.TLS.KeyFile {return nil,errors.New("TLS certificate and key paths must differ")}
  if err:=checkTLSFile(c.TLS.CertFile);err!=nil{return nil,fmt.Errorf("TLS certificate: %w",err)}
  if err:=checkTLSFile(c.TLS.KeyFile);err!=nil{return nil,fmt.Errorf("TLS key: %w",err)}
 }else if c.TLS.CertFile!="" || c.TLS.KeyFile!="" {return nil,errors.New("TLS file paths supplied while TLS disabled")}
 if c.Rate.RequestsPerMinute<1 || c.Rate.RequestsPerMinute>1200 || c.Rate.Burst<1 || c.Rate.Burst>200 {
  return nil,errors.New("rate_limit requires requests_per_minute 1..1200 and burst 1..200")
 }
 if len(c.Sites)>16 || len(c.Routes)>32 {return nil,errors.New("too many sites or routes")}
 if len(c.Sites)==0 && len(c.Routes)==0 {return nil,errors.New("configure at least one site or route")}
 rootDir,err:=os.Getwd();if err!=nil{return nil,err}
 cfg:=&liveConfig{raw:c,sites:make(map[string]SiteConfig),routes:make(map[string]RouteConfig)}
 for _,site:=range c.Sites{
  site.Host=strings.ToLower(strings.TrimSpace(site.Host))
  if site.Host!="*" && !validHost(site.Host) {return nil,fmt.Errorf("invalid virtual host %q",site.Host)}
  if site.Host=="*" && !ip.IsLoopback() {return nil,errors.New("wildcard virtual host is allowed only on loopback")}
  if _,ok:=cfg.sites[site.Host];ok{return nil,fmt.Errorf("duplicate virtual host %q",site.Host)}
  if site.Root==""{return nil,errors.New("site root is required")}
  root:=site.Root
  if !filepath.IsAbs(root){root=filepath.Join(rootDir,root)}
  root,err=filepath.EvalSymlinks(root)
  if err!=nil{return nil,fmt.Errorf("site root %q: %w",site.Root,err)}
  rel,err:=filepath.Rel(rootDir,root)
  if err!=nil || rel==".." || strings.HasPrefix(rel,".."+string(filepath.Separator)){return nil,errors.New("site root must stay inside the plugin directory")}
  info,err:=os.Stat(root)
  if err!=nil || !info.IsDir(){return nil,fmt.Errorf("site root is not a directory: %q",site.Root)}
  site.Root=root
  cfg.sites[site.Host]=site
 }
 for _,route:=range c.Routes{
  if route.Path=="" || route.Path[0]!='/' || len(route.Path)>128 || path.Clean(route.Path)!=route.Path || strings.ContainsAny(route.Path,"\\?\x00\r\n") || strings.HasPrefix(route.Path,"/_sentinel/") {
   return nil,fmt.Errorf("invalid or reserved route path %q",route.Path)
  }
  if _,exists:=cfg.routes[route.Path];exists{return nil,fmt.Errorf("duplicate route %q",route.Path)}
  if route.Kind!="json" && route.Kind!="text" {return nil,fmt.Errorf("route %s: kind must be json or text",route.Path)}
  if route.Status<200 || route.Status>299{return nil,fmt.Errorf("route %s: status must be 2xx",route.Path)}
  if len(route.Body)>4096{return nil,fmt.Errorf("route %s: body exceeds 4 KiB",route.Path)}
  if route.Kind=="json" && !json.Valid([]byte(route.Body)){return nil,fmt.Errorf("route %s: invalid JSON body",route.Path)}
  cfg.routes[route.Path]=route
 }
 return cfg,nil
}
func checkTLSFile(name string)error{
 if strings.ContainsAny(name,"\x00\r\n"){return errors.New("invalid file path")}
 info,err:=os.Lstat(name)
 if err!=nil{return err}
 if !info.Mode().IsRegular() || info.Size()<1 || info.Size()>1024*1024{return errors.New("must be a regular non-symlinked file, maximum 1 MiB")}
 return nil
}
func validHost(h string)bool{
 if h=="" || len(h)>253 || strings.Contains(h,".."){return false}
 if ip:=net.ParseIP(h);ip!=nil{return true}
 if !hostPattern.MatchString(h){return false}
 for _,part:=range strings.Split(h,".") {
  if part=="" || len(part)>63 || strings.HasPrefix(part,"-") || strings.HasSuffix(part,"-"){return false}
 }
 return true
}
