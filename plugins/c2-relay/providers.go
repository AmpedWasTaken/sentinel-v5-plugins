package main

import (
 "errors"
 "fmt"
 "net"
 "net/url"
 "strconv"
 "strings"
)

type ProviderConfig struct {
 Enabled bool `yaml:"enabled"`
 Endpoints []ProviderEndpoint `yaml:"endpoints"`
}
type ProviderEndpoint struct {
 Name string `yaml:"name"`
 URL string `yaml:"url"`
}
type MethodConfig struct {
 Enabled bool `yaml:"enabled"`
 Description string `yaml:"description"`
 Providers []string `yaml:"providers"`
 Permissions []string `yaml:"permissions"`
 MinimumSuccess int `yaml:"minimum_success"`
}

func validateProviderMethods(f RelayConfig) error {
 if len(f.Providers)==0||len(f.Providers)>12{return errors.New("configure 1..12 providers")}
 if len(f.Methods)==0||len(f.Methods)>8{return errors.New("configure 1..8 methods")}
 groups:=map[string]bool{}
 for _,g:=range f.Groups{groups[g.Name]=true}
 for id,p:=range f.Providers {
  if !safeSlug.MatchString(id){return fmt.Errorf("invalid provider identifier %q",id)}
  if len(p.Endpoints)==0||len(p.Endpoints)>3{return fmt.Errorf("provider %q requires 1..3 endpoints",id)}
  seen:=map[string]bool{}
  for _,ep:=range p.Endpoints {
   if !safeSlug.MatchString(ep.Name)||seen[ep.Name]{return fmt.Errorf("invalid or duplicate endpoint in provider %q",id)}
   seen[ep.Name]=true
   tmpl:=AttackTemplate{Enabled:true,Mode:"preview_only",URL:ep.URL}
   if err:=tmpl.Validate();err!=nil{return fmt.Errorf("provider %q endpoint %q: %w",id,ep.Name,err)}
  }
 }
 for name,m:=range f.Methods {
  if !safeSlug.MatchString(name)||len(m.Description)>180||strings.ContainsAny(m.Description,"\r\n\x1b"){return fmt.Errorf("invalid method %q",name)}
  if len(m.Providers)==0||len(m.Providers)>4{return fmt.Errorf("method %q needs 1..4 providers",name)}
  total:=0
  seen:=map[string]bool{}
  for _,id:=range m.Providers {
   p,exists:=f.Providers[id]
   if !exists||!p.Enabled||seen[id]{return fmt.Errorf("method %q references unavailable provider %q",name,id)}
   seen[id]=true
   total+=len(p.Endpoints)
  }
  if m.MinimumSuccess<1||m.MinimumSuccess>total{return fmt.Errorf("method %q invalid minimum_success",name)}
  if len(m.Permissions)==0||len(m.Permissions)>16{return fmt.Errorf("method %q requires group permissions",name)}
  seenPermission:=map[string]bool{}
  for _,perm:=range m.Permissions{
   if !groups[perm]||seenPermission[perm]{return fmt.Errorf("method %q invalid group permission %q",name,perm)}
   seenPermission[perm]=true
  }
 }
 return nil
}

// A target is supplied per command; no provider URL is contacted.
func configuredMethodInfo(req Request, f RelayConfig) (Result,error) {
 m,ok:=f.Methods[req.Command]
 if !ok||!m.Enabled{return Result{},errors.New("method unavailable")}
 for key:=range req.Args{
  if key!="target"&&key!="port"&&key!="duration"&&key!="group"{return Result{},fmt.Errorf("unknown method argument %q",key)}
 }
 target:=strings.TrimSpace(req.Args["target"])
 if target==""||len(target)>253||strings.ContainsAny(target,"\r\n\x1b"){return Result{},errors.New("invalid target argument")}
 if strings.Contains(target,"://"){
  parsed,err:=url.Parse(target)
  if err!=nil||parsed.Scheme!="https"||parsed.Hostname()==""||parsed.User!=nil||parsed.Fragment!=""{return Result{},errors.New("target URL must use HTTPS")}
 }else if net.ParseIP(target)==nil&&!previewHostPattern.MatchString(target){return Result{},errors.New("target must be an IP, hostname, or HTTPS URL")}
 port,err:=strconv.Atoi(req.Args["port"])
 if err!=nil||port<1||port>65535{return Result{},errors.New("port must be 1..65535")}
 group:=req.Args["group"]
 if group==""{group="user"}
 allowed:=false
 for _,name:=range m.Permissions{if name==group{allowed=true;break}}
 if !allowed{return Result{},errors.New("selected group cannot use this method")}
 limit:=0
 for _,g:=range f.Groups{if g.Name==group{limit=g.MaxDurationSeconds;break}}
 if limit==0{return Result{},errors.New("unknown group")}
 seconds:=f.DefaultDurationSeconds
 if raw:=req.Args["duration"];raw!=""{
  seconds,err=strconv.Atoi(raw)
  if err!=nil{return Result{},errors.New("duration must be whole seconds")}
 }
 if seconds<1||seconds>limit{return Result{},fmt.Errorf("duration must be 1..%d seconds",limit)}
 return viewResult("relay-target-restricted",map[string]string{
  "input":fmt.Sprintf("%s %s %d %d",req.Command,target,seconds,port),
  "hint":fmt.Sprintf("%d provider bindings configured. No remote launch API requests sent.",len(m.Providers)),
 }),nil
}
