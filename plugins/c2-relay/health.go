package main

import (
 "context"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/netip"
 "net/url"
 "regexp"
 "strings"
 "time"
)

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
