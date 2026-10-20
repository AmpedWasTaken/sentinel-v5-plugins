package main

import (
 "context"
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
 "strings"
 "time"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

type Settings struct {
 Endpoint string `json:"endpoint"`
 AllowedHost string `json:"allowed_host"`
 TimeoutMS int `json:"timeout_ms"`
 Query map[string]string `json:"query"`
}
var safeArg=regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)
func allowed(ip netip.Addr) bool {
 return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.Is4In6() && !ip.Is6()
}
func newClient(host string, timeout time.Duration)*http.Client{
 dialer:=&net.Dialer{Timeout:time.Second}
 transport:=&http.Transport{
  Proxy:nil,
  DisableKeepAlives:true,
  TLSHandshakeTimeout:time.Second,
  DialContext:func(ctx context.Context,network,address string)(net.Conn,error){
   requestedHost,port,err:=net.SplitHostPort(address)
   if err!=nil{return nil,err}
   if !strings.EqualFold(strings.TrimSuffix(requestedHost,"."),host)||port!="443"{return nil,errors.New("unexpected outbound host or port")}
   addresses,err:=net.DefaultResolver.LookupNetIP(ctx,"ip",host)
   if err!=nil{return nil,errors.New("DNS resolution failed")}
   for _,ip:=range addresses{if !allowed(ip){return nil,errors.New("destination resolves to a blocked address")}}
   if len(addresses)==0{return nil,errors.New("destination has no DNS addresses")}
   return dialer.DialContext(ctx,"tcp",net.JoinHostPort(addresses[0].String(),"443"))
  },
 }
 return &http.Client{Timeout:timeout,Transport:transport,CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}}
}
func loadSettings()(Settings,error){
 var c Settings
 file,err:=os.Open("config.json")
 if err!=nil{return c,err}
 defer file.Close()
 dec:=json.NewDecoder(io.LimitReader(file,8192))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(&c);err!=nil{return c,err}
 u,err:=url.Parse(c.Endpoint)
 if err!=nil{return c,err}
 if u.Scheme!="https"||u.User!=nil||u.Port()!=""||u.RawQuery!=""||u.Fragment!=""||u.Hostname()==""||u.Path==""||u.Path=="/"{
  return c,errors.New("endpoint must be a fixed HTTPS URL on port 443 without embedded credentials, query or fragment")
 }
 if !strings.EqualFold(u.Hostname(),c.AllowedHost)||strings.Contains(c.AllowedHost,":")||net.ParseIP(c.AllowedHost)!=nil||!strings.Contains(c.AllowedHost,".") {
  return c,errors.New("endpoint hostname must match configured public allowed_host")
 }
 if c.TimeoutMS<500||c.TimeoutMS>3000{return c,errors.New("timeout_ms must be between 500 and 3000")}
 if len(c.Query)==0 { return c,errors.New("query mapping required") }
 if len(c.Query)>8 { return c,errors.New("too many query fields") }
 for key,template:=range c.Query {
  if !safeArg.MatchString(key) { return c,errors.New("invalid query field") }
  if template!="<<$target>>" && template!="<<$category>>" { return c,errors.New("unsupported query template: "+key) }
 }
 return c,nil
}
func run(req sentinelplugin.Request)(sentinelplugin.Result,error){
 var empty sentinelplugin.Result
 for key,value:=range req.Args{
  if key!="target"&&key!="category"{return empty,fmt.Errorf("unknown argument %s",key)}
  if !safeArg.MatchString(value){return empty,fmt.Errorf("invalid argument %s",key)}
 }
 target:=req.Args["target"]
 if target==""{return empty,errors.New("target is required")}
 category:=req.Args["category"]
 if category==""{category="general"}
 if category!="general"&&category!="security"&&category!="inventory"&&category!="monitoring"{return empty,errors.New("unsupported category")}
 c,err:=loadSettings()
 if err!=nil{return empty,fmt.Errorf("invalid administrator configuration: %w",err)}
 u,_:=url.Parse(c.Endpoint)
 q:=u.Query()
 for key,template:=range c.Query {
  switch template {
  case "<<$target>>": q.Set(key,target)
  case "<<$category>>": q.Set(key,category)
  }
 }
 u.RawQuery=q.Encode()
 ctx,cancel:=context.WithTimeout(context.Background(),time.Duration(c.TimeoutMS)*time.Millisecond)
 defer cancel()
 request,err:=http.NewRequestWithContext(ctx,http.MethodGet,u.String(),nil)
 if err!=nil{return empty,err}
 request.Header.Set("Accept","application/json")
 request.Header.Set("User-Agent","Sentinel-Simple-C2/1")
 response,err:=newClient(c.AllowedHost,time.Duration(c.TimeoutMS)*time.Millisecond).Do(request)
 if err!=nil{return empty,errors.New("approved API request failed")}
 defer response.Body.Close()
 if response.StatusCode<200||response.StatusCode>=300{return empty,fmt.Errorf("provider returned HTTP %d",response.StatusCode)}
 body,err:=io.ReadAll(io.LimitReader(response.Body,16385))
 if err!=nil||len(body)>16384{return empty,errors.New("provider response too large")}
 var doc struct {
  Success bool `json:"success"`
  Message string `json:"message"`
  Data struct {
   Service string `json:"service"`
   Records int `json:"records"`
  } `json:"data"`
 }
 if err:=json.Unmarshal(body,&doc);err!=nil{return empty,errors.New("invalid provider JSON response")}
 status:="completed"
 if !doc.Success{status="unsuccessful"}
 return sentinelplugin.Result{View:"bridge-result",Values:map[string]string{
  "target":target,"category":category,"status":status,
  "service":doc.Data.Service,"records":fmt.Sprint(doc.Data.Records),"message":doc.Message,
 }},nil
}
func main(){
 plugin:=sentinelplugin.New()
 if err:=plugin.Command("lookup",run);err!=nil{log.Fatal(err)}
 if err:=plugin.Command("attack",simulateAttack);err!=nil{log.Fatal(err)}
 if err:=plugin.Serve();err!=nil{log.Fatal(err)}
}
