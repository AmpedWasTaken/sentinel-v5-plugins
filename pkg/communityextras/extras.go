package communityextras
import (
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "os/exec"
 "path/filepath"
 "sort"
 "strings"
 "time"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)
func output(s string)(sentinelplugin.Result,error){if len(s)>6000{s=s[:6000]+"\n[truncated]"};return sentinelplugin.Result{Text:s},nil}
func required(a map[string]string,k string)(string,error){s:=strings.TrimSpace(a[k]);if s==""||len(s)>2048{return "",fmt.Errorf("%s required (max 2048 chars)",k)};return s,nil}
func get(ctx context.Context,raw string)(*http.Response,error){
 u,e:=url.Parse(raw);if e!=nil||u.Hostname()==""||(u.Scheme!="https"&&u.Scheme!="http")||u.User!=nil{return nil,errors.New("HTTP(S) URL required")}
 ips,e:=net.DefaultResolver.LookupIPAddr(ctx,u.Hostname());if e!=nil{return nil,e}
 if len(ips)==0{return nil,errors.New("no DNS addresses")}
 for _,ip:=range ips{if ip.IP.IsLoopback()||ip.IP.IsPrivate()||ip.IP.IsLinkLocalUnicast()||ip.IP.IsUnspecified()||ip.IP.IsMulticast(){return nil,errors.New("local/private destination denied")}}
 tr:=&http.Transport{Proxy:nil,DisableKeepAlives:true,DialContext:func(c context.Context,network,addr string)(net.Conn,error){_,p,e:=net.SplitHostPort(addr);if e!=nil{return nil,e};return (&net.Dialer{Timeout:3*time.Second}).DialContext(c,network,net.JoinHostPort(ips[0].IP.String(),p))}}
 client:=&http.Client{Timeout:6*time.Second,Transport:tr,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
 req,e:=http.NewRequestWithContext(ctx,"GET",u.String(),nil);if e!=nil{return nil,e};return client.Do(req)
}
func Run(id,command string,a map[string]string)(sentinelplugin.Result,error){
 ctx,cancel:=context.WithTimeout(context.Background(),6*time.Second);defer cancel()
 switch id {
 case "httpxray":
  if command!="inspect"{break}
  u,e:=required(a,"url");if e!=nil{return sentinelplugin.Result{},e};r,e:=get(ctx,u);if e!=nil{return sentinelplugin.Result{},e};defer r.Body.Close()
  keys:=[]string{"Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options","Referrer-Policy","Permissions-Policy","X-Frame-Options"}
  out:=fmt.Sprintf("HTTP %s\n",r.Status);for _,k:=range keys{v:=r.Header.Get(k);if v==""{v="(missing)"};out+=k+": "+v+"\n"};return output(out)
 case "whoiz":
  if command!="lookup"{break}
  domain,e:=required(a,"domain");if e!=nil{return sentinelplugin.Result{},e}
  if len(domain)>253||strings.ContainsAny(domain," \t\r\n/\\"){return sentinelplugin.Result{},errors.New("invalid domain")}
  b,e:=exec.CommandContext(ctx,"whois",domain).CombinedOutput();if e!=nil&&len(b)==0{return sentinelplugin.Result{},e};return output(string(b))
 case "jwtpeek":
  if command!="decode"{break}
  token,e:=required(a,"token");if e!=nil{return sentinelplugin.Result{},e};parts:=strings.Split(token,".");if len(parts)!=3{return sentinelplugin.Result{},errors.New("JWT requires 3 segments")}
  var out strings.Builder;for i,p:=range parts[:2]{b,e:=base64.RawURLEncoding.DecodeString(p);if e!=nil||len(b)>4096||!json.Valid(b){return sentinelplugin.Result{},errors.New("invalid JWT JSON")}
    var v any;_ = json.Unmarshal(b,&v);pretty,_:=json.MarshalIndent(v,"","  ");if i==0{out.WriteString("HEADER\n")}else{out.WriteString("\nPAYLOAD\n")};out.Write(pretty)}
  out.WriteString("\nSignature NOT verified.");return output(out.String())
 case "gitty":
  if command!="status"{break}
  root:=os.Getenv("SENTINEL_GITTY_ROOT");if !filepath.IsAbs(root){return sentinelplugin.Result{},errors.New("set absolute SENTINEL_GITTY_ROOT")}
  b,e:=exec.CommandContext(ctx,"git","-C",root,"status","--short","--branch").CombinedOutput();if e!=nil{return sentinelplugin.Result{},e};return output(string(b))
 case "servectl":
  if command!="list"{break}
  b,e:=exec.CommandContext(ctx,"systemctl","list-units","--type=service","--no-pager","--no-legend","--plain").CombinedOutput();if e!=nil{return sentinelplugin.Result{},e};return output(string(b))
 case "termfiles":
  if command!="list"{break}
  root:=os.Getenv("SENTINEL_TERMFILES_ROOT");if !filepath.IsAbs(root){return sentinelplugin.Result{},errors.New("set absolute SENTINEL_TERMFILES_ROOT")}
  entries,e:=os.ReadDir(root);if e!=nil{return sentinelplugin.Result{},e};var names []string
  for _,f:=range entries{kind:="file";if f.IsDir(){kind="dir"};names=append(names,kind+" "+f.Name());if len(names)>=60{break}};sort.Strings(names);return output(strings.Join(names,"\n"))
 case "authguard":
  if command!="summary"{break}
  var b []byte;for _,p:=range []string{"/var/log/auth.log","/var/log/secure"}{f,e:=os.Open(p);if e!=nil{continue};b,_=io.ReadAll(io.LimitReader(f,4*1024*1024));_ = f.Close();break}
  if len(b)==0{return sentinelplugin.Result{},errors.New("auth log unavailable")}
  s:=strings.ToLower(string(b));return output(fmt.Sprintf("Sampled host auth log (max 4 MiB)\nFailed password: %d\nAccepted publickey: %d\nInvalid user: %d",strings.Count(s,"failed password"),strings.Count(s,"accepted publickey"),strings.Count(s,"invalid user")))
 case "jsonfix":
  if command!="format"{break}
  data,e:=required(a,"data");if e!=nil{return sentinelplugin.Result{},e}
  var v any;if e:=json.Unmarshal([]byte(data),&v);e!=nil{return sentinelplugin.Result{},e}
  b,_:=json.MarshalIndent(v,"","  ");return output(string(b))
 case "hashkit":
  if command!="digest"{break}
  data,e:=required(a,"data");if e!=nil{return sentinelplugin.Result{},e};sum:=sha256.Sum256([]byte(data));return output("SHA256 "+hex.EncodeToString(sum[:]))
 case "uptimez":
  if command!="check"{break}
  u,e:=required(a,"url");if e!=nil{return sentinelplugin.Result{},e};start:=time.Now()
  r,e:=get(ctx,u);if e!=nil{return sentinelplugin.Result{},e};defer r.Body.Close();return output(fmt.Sprintf("HTTP %d in %s\n%s",r.StatusCode,time.Since(start),u))
 }
 return sentinelplugin.Result{},errors.New("unsupported command")
}
