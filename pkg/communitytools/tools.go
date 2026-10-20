// Package communitytools provides bounded server-side operations for independently enabled Sentinel plugins.
package communitytools

import (
 "bufio"
 "context"
 "crypto/sha256"
 "crypto/tls"
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
 "runtime"
 "sort"
 "strconv"
 "strings"
 "time"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

func result(s string)(sentinelplugin.Result,error){if len(s)>6000{s=s[:6000]+"\n[truncated]"};return sentinelplugin.Result{Text:s},nil}
func arg(a map[string]string,k string)string{return strings.TrimSpace(a[k])}
func duration(a map[string]string)time.Duration{n,_:=strconv.Atoi(arg(a,"timeout"));if n<1{n=3};if n>7{n=7};return time.Duration(n)*time.Second}
func port(a map[string]string)(string,error){p,err:=strconv.Atoi(arg(a,"port"));if err!=nil||p<1||p>65535{return "",errors.New("port must be 1..65535")};return strconv.Itoa(p),nil}
func host(a map[string]string)(string,error){h:=arg(a,"host");if len(h)==0||len(h)>253||strings.ContainsAny(h," \t\r\n/\\"){return "",errors.New("invalid host")};return h,nil}
func safeLabel(s string)bool {return s!=""&&len(s)<=128&&!strings.ContainsAny(s,"\r\n\t\x00")}
func external(ctx context.Context,program string,args ...string)(string,error){b,err:=exec.CommandContext(ctx,program,args...).CombinedOutput();if len(b)>6000{b=b[:6000]};return string(b),err}
func httpClient(t time.Duration)*http.Client{return &http.Client{Timeout:t,CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse},Transport:&http.Transport{Proxy:nil,TLSHandshakeTimeout:t,DisableKeepAlives:true}}}
func validURL(s string)(*url.URL,error){u,e:=url.Parse(s);if e!=nil||u.Hostname()==""||(u.Scheme!="http"&&u.Scheme!="https")||u.User!=nil{return nil,errors.New("only HTTP(S) URLs with a hostname and no embedded credentials are supported")};return u,nil}
func readLimited(r io.Reader,n int64)string{b,_:=io.ReadAll(io.LimitReader(r,n));return string(b)}
func Run(id,command string,a map[string]string)(sentinelplugin.Result,error){
 ctx,cancel:=context.WithTimeout(context.Background(),duration(a)*time.Second);defer cancel()
 switch id {
 case "netcatty":
  if command!="connect"&&command!="scan"&&command!="banner"&&command!="udp" {return sentinelplugin.Result{},errors.New("unknown netcatty command")}
  h,e:=host(a);if e!=nil{return sentinelplugin.Result{},e}
  p,e:=port(a);if e!=nil{return sentinelplugin.Result{},e}
  proto:="tcp";if command=="udp"{proto="udp"}
  c,e:=net.DialTimeout(proto,net.JoinHostPort(h,p),duration(a));if e!=nil{return sentinelplugin.Result{},e};defer c.Close()
  if command=="scan"{return result("open tcp "+net.JoinHostPort(h,p))}
  _=c.SetDeadline(time.Now().Add(duration(a)))
  data:=a["data"];if len(data)>1024{return sentinelplugin.Result{},errors.New("data too large")}
  if data!=""{_,e=c.Write([]byte(data));if e!=nil{return sentinelplugin.Result{},e}}
  b:=make([]byte,2048);n,e:=c.Read(b);if e!=nil {if ne,ok:=e.(net.Error);ok&&ne.Timeout(){return result("connected; no response before timeout")};if !errors.Is(e,io.EOF){return sentinelplugin.Result{},e}}
  return result(fmt.Sprintf("%s %s -> %s\n%s",proto,c.LocalAddr(),c.RemoteAddr(),strconv.QuoteToASCII(string(b[:n]))))
 case "pktpeek":
  if command!="capture"{return sentinelplugin.Result{},errors.New("unknown command")}
  if runtime.GOOS!="linux"{return sentinelplugin.Result{},errors.New("capture requires Linux and tcpdump")}
  iface:=arg(a,"interface");if iface==""{iface="any"};if !safeLabel(iface)||strings.ContainsAny(iface,"/\\"){return sentinelplugin.Result{},errors.New("invalid interface")}
  // Capture is bounded in duration/packet count. Never delegate a shell or arbitrary expression.
  captureCtx,stop:=context.WithTimeout(context.Background(),duration(a));defer stop()
  text,e:=external(captureCtx,"tcpdump","-n","-l","-i",iface,"-c","10","-q")
  if e!=nil&&text==""{return sentinelplugin.Result{},fmt.Errorf("tcpdump unavailable or requires capture privileges: %w",e)}
  return result(text)
 case "portfox":
  if command!="check"{return sentinelplugin.Result{},errors.New("unknown command")}
  h,e:=host(a);if e!=nil{return sentinelplugin.Result{},e}
  p,e:=port(a);if e!=nil{return sentinelplugin.Result{},e}
  c,e:=net.DialTimeout("tcp",net.JoinHostPort(h,p),duration(a));if e!=nil{return result("closed/filtered: "+e.Error())};_ = c.Close();return result("open: "+net.JoinHostPort(h,p))
 case "sysmon":
  if command!="stats"{return sentinelplugin.Result{},errors.New("unknown command")}
  var m runtime.MemStats;runtime.ReadMemStats(&m)
  out:=fmt.Sprintf("OS: %s/%s\nLogical CPUs: %d\nPlugin process memory: %d MiB\n",runtime.GOOS,runtime.GOARCH,runtime.NumCPU(),m.Sys/1024/1024)
  if runtime.GOOS=="linux"{for _,f:=range []string{"/proc/meminfo","/proc/loadavg"}{b,e:=os.ReadFile(f);if e==nil{lines:=strings.Split(string(b),"\n");if len(lines)>6{lines=lines[:6]};out+=f+":\n"+strings.Join(lines,"\n")+"\n"}}}
  return result(out)
 case "reqr":
  if command!="request"{return sentinelplugin.Result{},errors.New("unknown command")}
  u,e:=validURL(arg(a,"url"));if e!=nil{return sentinelplugin.Result{},e}
  method:=strings.ToUpper(arg(a,"method"));if method==""{method="GET"}
  if method!="GET"&&method!="HEAD"&&method!="POST"&&method!="PUT"&&method!="PATCH"&&method!="DELETE"{return sentinelplugin.Result{},errors.New("unsupported HTTP method")}
  body:=a["body"];if len(body)>2048{return sentinelplugin.Result{},errors.New("body exceeds 2048 bytes")}
  req,e:=http.NewRequestWithContext(ctx,method,u.String(),strings.NewReader(body));if e!=nil{return sentinelplugin.Result{},e}
  if body!=""{req.Header.Set("Content-Type","application/json")}
  resp,e:=httpClient(duration(a)).Do(req);if e!=nil{return sentinelplugin.Result{},e};defer resp.Body.Close()
  out:=fmt.Sprintf("%s %s\n",resp.Proto,resp.Status);for k,v:=range resp.Header{if len(v)>0{out+=k+": "+strings.Join(v,", ")+"\n"}}
  return result(out+"\n"+readLimited(resp.Body,3000))
 case "dnsdig":
  if command!="lookup"{return sentinelplugin.Result{},errors.New("unknown command")}
  h,e:=host(a);if e!=nil{return sentinelplugin.Result{},e}
  kind:=strings.ToUpper(arg(a,"type"));if kind==""{kind="A"}
  r:=net.DefaultResolver
  var lines []string
  switch kind {
  case "A","AAAA":
   ips,e:=r.LookupIPAddr(ctx,h);if e!=nil{return sentinelplugin.Result{},e}
   for _,v:=range ips {if (kind=="A")==(v.IP.To4()!=nil){lines=append(lines,v.IP.String())}}
  case "MX":
   mx,e:=r.LookupMX(ctx,h);if e!=nil{return sentinelplugin.Result{},e};for _,v:=range mx{lines=append(lines,fmt.Sprintf("%d %s",v.Pref,v.Host))}
  case "TXT":
   lines,e=r.LookupTXT(ctx,h);if e!=nil{return sentinelplugin.Result{},e}
  case "NS":
   ns,e:=r.LookupNS(ctx,h);if e!=nil{return sentinelplugin.Result{},e};for _,v:=range ns{lines=append(lines,v.Host)}
  case "CNAME":
   v,e:=r.LookupCNAME(ctx,h);if e!=nil{return sentinelplugin.Result{},e};lines=append(lines,v)
  default:return sentinelplugin.Result{},errors.New("type: A, AAAA, MX, TXT, NS, CNAME")
  }
  if len(lines)>30{lines=lines[:30]};return result(strings.Join(lines,"\n"))
 case "certcheck":
  if command!="inspect"{return sentinelplugin.Result{},errors.New("unknown command")}
  h,e:=host(a);if e!=nil{return sentinelplugin.Result{},e}
  p:=arg(a,"port");if p==""{p="443"}else{p,e=port(a);if e!=nil{return sentinelplugin.Result{},e}}
  dialer:=&net.Dialer{Timeout:duration(a)}
  c,e:=tls.DialWithDialer(dialer,"tcp",net.JoinHostPort(h,p),&tls.Config{ServerName:h,MinVersion:tls.VersionTLS12});if e!=nil{return sentinelplugin.Result{},e};defer c.Close()
  st:=c.ConnectionState();if len(st.PeerCertificates)==0{return sentinelplugin.Result{},errors.New("no certificates")}
  cert:=st.PeerCertificates[0]
  return result(fmt.Sprintf("Subject: %s\nIssuer: %s\nExpires: %s\nDays remaining: %.1f\nDNS names: %s\nTLS version: 0x%x\n",cert.Subject,cert.Issuer,cert.NotAfter.Format(time.RFC3339),time.Until(cert.NotAfter).Hours()/24,strings.Join(cert.DNSNames,", "),st.Version))
 case "logtail":
  if command!="read"{return sentinelplugin.Result{},errors.New("unknown command")}
  kind:=arg(a,"source")
  paths:=map[string][]string{"auth":{"/var/log/auth.log","/var/log/secure"},"syslog":{"/var/log/syslog","/var/log/messages"}}
  candidates,ok:=paths[kind];if !ok{return sentinelplugin.Result{},errors.New("source must be auth or syslog")}
  for _,p:=range candidates{f,e:=os.Open(p);if e!=nil{continue};defer f.Close()
   s:=bufio.NewScanner(io.LimitReader(f,8*1024*1024));var last []string
   for s.Scan(){last=append(last,s.Text());if len(last)>30{last=last[1:]}}
   return result(strings.Join(last,"\n"))
  };return sentinelplugin.Result{},errors.New("log unavailable or not readable")
 case "latency":
  if command!="probe"{return sentinelplugin.Result{},errors.New("unknown command")}
  h,e:=host(a);if e!=nil{return sentinelplugin.Result{},e};p:=arg(a,"port");if p==""{p="443"}else{p,e=port(a);if e!=nil{return sentinelplugin.Result{},e}}
  begin:=time.Now();c,e:=net.DialTimeout("tcp",net.JoinHostPort(h,p),duration(a));elapsed:=time.Since(begin)
  if e!=nil{return result(fmt.Sprintf("TCP probe %s:%s failed after %s: %v",h,p,elapsed,e))}
  _=c.Close();return result(fmt.Sprintf("TCP connection latency %s:%s: %s\n(Not ICMP ping or jitter)",h,p,elapsed))
 case "socktop":
  if command!="connections"{return sentinelplugin.Result{},errors.New("unknown command")}
  if runtime.GOOS!="linux"{return sentinelplugin.Result{},errors.New("Linux /proc/net required")}
  var out strings.Builder;for _,p:=range []string{"/proc/net/tcp","/proc/net/udp","/proc/net/tcp6","/proc/net/udp6"}{b,e:=os.ReadFile(p);if e==nil{lines:=strings.Split(string(b),"\n");if len(lines)>16{lines=lines[:16]};out.WriteString(p+"\n"+strings.Join(lines,"\n")+"\n")}}
  return result(out.String())
 case "filewatch":
  if command!="hash"{return sentinelplugin.Result{},errors.New("unknown command")}
  // Hash only a bounded file within the plugin's curated server log area.
  name:=arg(a,"file");if !safeLabel(name)||strings.ContainsAny(name,"/\\."){return sentinelplugin.Result{},errors.New("file must be a simple filename without dots or separators")}
  root:="/var/log";f,e:=os.Open(filepath.Join(root,name));if e!=nil{return sentinelplugin.Result{},e};defer f.Close()
  info,e:=f.Stat();if e!=nil{return sentinelplugin.Result{},e};if !info.Mode().IsRegular()||info.Size()>8*1024*1024{return sentinelplugin.Result{},errors.New("only regular files <=8 MiB")}
  digest:=sha256.New();_,e=io.Copy(digest,io.LimitReader(f,8*1024*1024+1));if e!=nil{return sentinelplugin.Result{},e}
  return result(fmt.Sprintf("%s sha256 %s",name,hex.EncodeToString(digest.Sum(nil))))
 case "docktop":
  if command!="ps"{return sentinelplugin.Result{},errors.New("unknown command")}
  out,e:=external(ctx,"docker","ps","--format","table {{.Names}}\t{{.Status}}\t{{.Image}}");if e!=nil{return sentinelplugin.Result{},fmt.Errorf("Docker read failed: %w",e)};return result(out)
 case "sshwatch":
  if command!="sessions"{return sentinelplugin.Result{},errors.New("unknown command")}
  out,e:=external(ctx,"who");if e!=nil{return sentinelplugin.Result{},e};return result(out)
 case "hookbin":
  if command!="inspect"{return sentinelplugin.Result{},errors.New("unknown command")}
  // Inspect a caller-supplied webhook payload; does not bind a public port.
  data:=a["data"];if len(data)>3000{return sentinelplugin.Result{},errors.New("payload too large")}
  if !json.Valid([]byte(data)){return sentinelplugin.Result{},errors.New("data must contain valid JSON")}
  var parsed any;if e:=json.Unmarshal([]byte(data),&parsed);e!=nil{return sentinelplugin.Result{},e}
  pretty,_:=json.MarshalIndent(parsed,"","  ");return result(string(pretty))
 case "ioclookup":
  if command!="resolve"{return sentinelplugin.Result{},errors.New("unknown command")}
  h,e:=host(a);if e!=nil{return sentinelplugin.Result{},e}
  ips,e:=net.DefaultResolver.LookupIPAddr(ctx,h);if e!=nil{return sentinelplugin.Result{},e}
  values:=make([]string,0,len(ips));for _,v:=range ips{values=append(values,v.IP.String())};sort.Strings(values)
  return result("DNS resolution only (not a reputation verdict):\n"+strings.Join(values,"\n"))
 default:return sentinelplugin.Result{},errors.New("unknown plugin")
 }
}
