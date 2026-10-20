package main

import (
 "context"
 "crypto/tls"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "path"
 "path/filepath"
 "sort"
 "strconv"
 "strings"
 "sync"
 "sync/atomic"
 "time"
)

type routeState struct {
 config *liveConfig
 limiter *ipLimiter
}
type requestRecord struct {
 At time.Time
 Method,Path,Remote string
 Status int
 Latency time.Duration
}
type trafficStats struct {
 mu sync.Mutex
 total, bytes, denied uint64
 status2xx, status4xx, status5xx uint64
 recent []requestRecord
}
func(s *trafficStats)record(r requestRecord,n int){
 s.mu.Lock();defer s.mu.Unlock()
 s.total++
 if n>0{s.bytes+=uint64(n)}
 if r.Status==429{s.denied++}
 if r.Status>=200 && r.Status<300{s.status2xx++}
 if r.Status>=400 && r.Status<500{s.status4xx++}
 if r.Status>=500{s.status5xx++}
 if len(s.recent)==128{copy(s.recent,s.recent[1:]);s.recent=s.recent[:127]}
 s.recent=append(s.recent,r)
}
type bucket struct { tokens float64; last time.Time }
type ipLimiter struct {
 mu sync.Mutex
 clients map[string]bucket
 perSecond float64
 burst float64
}
func newLimiter(c RateConfig)*ipLimiter{
 return &ipLimiter{clients:make(map[string]bucket),perSecond:float64(c.RequestsPerMinute)/60,burst:float64(c.Burst)}
}
func(l *ipLimiter)allow(ip string)bool{
 now:=time.Now()
 l.mu.Lock();defer l.mu.Unlock()
 b,ok:=l.clients[ip]
 if !ok{
  if len(l.clients)>=4096{
   for key,v:=range l.clients{if now.Sub(v.last)>5*time.Minute{delete(l.clients,key)}}
   if len(l.clients)>=4096{return false}
  }
  b=bucket{tokens:l.burst,last:now}
 }
 b.tokens+=now.Sub(b.last).Seconds()*l.perSecond
 if b.tokens>l.burst{b.tokens=l.burst}
 b.last=now
 granted:=b.tokens>=1
 if granted{b.tokens--}
 l.clients[ip]=b
 return granted
}
type webService struct {
 mu sync.RWMutex
 server *http.Server
 listener net.Listener
 started time.Time
 lastError string
 state atomic.Pointer[routeState]
 stats trafficStats
}
func newWebService()*webService{return &webService{}}

func(s *webService)startFromDisk()error{
 cfg,err:=loadConfig()
 if err!=nil{return err}
 s.mu.Lock();defer s.mu.Unlock()
 if s.server!=nil{return errors.New("web server is already running")}
 listener,err:=net.Listen("tcp",cfg.raw.Listen)
 if err!=nil{return fmt.Errorf("cannot bind web listener: %w",err)}
 if cfg.raw.TLS.Enabled {
  cert,err:=tls.LoadX509KeyPair(cfg.raw.TLS.CertFile,cfg.raw.TLS.KeyFile)
  if err!=nil{_ = listener.Close();return fmt.Errorf("cannot load TLS certificate: %w",err)}
  listener=tls.NewListener(listener,&tls.Config{MinVersion:tls.VersionTLS12,Certificates:[]tls.Certificate{cert}})
 }
 srv:=&http.Server{
  Handler:http.HandlerFunc(s.serveHTTP),
  ReadHeaderTimeout:5*time.Second,
  ReadTimeout:12*time.Second,
  WriteTimeout:15*time.Second,
  IdleTimeout:40*time.Second,
  MaxHeaderBytes:16<<10,
 }
 s.state.Store(&routeState{config:cfg,limiter:newLimiter(cfg.raw.Rate)})
 s.server=srv
 s.listener=listener
 s.started=time.Now()
 s.lastError=""
 go func(){
  err:=srv.Serve(listener)
  s.mu.Lock()
  if s.server==srv {
   s.server=nil
   s.listener=nil
   if err!=nil && !errors.Is(err,http.ErrServerClosed){s.lastError=err.Error()}
  }
  s.mu.Unlock()
 }()
 return nil
}
func(s *webService)stop()error{
 s.mu.Lock()
 srv:=s.server
 if srv==nil{s.mu.Unlock();return errors.New("web server is not running")}
 s.server=nil
 s.listener=nil
 s.mu.Unlock()
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
 defer cancel()
 err:=srv.Shutdown(ctx)
 if err!=nil{_ = srv.Close();return fmt.Errorf("shutdown interrupted: %w",err)}
 return nil
}
func(s *webService)close(){if s.stop()!=nil{}}
func(s *webService)reload()error{
 next,err:=loadConfig();if err!=nil{return err}
 s.mu.Lock();defer s.mu.Unlock()
 if s.server==nil{return errors.New("web server is stopped; use start")}
 current:=s.state.Load()
 if current==nil{return errors.New("active configuration is unavailable")}
 a,b:=current.config.raw,next.raw
 if a.Listen!=b.Listen || a.TLS!=b.TLS || a.AllowPublic!=b.AllowPublic {
  return errors.New("listener or TLS settings changed; use stop then start")
 }
 s.state.Store(&routeState{config:next,limiter:newLimiter(next.raw.Rate)})
 return nil
}

type responseRecorder struct {http.ResponseWriter; status,bytes int}
func(w *responseRecorder)WriteHeader(code int){if w.status!=0{return};w.status=code;w.ResponseWriter.WriteHeader(code)}
func(w *responseRecorder)Write(p []byte)(int,error){if w.status==0{w.WriteHeader(http.StatusOK)};n,err:=w.ResponseWriter.Write(p);w.bytes+=n;return n,err}
func remoteIP(r *http.Request)string{
 host,_,err:=net.SplitHostPort(r.RemoteAddr)
 if err!=nil{return "unknown"}
 if ip:=net.ParseIP(host);ip!=nil{return ip.String()}
 return "unknown"
}
func cleanLogPath(p string)string{
 p=strings.Map(func(r rune)rune{if r<32 || r==127 || r==0x1b{return -1};return r},p)
 if len(p)>72 {p=p[:69]+"..."}
 return p
}
func securityHeaders(w http.ResponseWriter,tls bool){
 h:=w.Header()
 h.Set("X-Content-Type-Options","nosniff")
 h.Set("X-Frame-Options","DENY")
 h.Set("Referrer-Policy","no-referrer")
 h.Set("Permissions-Policy","camera=(), microphone=(), geolocation=()")
 h.Set("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
 if tls{h.Set("Strict-Transport-Security","max-age=31536000")}
}
func(s *webService)serveHTTP(w http.ResponseWriter,r *http.Request){
 started:=time.Now()
 recorder:=&responseRecorder{ResponseWriter:w}
 defer func(){
  if recorder.status==0{recorder.status=200}
  s.stats.record(requestRecord{At:started,Method:r.Method,Path:cleanLogPath(r.URL.Path),Remote:remoteIP(r),Status:recorder.status,Latency:time.Since(started)},recorder.bytes)
 }()
 state:=s.state.Load()
 if state==nil{http.Error(recorder,"service unavailable",http.StatusServiceUnavailable);return}
 cfg:=state.config
 securityHeaders(recorder,cfg.raw.TLS.Enabled)
 recorder.Header().Set("Cache-Control","no-store")
 if r.Method!=http.MethodGet && r.Method!=http.MethodHead{
  recorder.Header().Set("Allow","GET, HEAD")
  http.Error(recorder,"method not allowed",http.StatusMethodNotAllowed)
  return
 }
 if !state.limiter.allow(remoteIP(r)){
  recorder.Header().Set("Retry-After","60")
  writeJSON(recorder,http.StatusTooManyRequests,`{"error":"rate limit exceeded"}`)
  return
 }
 if r.URL.Path=="/_sentinel/health"{
  writeJSON(recorder,http.StatusOK,`{"status":"ok"}`)
  return
 }
 if route,ok:=cfg.routes[r.URL.Path];ok{
  contentType:="text/plain; charset=utf-8"
  if route.Kind=="json"{contentType="application/json; charset=utf-8"}
  recorder.Header().Set("Content-Type",contentType)
  recorder.WriteHeader(route.Status)
  if r.Method!=http.MethodHead{_,_=io.WriteString(recorder,route.Body)}
  return
 }
 host:=normalizeHost(r.Host)
 site,ok:=cfg.sites[host]
 if !ok{site,ok=cfg.sites["*"]}
 if !ok{http.NotFound(recorder,r);return}
 serveStatic(recorder,r,site)
}
func normalizeHost(raw string)string{
 if h,_,err:=net.SplitHostPort(raw);err==nil{raw=h}
 raw=strings.TrimPrefix(strings.TrimSuffix(raw,"]"),"[")
 return strings.TrimSuffix(strings.ToLower(raw),".")
}
func writeJSON(w http.ResponseWriter,status int,body string){
 w.Header().Set("Content-Type","application/json; charset=utf-8")
 w.WriteHeader(status)
 _,_=io.WriteString(w,body)
}
func safeFile(root,requested string)(*os.File,os.FileInfo,error){
 candidate:=filepath.Join(root,filepath.FromSlash(strings.TrimPrefix(requested,"/")))
 resolved,err:=filepath.EvalSymlinks(candidate)
 if err!=nil{return nil,nil,err}
 rel,err:=filepath.Rel(root,resolved)
 if err!=nil || rel==".." || strings.HasPrefix(rel,".."+string(filepath.Separator)){return nil,nil,errors.New("path escapes static root")}
 f,err:=os.Open(resolved);if err!=nil{return nil,nil,err}
 fi,err:=f.Stat()
 if err!=nil || !fi.Mode().IsRegular(){_ =f.Close();return nil,nil,errors.New("not a regular static file")}
 return f,fi,nil
}
func serveStatic(w http.ResponseWriter,r *http.Request,site SiteConfig){
 for _,part:=range strings.Split(r.URL.Path,"/"){
  if strings.HasPrefix(part,".") && part!=""{http.NotFound(w,r);return}
 }
 if strings.ContainsAny(r.URL.Path,"\\\x00"){http.NotFound(w,r);return}
 requested:=path.Clean("/"+r.URL.Path)
 if requested=="/"{requested="/index.html"}
 if requested!="/index.html" && strings.HasSuffix(r.URL.Path,"/"){requested=path.Join(requested,"index.html")}
 f,info,err:=safeFile(site.Root,requested)
 if err!=nil && site.SPAFallback && path.Ext(requested)=="" {
  f,info,err=safeFile(site.Root,"/index.html")
 }
 if err!=nil{http.NotFound(w,r);return}
 defer f.Close()
 w.Header().Set("Cache-Control","public, max-age=60")
 http.ServeContent(w,r,filepath.Base(requested),info.ModTime(),f)
}

func(s *webService)statusLine()string{
 v:=s.statusValues()
 return fmt.Sprintf("State: %s | Listener: %s | TLS: %s",v["state"],v["listen"],v["tls"])
}
func(s *webService)statusValues()map[string]string{
 s.mu.RLock()
 alive:=s.server!=nil
 started:=s.started
 lastErr:=s.lastError
 s.mu.RUnlock()
 v:=map[string]string{"state":"STOPPED","listen":"—","tls":"OFF","uptime":"0","sites":"0","routes":"0","last_error":"none"}
 if alive{v["state"]="RUNNING";v["uptime"]=strconv.FormatInt(int64(time.Since(started).Seconds()),10)}
 if state:=s.state.Load();state!=nil {
  c:=state.config
  v["listen"]=c.raw.Listen
  if c.raw.TLS.Enabled{v["tls"]="ON"}
  v["sites"]=strconv.Itoa(len(c.sites))
  v["routes"]=strconv.Itoa(len(c.routes))
 }
 if lastErr!="" {v["last_error"]=truncate(lastErr,100)}
 s.stats.mu.Lock()
 v["requests"]=strconv.FormatUint(s.stats.total,10)
 v["rate_limited"]=strconv.FormatUint(s.stats.denied,10)
 v["responses_2xx"]=strconv.FormatUint(s.stats.status2xx,10)
 v["responses_4xx"]=strconv.FormatUint(s.stats.status4xx,10)
 v["responses_5xx"]=strconv.FormatUint(s.stats.status5xx,10)
 v["bytes"]=strconv.FormatUint(s.stats.bytes,10)
 s.stats.mu.Unlock()
 return v
}
func truncate(s string,n int)string{if len(s)<=n{return s};return s[:n-3]+"..."}
func(s *webService)routeTable()string{
 state:=s.state.Load()
 if state==nil{return "WEB SERVER / ROUTES\nNo configuration loaded."}
 cfg:=state.config
 lines:=[]string{"WEB SERVER / ROUTES","METHOD  PATH / HOST                         TYPE / SOURCE","------  ----------------------------------  ---------------------------"}
 keys:=make([]string,0,len(cfg.routes))
 for key:=range cfg.routes{keys=append(keys,key)}
 sort.Strings(keys)
 lines=append(lines,"GET     /_sentinel/health                  JSON / built-in")
 for _,key:=range keys{r:=cfg.routes[key];lines=append(lines,fmt.Sprintf("%-6s  %-34s  %s / %d","GET",truncate(key,34),strings.ToUpper(r.Kind),r.Status))}
 hosts:=make([]string,0,len(cfg.sites))
 for h:=range cfg.sites{hosts=append(hosts,h)}
 sort.Strings(hosts)
 for _,host:=range hosts{
  site:=cfg.sites[host]
  label:="STATIC"
  if site.SPAFallback{label="STATIC + SPA"}
  lines=append(lines,fmt.Sprintf("%-6s  %-34s  %s","GET",truncate(host+"/*",34),label))
 }
 return strings.Join(lines,"\n")
}
func(s *webService)trafficTable(limit int)string{
 s.stats.mu.Lock()
 records:=append([]requestRecord(nil),s.stats.recent...)
 total,denied,bytes:=s.stats.total,s.stats.denied,s.stats.bytes
 s.stats.mu.Unlock()
 lines:=[]string{fmt.Sprintf("WEB SERVER / TRAFFIC    requests=%d  limited=%d  bytes=%d",total,denied,bytes),"TIME      CODE  LATENCY  REMOTE ADDRESS            METHOD  PATH","--------  ----  -------  ------------------------  ------  ----------------"}
 if len(records)==0{lines=append(lines,"No requests captured yet.");return strings.Join(lines,"\n")}
 for i:=len(records)-1;i>=0 && len(lines)<limit+3;i--{
  r:=records[i]
  lines=append(lines,fmt.Sprintf("%-8s  %-4d  %5dms  %-24s  %-6s  %s",r.At.Format("15:04:05"),r.Status,r.Latency.Milliseconds(),truncate(r.Remote,24),r.Method,truncate(r.Path,65)))
 }
 return strings.Join(lines,"\n")
}
// The plugin never trusts CF-Connecting-IP, True-Client-IP, X-Real-IP or
// X-Forwarded-For from arbitrary clients. A future trusted-proxy feature
// must explicitly authenticate proxy source addresses before using headers.
