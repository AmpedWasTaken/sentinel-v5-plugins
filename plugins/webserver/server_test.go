package main

import (
 "net/http"
 "net/http/httptest"
 "os"
 "strings"
 "testing"
)

func testConfig()Config{
 return Config{
  Version:1,Listen:"127.0.0.1:8088",
  Rate:RateConfig{RequestsPerMinute:120,Burst:30},
  Sites:[]SiteConfig{{Host:"*",Root:"./public"}},
  Routes:[]RouteConfig{{Path:"/api/ping",Kind:"json",Status:200,Body:`{"pong":true}`}},
 }
}
func testService(t *testing.T)*webService{
 t.Helper()
 cfg,err:=validateConfig(testConfig())
 if err!=nil{t.Fatal(err)}
 s:=newWebService()
 s.state.Store(&routeState{config:cfg,limiter:newLimiter(cfg.raw.Rate)})
 return s
}
func hit(s *webService,method,p string)*httptest.ResponseRecorder{
 req:=httptest.NewRequest(method,"http://localhost:8088"+p,nil)
 req.RemoteAddr="127.0.0.1:45454"
 w:=httptest.NewRecorder()
 s.serveHTTP(w,req)
 return w
}
func TestSafeDefaultsAndValidation(t *testing.T){
 if _,err:=loadConfig();err!=nil{t.Fatalf("included YAML is invalid: %v",err)}
 c:=testConfig()
 c.Listen="0.0.0.0:8088"
 if _,err:=validateConfig(c);err==nil{t.Fatal("accepted public HTTP listener")}
 c.Listen="127.0.0.1:8088";c.AllowPublic=true
 if _,err:=validateConfig(c);err==nil{t.Fatal("accepted public flag on local listener")}
 c.AllowPublic=false;c.Routes[0].Body="{not-json}"
 if _,err:=validateConfig(c);err==nil{t.Fatal("accepted invalid JSON")}
 c=testConfig();c.Sites[0].Root="../"
 if _,err:=validateConfig(c);err==nil{t.Fatal("allowed site root to escape plugin directory")}
 c=testConfig();c.Routes[0].Path="/_sentinel/override"
 if _,err:=validateConfig(c);err==nil{t.Fatal("accepted reserved endpoint")}
}
func TestHTTPRoutesHealthAndStatic(t *testing.T){
 s:=testService(t)
 if got:=hit(s,"GET","/_sentinel/health");got.Code!=200 || !strings.Contains(got.Body.String(),`"ok"`){t.Fatalf("health failed: %d %s",got.Code,got.Body.String())}
 if got:=hit(s,"GET","/api/ping");got.Code!=200 || !strings.Contains(got.Body.String(),`"pong"`){t.Fatalf("JSON route failed: %d",got.Code)}
 if got:=hit(s,"HEAD","/api/ping");got.Code!=200 || got.Body.Len()!=0 {t.Fatalf("HEAD body/status invalid: %d %q",got.Code,got.Body.String())}
 if got:=hit(s,"POST","/api/ping");got.Code!=http.StatusMethodNotAllowed{t.Fatalf("POST should be denied: %d",got.Code)}
 if got:=hit(s,"GET","/");got.Code!=200 || !strings.Contains(got.Body.String(),"Sentinel V5"){t.Fatalf("static site failed: %d",got.Code)}
 if got:=hit(s,"GET","/.env");got.Code!=404{t.Fatalf("dotfile disclosed: %d",got.Code)}
 if got:=hit(s,"GET","/../../config.yml");got.Code!=404{t.Fatalf("traversal passed: %d",got.Code)}
 if got:=hit(s,"GET","/missing-file.txt");got.Code!=404{t.Fatalf("missing file returned: %d",got.Code)}
 if got:=hit(s,"GET","/public");got.Code!=404{t.Fatalf("directory listing returned: %d",got.Code)}
}
func TestVirtualHostMatching(t *testing.T){
 cfg:=testConfig()
 cfg.Sites[0].Host="example.test"
 live,err:=validateConfig(cfg);if err!=nil{t.Fatal(err)}
 s:=newWebService()
 s.state.Store(&routeState{config:live,limiter:newLimiter(cfg.Rate)})
 if got:=hit(s,"GET","/");got.Code!=404{t.Fatalf("unmatched hostname served: %d",got.Code)}
 req:=httptest.NewRequest("GET","http://example.test:8088/",nil)
 req.RemoteAddr="127.0.0.1:1234"
 w:=httptest.NewRecorder();s.serveHTTP(w,req)
 if w.Code!=200{t.Fatalf("matching hostname rejected: %d",w.Code)}
}
func TestRateLimitAndRemoteIPTrust(t *testing.T){
 c:=testConfig();c.Rate=RateConfig{RequestsPerMinute:1,Burst:1}
 cfg,err:=validateConfig(c);if err!=nil{t.Fatal(err)}
 s:=newWebService()
 s.state.Store(&routeState{config:cfg,limiter:newLimiter(cfg.raw.Rate)})
 if got:=hit(s,"GET","/api/ping");got.Code!=200{t.Fatalf("first request failed: %d",got.Code)}
 if got:=hit(s,"GET","/api/ping");got.Code!=429{t.Fatalf("second request not throttled: %d",got.Code)}
 req:=httptest.NewRequest("GET","http://localhost:8088/api/ping",nil)
 req.RemoteAddr="127.0.0.1:8080"
 req.Header.Set("CF-Connecting-IP","203.0.113.99")
 req.Header.Set("X-Forwarded-For","198.51.100.88")
 if remoteIP(req)!="127.0.0.1"{t.Fatal("spoofed client IP header was trusted")}
 w:=httptest.NewRecorder();s.serveHTTP(w,req)
 if w.Code!=429{t.Fatalf("rate limit bypass via forwarded headers: %d",w.Code)}
 if v:=s.statusValues();v["requests"]!="3" || v["rate_limited"]!="2"{t.Fatalf("incorrect counters: %v",v)}
}
func TestNoDirectoryListingOrPrivateFile(t *testing.T){
 s:=testService(t)
 for _,path:=range []string{"/config.yml","/main.go","/server.go","/.git/config","/public/../config.yml"}{
  got:=hit(s,"GET",path)
  if got.Code!=404{t.Fatalf("private path %s returned status %d",path,got.Code)}
 }
 if _,err:=os.Stat("public/index.html");err!=nil{t.Fatalf("sample content missing: %v",err)}
}
