package main

import (
 "net"
 "strings"
 "testing"
)

func TestSafeReadOnlyHealthURL(t *testing.T){
 good:=[]string{"https://example.com/health","https://status.example.org/status"}
 for _,raw:=range good{
  if err:=validateHealthURL(raw);err!=nil{t.Errorf("rejected %q: %v",raw,err)}
 }
 bad:=[]string{
  "http://example.com/health",
  "https://example.com:8443/health",
  "https://127.0.0.1/health",
  "https://localhost/health",
  "https://server.local/status",
  "https://example.com/attack?target=1.2.3.4",
  "https://example.com/health?target=example.net",
  "https://user:password@example.com/health",
  "https://example.com/health#fragment",
  "https://example.com/%68ealth",
  "https://example.com/anything",
  "https://example.com/health?method=tcp",
 }
 for _,raw:=range bad{
  if err:=validateHealthURL(raw);err==nil{t.Errorf("accepted unsafe URL %q",raw)}
 }
}

func TestHealthAPIValidation(t *testing.T){
 valid:=HealthAPI{
  Enabled:true,MinimumSuccess:1,
  Endpoints:[]HealthEndpoint{{Name:"primary",URL:"https://example.com/health"}},
 }
 if err:=valid.Validate();err!=nil{t.Fatal(err)}
 invalid:=valid
 invalid.MinimumSuccess=2
 if err:=invalid.Validate();err==nil{t.Fatal("minimum_success larger than endpoint count allowed")}
 invalid=valid
 invalid.Endpoints=[]HealthEndpoint{
  {Name:"primary",URL:"https://example.com/health"},
  {Name:"primary",URL:"https://example.org/health"},
 }
 if err:=invalid.Validate();err==nil{t.Fatal("duplicate endpoint name allowed")}
}

func TestHealthDisabledDoesNotCallNetwork(t *testing.T){
 api:=HealthAPI{Enabled:false}
 summary,err:=checkHealthAPI(api,"")
 if err!=nil||!strings.Contains(summary,"disabled"){
  t.Fatalf("disabled check must report no outbound activity: %s %v",summary,err)
 }
}

func TestCheckCommandNoTargetOrMethodArgs(t *testing.T){
 cfg:=configForTest(t)
 for _,args:=range []map[string]string{
  {"target":"example.com"},
  {"method":"tcp"},
  {"url":"https://example.com/health"},
  {"duration":"30"},
 } {
  _,err:=handle(Request{Version:1,Command:"check",Args:args},cfg)
  if err==nil{t.Errorf("check allowed unexpected arguments: %#v",args)}
 }
 response,err:=handle(Request{Version:1,Command:"check"},cfg)
 if err!=nil{t.Fatal(err)}
 if response.View!="relay-api-disabled"||!strings.Contains(response.Values["summary"],"disabled"){
  t.Fatalf("unexpected disabled health status: %+v",response)
 }
}

func TestBlockedPrivateAndReservedIPs(t *testing.T){
 for _,addr:=range []string{"127.0.0.1","10.0.0.1","169.254.10.4","100.64.0.1",
  "172.16.0.1","192.168.1.10","192.0.2.1","198.18.0.1","203.0.113.5","::1","fd00::1","2001:db8::1"}{
  if allowedPublicIP(net.ParseIP(addr)){t.Errorf("nonpublic IP accepted: %s",addr)}
 }
 for _,addr:=range []string{"1.1.1.1","8.8.8.8"}{
  if !allowedPublicIP(net.ParseIP(addr)){t.Errorf("public IP refused: %s",addr)}
 }
}
