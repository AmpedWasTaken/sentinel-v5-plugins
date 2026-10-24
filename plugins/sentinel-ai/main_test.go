package main

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestRestrictToLiteralLoopback(t *testing.T){
 for _,raw:=range []string{
  "http://example.org/v1/chat/completions",
  "https://api.openai.com/v1/chat/completions",
  "http://localhost:11434/v1/chat/completions",
  "http://127.0.0.1:11434/other",
  "http://127.0.0.1:11434/v1/chat/completions?key=abc",
  "http://127.0.0.1:0/v1/chat/completions",
 } {
  if _,err:=checkEndpoint(raw);err==nil{t.Errorf("unsafe endpoint accepted: %s",raw)}
 }
 if _,err:=checkEndpoint(defaultEndpoint);err!=nil{t.Fatal(err)}
}
func TestLocalModelResponseAndPayload(t *testing.T){
 calls:=0
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls++
  if r.Method!="POST"||r.URL.Path!="/v1/chat/completions"{t.Errorf("bad request: %s %s",r.Method,r.URL.Path)}
  var req completionRequest
  if err:=json.NewDecoder(r.Body).Decode(&req);err!=nil{t.Error(err)}
  if req.Model!="small:latest"||len(req.Messages)!=2||req.Messages[1].Content!="What is this log?"{
   t.Errorf("unwanted outbound request: %+v",req)
  }
  w.Header().Set("Content-Type","application/json")
  _,_=w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Review the logs\u001b[31m safely."}}]}`))
 }))
 defer srv.Close()
 output,err:=askLocal(context.Background(),srv.Client(),srv.URL+"/v1/chat/completions","small:latest","explain","What is this log?")
 if err!=nil{t.Fatal(err)}
 if calls!=1||strings.Contains(output,"\x1b")||!strings.Contains(output,"Review the logs"){t.Fatalf("invalid completion %q",output)}
}
func TestRefuseOversizedInputWithoutNetwork(t *testing.T){
 client:=&http.Client{Timeout:time.Second}
 if _,err:=askLocal(context.Background(),client,defaultEndpoint,"small","ask",strings.Repeat("A",2001));err==nil{t.Fatal("oversized input accepted")}
}
