package main

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "net/url"
 "os"
 "regexp"
 "strings"
 "time"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

const defaultEndpoint = "http://127.0.0.1:11434/v1/chat/completions"
const maxQuestion = 2000
const maxOutput = 2600
var safeModel = regexp.MustCompile(`^[a-zA-Z0-9_.:/-]{1,80}$`)

type aiMessage struct { Role string `json:"role"`; Content string `json:"content"` }
type completionRequest struct {
 Model string `json:"model"`
 Messages []aiMessage `json:"messages"`
 Stream bool `json:"stream"`
 Temperature float64 `json:"temperature"`
 MaxTokens int `json:"max_tokens"`
}
type completionResponse struct {
 Choices []struct { Message aiMessage `json:"message"` } `json:"choices"`
}

func checkEndpoint(raw string)(string,error) {
 u,err:=url.Parse(raw)
 if err!=nil || u==nil{return "",errors.New("invalid local AI endpoint")}
 if u.Scheme!="http" || u.User!=nil || u.RawQuery!="" || u.Fragment!="" || u.Path!="/v1/chat/completions"{
  return "",errors.New("AI endpoint must be a loopback HTTP /v1/chat/completions URL")
 }
 ip:=net.ParseIP(u.Hostname())
 if ip==nil || !ip.IsLoopback(){return "",errors.New("AI endpoint must use literal 127.0.0.1 or ::1, not a hostname")}
 port:=u.Port()
 if port==""{return "",errors.New("explicit loopback port required")}
 // net.SplitHostPort checks numeric, valid port range via LookupPort.
 number,err:=net.LookupPort("tcp",port)
 if err!=nil||number<1||number>65535{return "",errors.New("invalid AI loopback port")}
 return u.String(),nil
}
func cleanOutput(raw string)string {
 var out strings.Builder
 for _,r:=range raw {
  if r=='\n'||r=='\t'||r>=32&&r!=127&&r!=0x1b&&r!=0x9b {out.WriteRune(r)}
  if out.Len()>=maxOutput {break}
 }
 return strings.TrimSpace(out.String())
}
func askLocal(ctx context.Context,client *http.Client,endpoint,model,subject,question string)(string,error){
 if _,err:=checkEndpoint(endpoint);err!=nil{return "",err}
 if !safeModel.MatchString(model){return "",errors.New("invalid local AI model name")}
 question=strings.TrimSpace(question)
 if len(question)<3||len(question)>maxQuestion{return "",errors.New("question/diagnostic must be 3..2000 bytes")}
 policy:="You are Sentinel's defensive operations assistant. Explain the supplied information and offer non-destructive troubleshooting guidance. Do not propose exploitation, DDoS attacks, credential extraction, persistence or automatic privileged changes. You cannot use tools or execute commands. Do not claim to have inspected the system."
 if subject=="explain"{policy+=" Explain the pasted diagnostic, possible causes and safe checks. State uncertainty."}
 body,err:=json.Marshal(completionRequest{
  Model:model,Messages:[]aiMessage{{Role:"system",Content:policy},{Role:"user",Content:question}},
  Stream:false,Temperature:0.2,MaxTokens:300,
 })
 if err!=nil{return "",err}
 request,err:=http.NewRequestWithContext(ctx,http.MethodPost,endpoint,bytes.NewReader(body))
 if err!=nil{return "",err}
 request.Header.Set("Content-Type","application/json")
 response,err:=client.Do(request)
 if err!=nil{return "",fmt.Errorf("local model unavailable: %w",err)}
 defer response.Body.Close()
 if response.StatusCode!=http.StatusOK{return "",fmt.Errorf("local model HTTP status %d (response hidden)",response.StatusCode)}
 limited,err:=io.ReadAll(io.LimitReader(response.Body,64*1024+1))
 if err!=nil{return "",errors.New("failed to read local AI response")}
 if len(limited)>64*1024{return "",errors.New("local AI response exceeded size limit")}
 var decoded completionResponse
 if err:=json.Unmarshal(limited,&decoded);err!=nil||len(decoded.Choices)==0{return "",errors.New("local AI response has no completion")}
 result:=cleanOutput(decoded.Choices[0].Message.Content)
 if result==""{return "",errors.New("local AI returned an empty completion")}
 return result,nil
}
func ask(req sentinelplugin.Request)(sentinelplugin.Result,error){
 if len(req.Args)!=1{return sentinelplugin.Result{},errors.New("usage: sentinel-ai ask question=<text>")}
 question:=req.Args["question"]
 if question==""{return sentinelplugin.Result{},errors.New("question argument is required")}
 return invokeAI("ask",question)
}
func explain(req sentinelplugin.Request)(sentinelplugin.Result,error){
 if len(req.Args)!=1{return sentinelplugin.Result{},errors.New("usage: sentinel-ai explain diagnostic=<text>")}
 diagnostic:=req.Args["diagnostic"]
 if diagnostic==""{return sentinelplugin.Result{},errors.New("diagnostic argument is required")}
 return invokeAI("explain",diagnostic)
}
func invokeAI(subject,question string)(sentinelplugin.Result,error){
 endpoint:=strings.TrimSpace(os.Getenv("SENTINEL_AI_ENDPOINT"))
 if endpoint==""{endpoint=defaultEndpoint}
 model:=strings.TrimSpace(os.Getenv("SENTINEL_AI_MODEL"))
 if model==""{model="qwen2.5:7b"}
 transport:=&http.Transport{Proxy:nil,DisableKeepAlives:true}
 defer transport.CloseIdleConnections()
 client:=&http.Client{Timeout:6500*time.Millisecond,Transport:transport,
  CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}}
 ctx,cancel:=context.WithTimeout(context.Background(),6500*time.Millisecond)
 defer cancel()
 output,err:=askLocal(ctx,client,endpoint,model,subject,question)
 if err!=nil{return sentinelplugin.Result{},err}
 return sentinelplugin.Result{Text:"SENTINEL AI / LOCAL MODEL (ADVISORY ONLY)\n"+output+"\n\nNo tools, command execution, host changes or automatic context access."},nil
}
func main(){
 app:=sentinelplugin.New()
 if err:=app.Command("ask",ask);err!=nil{log.Fatal(err)}
 if err:=app.Command("explain",explain);err!=nil{log.Fatal(err)}
 if err:=app.Serve();err!=nil{log.Fatal(err)}
}
