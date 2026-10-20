package main

import (
 "crypto/rand"
 "encoding/hex"
 "errors"
 "fmt"
 "net"
 "regexp"
 "strconv"
 "strings"
 "time"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

// simulateAttack implements a realistic command/control UI contract without
// contacting a target, generating traffic, or dispatching an upstream attack.
func simulateAttack(req sentinelplugin.Request) (sentinelplugin.Result,error) {
 var empty sentinelplugin.Result
 for k:=range req.Args {
  switch k { case "target","method","port","time": default: return empty,fmt.Errorf("unknown argument %q",k) }
 }
 target:=strings.TrimSpace(req.Args["target"])
 if len(target)==0 || len(target)>253 || strings.ContainsAny(target,"/\\:@?# ") {
  return empty,errors.New("target must be a hostname or IP address")
 }
 if net.ParseIP(target)==nil {
  valid:=regexp.MustCompile("^[a-zA-Z0-9-]+([.][a-zA-Z0-9-]+)*$")
  if !valid.MatchString(target) { return empty,errors.New("invalid hostname") }
 }
 method:=strings.ToUpper(req.Args["method"])
 switch method { case "TCP","UDP","HTTP": default: return empty,errors.New("method must be TCP, UDP, or HTTP (simulation labels only)") }
 port,err:=strconv.Atoi(req.Args["port"])
 if err!=nil || port<1 || port>65535 {return empty,errors.New("port must be between 1 and 65535")}
 seconds,err:=strconv.Atoi(req.Args["time"])
 if err!=nil || seconds<1 || seconds>3600 {return empty,errors.New("time must be 1..3600 seconds")}
 b:=make([]byte,8)
 if _,err:=rand.Read(b);err!=nil{return empty,errors.New("cannot issue simulation ID")}
 id:="sim-"+hex.EncodeToString(b)
 return sentinelplugin.Result{View:"attack-sim",Values:map[string]string{
  "request_id":id,
  "target":target,
  "method":method,
  "port":strconv.Itoa(port),
  "duration":strconv.Itoa(seconds)+"s",
  "status":"SIMULATED",
  "created_at":time.Now().UTC().Format(time.RFC3339),
  "detail":"Validated locally. No API attack request, target connection, or network traffic was sent.",
 }},nil
}
