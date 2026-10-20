package main

import (
 "fmt"
 "strings"
)

// commandErrorView maps safe input/configuration failures to the matching
// terminal screen. Sentinel authorization failures remain managed by its host.
func commandErrorView(req Request, err error) (Result,bool) {
 if err==nil{return Result{},false}
 switch req.Command{
 case "preview","template","check":
 default:return Result{},false
 }
 name:="relay-preview-fault"
 detail:=strings.ToLower(err.Error())
 switch{
 case req.Command=="check":
  name="relay-backend-fault"
 case strings.Contains(detail,"disabled"):
  name="relay-disabled"
 case strings.Contains(detail,"target"):
  name="relay-invalid-target"
 case strings.Contains(detail,"port"):
  name="relay-invalid-port"
 case strings.Contains(detail,"duration"):
  name="relay-invalid-duration"
 case strings.Contains(detail,"scenario"),strings.Contains(detail,"method"):
  name="relay-unknown-method"
 case strings.Contains(detail,"group"),strings.Contains(detail,"limit"):
  name="relay-limit"
 case strings.Contains(detail,"argument"):
  name="relay-kv-unknown"
 }
 input:=""
 for _,key:=range []string{"scenario","method","target","port","duration","group"}{
  if value:=req.Args[key];value!="" {
   if len(value)>80{value=value[:80]}
   if input!=""{input+=" "}
   input+=fmt.Sprintf("%s=%s",key,value)
  }
 }
 values:=map[string]string{
  "detail":err.Error(),
  "input":input,
  "hint":"c2-relay help",
  "group":req.Args["group"],
  "method":req.Args["method"],
  "limit":"See relay.groups in config.yaml",
 }
 return viewResult(name,values),true
}
