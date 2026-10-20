package main

import (
 "errors"
 "fmt"
 "sort"
 "strings"
)

// Supported screens are explicitly listed; the views command does not accept
// arbitrary filenames or paths. It renders representative, non-operational
// terminal examples for maintainers to customize.
var galleryNames = map[string]bool{
 "relay-preview-sent":true,"relay-preview-fault":true,
 "relay-overview":true,"relay-methods":true,
 "relay-health-ok":true,"relay-health-degraded":true,
 "relay-api-disabled":true,"relay-config-fault":true,
 "relay-syntax":true,"relay-input-method":true,
 "relay-input-target":true,"relay-input-duration":true,"relay-input-port":true,
 "relay-invalid-target":true,"relay-unknown-method":true,
 "relay-invalid-duration":true,"relay-invalid-port":true,
 "relay-kv-syntax":true,"relay-kv-unknown":true,"relay-kv-missing":true,
 "relay-kv-type":true,"relay-kv-limit":true,
 "relay-limit":true,"relay-slots":true,"relay-cooldown":true,
 "relay-disabled":true,"relay-permissions":true,"relay-no-running":true,
 "relay-no-callback":true,"relay-backend-fault":true,
 "relay-target-restricted":true,"relay-help":true,
}

func gallery(req Request) (Result,error) {
 for key:=range req.Args {
  if key!="name"{return Result{},fmt.Errorf("views takes only name=<screen>; unknown argument %q",key)}
 }
 name:=req.Args["name"]
 if name=="" {
  names:=make([]string,0,len(galleryNames))
  for candidate:=range galleryNames{names=append(names,candidate)}
  sort.Strings(names)
  return Result{Text:"C2 Relay screen gallery (no jobs launched).\n"+
   "Use: c2-relay views name=<screen>\n"+strings.Join(names,"  ")},nil
 }
 if !galleryNames[name] {return Result{},errors.New("unknown C2 Relay screen name")}
 return Result{View:name,Values:map[string]string{
  "gallery":"VIEW GALLERY / DEMONSTRATION ONLY - NO REQUEST SENT",
  "target":"example.org",
  "method":"api-health",
  "port":"443",
  "duration":"30 seconds (preview)",
  "group":"user",
  "url":"https://api.example.com/attack?target=example.org",
  "role":"operator",
  "scenario":"api-health",
  "limit":"600 seconds (configuration only)",
  "timeout":"15 seconds (configuration only)",
  "summary":"Example status; not a live API result.",
  "detail":"Example message for the chosen SML screen.",
  "hint":"c2-relay preview scenario=api-health group=user duration=30",
  "input":"example.org",
  "dns":"1.1.1.1, 8.8.8.8 (labels)",
 }},nil
}

func viewResult(name string, values map[string]string)Result {
 if !galleryNames[name]{return Result{Text:"C2 Relay: screen not available"}}
 if values==nil{values=map[string]string{}}
 return Result{View:name,Values:values}
}
