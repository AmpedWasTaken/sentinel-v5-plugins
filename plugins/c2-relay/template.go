package main

import (
 "errors"
 "fmt"
 "net"
 "net/url"
 "regexp"
 "strconv"
 "strings"
)

// AttackTemplate keeps legacy URL substitution syntax for display and config
// migration ONLY. No code path performs an HTTP request to this URL.
type AttackTemplate struct {
 Enabled bool `yaml:"enabled"`
 Mode string `yaml:"mode"`
 URL string `yaml:"url"`
}

var previewTokenPattern = regexp.MustCompile(`<<\$([a-z_]+)>>`)
var previewHostPattern = regexp.MustCompile(`^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$`)
var previewTargetPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}[a-zA-Z0-9]$`)
var previewPlaceholders = map[string]bool{"target":true,"port":true,"duration":true,"method":true,"api_key":true}

func (a AttackTemplate) Validate() error {
 if !a.Enabled && a.URL=="" && a.Mode=="" {return nil}
 if a.Mode!="preview_only" {return errors.New("attack_template mode must be preview_only; dispatch is not supported")}
 if len(a.URL)==0 || len(a.URL)>600 || strings.ContainsAny(a.URL,"\r\n\x1b") {
  return errors.New("invalid preview-only /attack or /testnetwork URL template")
 }
 u,err:=url.Parse(a.URL)
 if err!=nil || u.Scheme!="https" || u.Host=="" || u.User!=nil || u.Opaque!="" ||
  (u.Port()!="" && u.Port()!="443") || u.Fragment!="" || u.RawFragment!="" ||
  (u.Path!="/attack" && u.Path!="/testnetwork") || u.RawPath!="" || u.RawQuery=="" {
  return errors.New("preview-only template must be HTTPS /attack or /testnetwork with query placeholders")
 }
 if !previewHostPattern.MatchString(u.Hostname()) || net.ParseIP(u.Hostname())!=nil ||
  strings.HasSuffix(strings.ToLower(u.Hostname()),".local") || strings.HasSuffix(strings.ToLower(u.Hostname()),".localhost") {
  return errors.New("preview-only template needs a DNS hostname")
 }
 found:=map[string]bool{}
 for _,match:=range previewTokenPattern.FindAllStringSubmatch(a.URL,-1){
  if !previewPlaceholders[match[1]] {return fmt.Errorf("unsupported preview token %s",match[0])}
  found[match[1]]=true
 }
 for _,token:=range []string{"target","port","duration","method"}{
  if !found[token] {return fmt.Errorf("preview URL missing required %s placeholder",token)}
 }
 remaining:=previewTokenPattern.ReplaceAllString(a.URL,"value")
 if strings.Contains(remaining,"<<")||strings.Contains(remaining,">>")||
  strings.ContainsAny(remaining,"{}") {return errors.New("invalid or unresolved URL placeholder")}
 // Only query values may contain placeholders; no user value can rewrite an
 // origin, path, query parameter name, request method or HTTP headers.
 parts:=strings.Split(u.RawQuery,"&")
 if len(parts)>8 {return errors.New("too many URL query fields")}
 for _,part:=range parts{
  key,val,ok:=strings.Cut(part,"=")
  if !ok||key==""||strings.ContainsAny(key,"<>")||strings.Contains(key,"%") {
   return errors.New("preview query keys must be static")
  }
  if len(val)==0 {return errors.New("preview query values cannot be empty")}
  if key=="key" && val!="<<$api_key>>" {return errors.New("never store an API key in YAML; use the redacted <<$api_key>> preview marker")}
  if key!="key" && strings.Contains(val,"<<$api_key>>") {return errors.New("api_key marker is only valid in the key query field")}
 }
 if found["api_key"] && !strings.Contains(u.RawQuery,"key=<<$api_key>>") {
  return errors.New("api_key marker must be the complete key query value")
 }
 return nil
}

// RenderPreview is a pure string transformation and NEVER sends the URL.
// It is isolated from checkHealthAPI's network client and accepts no
// arbitrary request headers, HTTP methods, body, callback or target URL.
func (a AttackTemplate) RenderPreview(args map[string]string, groups []Group) (string,error) {
 if !a.Enabled {return "",errors.New("attack URL preview is disabled")}
 if err:=a.Validate();err!=nil{return "",err}
 for key:=range args {
  if key!="target"&&key!="port"&&key!="duration"&&key!="method"&&key!="group" {
   return "",fmt.Errorf("unsupported preview argument %q",key)
  }
 }
 target:=strings.TrimSpace(args["target"])
 if len(target)>253 || (net.ParseIP(target)==nil && !previewTargetPattern.MatchString(target))||
  strings.ContainsAny(target,"\r\n\x1b") {return "",errors.New("target must be a hostname or IP label, not a URL")}
 if args["method"]==""||!safeSlug.MatchString(args["method"]) {
  return "",errors.New("method must be a safe scenario label")
 }
 port,err:=strconv.Atoi(args["port"])
 if err!=nil||port<1||port>65535{return "",errors.New("port must be 1..65535")}
 duration,err:=strconv.Atoi(args["duration"])
 if err!=nil||duration<1{return "",errors.New("duration must be a positive number of seconds")}
 groupName:=args["group"]
 maxDuration:=0
 for _,g:=range groups {if g.Name==groupName {maxDuration=g.MaxDurationSeconds;break}}
 if maxDuration==0||duration>maxDuration {
  return "",errors.New("group is unknown or duration exceeds the configured limit")
 }
 replacements:=map[string]string{
  "target":target,
  "port":strconv.Itoa(port),
  "duration":strconv.Itoa(duration),
  "method":args["method"],
 }
 u,_:=url.Parse(a.URL)
 query:=u.RawQuery
 for token,value:=range replacements {
  query=strings.ReplaceAll(query,"<<$"+token+">>",url.QueryEscape(value))
 }
 // API keys are never read from the environment or embedded in previews.
 // The marker is always rendered as a conspicuous redacted placeholder.
 query=strings.ReplaceAll(query,"<<$api_key>>","REDACTED")
 u.RawQuery=query
 rendered:=u.String()
 if len(rendered)>1024{return "",errors.New("rendered URL exceeds display limit")}
 return rendered,nil
}
