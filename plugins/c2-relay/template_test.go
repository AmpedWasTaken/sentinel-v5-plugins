package main

import (
 "strings"
 "testing"
)

const safeAttackPreviewURL="https://api.example.com/attack?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>"

func previewTemplateForTest()AttackTemplate{
 return AttackTemplate{Enabled:true,Mode:"preview_only",URL:safeAttackPreviewURL}
}
func TestAttackTemplateAcceptsLegacyPlaceholders(t *testing.T){
 tmpl:=previewTemplateForTest()
 if err:=tmpl.Validate();err!=nil{t.Fatal(err)}
 group:=[]Group{{Name:"user",MaxDurationSeconds:600,MaxConcurrent:15}}
 out,err:=tmpl.RenderPreview(map[string]string{
  "target":"example.org","port":"443","duration":"30","method":"tcp","group":"user",
 },group)
 if err!=nil{t.Fatal(err)}
 for _,piece:=range []string{"/attack?","target=example.org","port=443","duration=30","method=tcp"}{
  if !strings.Contains(out,piece){t.Errorf("rendered URL missing %q: %q",piece,out)}
 }
 if strings.Contains(out,"<<$"){t.Errorf("unresolved placeholder: %q",out)}
}
func TestAttackTemplateRejectsUnapprovedModeAndHostRewrite(t *testing.T){
 invalid:=[]AttackTemplate{
  {Enabled:true,Mode:"dispatch",URL:safeAttackPreviewURL},
  {Enabled:true,Mode:"preview_only",URL:"http://api.example.com/attack?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>"},
  {Enabled:true,Mode:"preview_only",URL:"https://<<$target>>/attack?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>"},
  {Enabled:true,Mode:"preview_only",URL:"https://api.example.com/launch?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>"},
  {Enabled:true,Mode:"preview_only",URL:"https://api.example.com/attack?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$kv_devices>>"},
  {Enabled:true,Mode:"preview_only",URL:"https://api.example.com/attack?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>&secret=<<$key>>"},
 }
 for _,tmpl:=range invalid{if err:=tmpl.Validate();err==nil{t.Errorf("invalid template accepted: %+v",tmpl)}}
}
func TestAttackTemplateEnforcesPreviewArguments(t *testing.T){
 tmpl:=previewTemplateForTest()
 group:=[]Group{{Name:"user",MaxDurationSeconds:600,MaxConcurrent:15}}
 cases:=[]map[string]string{
  {"target":"https://example.com","port":"443","duration":"30","method":"tcp","group":"user"},
  {"target":"example.org","port":"0","duration":"30","method":"tcp","group":"user"},
  {"target":"example.org","port":"443","duration":"601","method":"tcp","group":"user"},
  {"target":"example.org","port":"443","duration":"30","method":"tcp","group":"unknown"},
  {"target":"example.org","port":"443","duration":"30","method":"tcp","group":"user","url":"https://other.example/attack"},
 }
 for _,args:=range cases {if _,err:=tmpl.RenderPreview(args,group);err==nil{t.Errorf("invalid arguments accepted: %#v",args)}}
}
func TestAttackTemplateCommandNeverInvokesHTTPClient(t *testing.T){
 cfg:=configForTest(t)
 cfg.Relay.AttackTemplate=previewTemplateForTest()
 req:=Request{Version:1,Command:"template",Args:map[string]string{
  "target":"example.org","port":"443","duration":"30","method":"tcp","group":"user",
 }}
 out,err:=handle(req,cfg)
 if err!=nil{t.Fatal(err)}
 if out.View!=""||!strings.Contains(out.Text,"DRY RUN ONLY")||
  !strings.Contains(out.Text,"target=example.org"){
  t.Fatalf("expected a text-only, non-dispatched request preview: %+v",out)
 }
}
func TestShippedConfigIncludesLegacyTemplate(t *testing.T){
 cfg,err:=readConfig("config.yaml")
 if err!=nil{t.Fatal(err)}
 if !cfg.Relay.AttackTemplate.Enabled || cfg.Relay.AttackTemplate.Mode!="preview_only"{
  t.Fatalf("shipped config must declare preview-only attack syntax: %+v",cfg.Relay.AttackTemplate)
 }
}
