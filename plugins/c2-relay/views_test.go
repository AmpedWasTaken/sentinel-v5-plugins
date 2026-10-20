package main

import (
 "bytes"
 "encoding/json"
 "encoding/xml"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestAllGallerySMLScreensExistAndParse(t *testing.T){
 if len(galleryNames)!=32 {t.Fatalf("expected 32 screens, got %d",len(galleryNames))}
 for name:=range galleryNames{
  t.Run(name,func(t *testing.T){
   data,err:=os.ReadFile(filepath.Join("views",name+".sml"))
   if err!=nil{t.Fatal(err)}
   var screen struct{
    XMLName xml.Name
    Name string `xml:"name,attr"`
    Version string `xml:"version,attr"`
   }
   if err:=xml.Unmarshal(data,&screen);err!=nil{t.Fatal(err)}
   if screen.XMLName.Local!="screen"||screen.Name!=name||screen.Version!="2"{
    t.Fatalf("unexpected SML document root: %+v",screen)
   }
  })
 }
}

func TestCommandsUseBundledViews(t *testing.T){
 cfg:=configForTest(t)
 cfg.Relay.AttackTemplate=previewTemplateForTest()
 cases:=[]Request{
  {Version:1,Command:"info"},
  {Version:1,Command:"methods"},
  {Version:1,Command:"help"},
  {Version:1,Command:"check"},
  {Version:1,Command:"views",Args:map[string]string{"name":"relay-preview-fault"}},
  {Version:1,Command:"preview",Args:map[string]string{"scenario":"tcp","group":"user","duration":"30"}},
  {Version:1,Command:"template",Args:map[string]string{"target":"example.org","port":"443","duration":"30","method":"tcp","group":"user"}},
 }
 for _,req:=range cases{
  result,err:=handle(req,cfg)
  if err!=nil{t.Fatalf("%s: %v",req.Command,err)}
  if !galleryNames[result.View]{
   t.Errorf("%s returned unknown SML screen %q",req.Command,result.View)
  }
 }
}

func TestPreviewInputErrorShowsAppropriateSMLView(t *testing.T){
 path:=fileWithConfig(t,testConfig)
 cases:=[]struct{
  args map[string]string
  view string
 }{
  {map[string]string{"scenario":"tcp","group":"user","duration":"999"},"relay-invalid-duration"},
  {map[string]string{"scenario":"missing","group":"user"},"relay-unknown-method"},
  {map[string]string{"scenario":"tcp","group":"bad"},"relay-limit"},
 }
 for _,tc:=range cases{
  request,_:=json.Marshal(Request{Version:1,Command:"preview",Args:tc.args})
  var out bytes.Buffer
  if err:=serve(bytes.NewReader(request),&out,path);err!=nil{t.Fatal(err)}
  var resp Response
  if err:=json.Unmarshal(out.Bytes(),&resp);err!=nil{t.Fatal(err)}
  if resp.Error!=""||resp.Result.View!=tc.view{
   t.Errorf("want %s, got %+v",tc.view,resp)
  }
 }
}

func TestGalleryIndexAndUnknownName(t *testing.T){
 list,err:=gallery(Request{Args:map[string]string{}})
 if err!=nil||!strings.Contains(list.Text,"relay-preview-sent") {t.Fatalf("invalid gallery listing: %+v %v",list,err)}
 if _,err:=gallery(Request{Args:map[string]string{"name":"../../secret"}});err==nil{
  t.Fatal("unsafe screen path accepted")
 }
}
