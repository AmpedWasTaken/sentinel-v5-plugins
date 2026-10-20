package sentinelplugin

import (
    "bytes"
    "errors"
    "strings"
    "testing"
)

func TestSDKRegistersAndHandlesCommand(t *testing.T) {
    plugin:=New()
    if err:=plugin.Command("hello",func(req Request)(Result,error){
        if req.Actor!="alice"||req.Role!="viewer"{t.Fatalf("lost actor permissions in request")}
        return Result{View:"greeting",Values:map[string]string{"name":req.Args["name"]}},nil
    });err!=nil{t.Fatal(err)}
    if err:=plugin.Command("hello",func(Request)(Result,error){return Result{},nil});err==nil{t.Fatal("duplicate handler accepted")}
    input:=`{"version":1,"command":"hello","actor":"alice","role":"viewer","args":{"name":"Sentinel"}}`
    var output bytes.Buffer
    if err:=plugin.ServeIO(strings.NewReader(input),&output);err!=nil{t.Fatal(err)}
    if !strings.Contains(output.String(),`"view":"greeting"`) || !strings.Contains(output.String(),`"name":"Sentinel"`){
        t.Fatalf("incorrect SDK response: %s",output.String())
    }
}

func TestSDKRejectsInvalidRequestsAndHandlerErrors(t *testing.T) {
    app:=New()
    if err:=app.Command("fail",func(Request)(Result,error){return Result{},errors.New("expected failure")});err!=nil{t.Fatal(err)}
    for _,request:=range []string{
        `{}`, `{"version":2,"command":"fail"}`, `{"version":1,"command":"unknown"}`,
        `{"version":1,"command":"fail"}`, `{"version":1,"command":"fail","shell":"no"}`,
        `{"version":1,"command":"fail"}{"version":1}`,
    }{
        var out bytes.Buffer
        if err:=app.ServeIO(strings.NewReader(request),&out);err!=nil{t.Fatal(err)}
        if !strings.Contains(out.String(),`"error":`){t.Fatalf("invalid request not rejected: %s => %s",request,out.String())}
    }
}
