package sentinelplugin

import (
    "bufio"
    "encoding/json"
    "io"
    "strings"
    "testing"
)

func TestPersistentHostServices(t *testing.T){
    inputR,inputW:=io.Pipe()
    outputR,outputW:=io.Pipe()
    app:=NewPersistent()
    if err:=app.Command("count",func(args map[string]string,host *HostServices)(Result,error){
        data,found,err:=host.Get("count")
        if err!=nil{return Result{},err}
        if !found{return Result{},nil}
        return Result{View:"report",Values:map[string]string{"count":string(data)}},nil
    });err!=nil{t.Fatal(err)}
    done:=make(chan error,1)
    go func(){done<-app.ServeIO(inputR,outputW)}()
    reader:=bufio.NewReader(outputR)
    token:=strings.Repeat("a",64)
    first:=persistentFrame{Version:1,Type:"command",Token:token,Command:"count"}
    if err:=json.NewEncoder(inputW).Encode(first);err!=nil{t.Fatal(err)}
    row,err:=reader.ReadBytes('\n');if err!=nil{t.Fatal(err)}
    var request persistentFrame
    if err:=json.Unmarshal(row,&request);err!=nil{t.Fatal(err)}
    if request.Service!="storage.get"||request.Key!="count"{t.Fatalf("unexpected request %#v",request)}
    response:=persistentFrame{Version:1,Type:"service-result",Token:token,ID:request.ID,Service:request.Service,Found:true,Data:json.RawMessage(`42`)}
    if err:=json.NewEncoder(inputW).Encode(response);err!=nil{t.Fatal(err)}
    row,err=reader.ReadBytes('\n');if err!=nil{t.Fatal(err)}
    var final persistentFrame
    if err:=json.Unmarshal(row,&final);err!=nil{t.Fatal(err)}
    if final.Type!="result"||final.View!="report"||final.Values["count"]!="42"{t.Fatalf("unexpected result %#v",final)}
    _=inputW.Close()
    if err:=<-done;err!=nil{t.Fatal(err)}
}

func TestPersistentHealthCheck(t *testing.T){
    inR,inW:=io.Pipe()
    outR,outW:=io.Pipe()
    app:=NewPersistent()
    done:=make(chan error,1)
    go func(){done<-app.ServeIO(inR,outW)}()
    token:=strings.Repeat("b",64)
    if err:=json.NewEncoder(inW).Encode(persistentFrame{Version:PersistentProtocolVersion,Type:"command",Token:token,Command:"__health__"});err!=nil{t.Fatal(err)}
    var response persistentFrame
    if err:=json.NewDecoder(outR).Decode(&response);err!=nil{t.Fatal(err)}
    if response.Type!="result"||response.Text!="ready"||response.Token!=token{
        t.Fatalf("health response mismatch: %#v",response)
    }
    _=inW.Close()
    if err:=<-done;err!=nil{t.Fatal(err)}
}
