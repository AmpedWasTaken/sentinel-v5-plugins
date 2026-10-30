package sentinelplugin

import (
    "bufio"
    "encoding/json"
    "io"
    "strings"
    "testing"
)

func TestHostExtensionsRPCWire(t *testing.T) {
    inputR,inputW:=io.Pipe()
    outputR,outputW:=io.Pipe()
    app:=NewPersistent()
    if err:=app.Command("probe",func(_ map[string]string,host *HostServices)(Result,error){
        if err:=host.DatabasePut("notes","item1",map[string]string{"name":"x"});err!=nil{return Result{},err}
        id,err:=host.SubscribeEvent("plugin.demo.ready")
        if err!=nil{return Result{},err}
        events,err:=host.PollEvents(id,5)
        if err!=nil{return Result{},err}
        sessions,err:=host.ListSessions(5)
        if err!=nil{return Result{},err}
        return Result{Text:"success",Values:map[string]string{
            "events":string(rune('0'+len(events))),
            "sessions":string(rune('0'+len(sessions))),
        }},nil
    });err!=nil{t.Fatal(err)}
    done:=make(chan error,1)
    go func(){done<-app.ServeIO(inputR,outputW)}()
    token:=strings.Repeat("a",64)
    if err:=json.NewEncoder(inputW).Encode(persistentFrame{Version:PersistentProtocolVersion,Type:"command",Token:token,Command:"probe"});err!=nil{t.Fatal(err)}
    reader:=bufio.NewReader(outputR)
    cases:=[]struct{service string; response string}{
        {"db.put",`{"ok":true}`},
        {"events.subscribe",`{"subscription_id":"sub1"}`},
        {"events.poll",`{"events":[{"topic":"plugin.demo.ready","plugin_id":"demo","timestamp":"2026-10-30T20:00:00Z"}]}`},
        {"sessions.list",`{"sessions":[{"id":"1","username":"root","connected":"2026-10-30T20:00:00Z","last_active":"2026-10-30T20:00:00Z"}]}`},
    }
    for _,expect:=range cases{
        line,err:=reader.ReadBytes(10)
        if err!=nil{t.Fatal(err)}
        var received persistentFrame
        if err:=json.Unmarshal(line,&received);err!=nil{t.Fatal(err)}
        if received.Service!=expect.service{t.Fatalf("expected %s got %s",expect.service,received.Service)}
        reply:=persistentFrame{Version:PersistentProtocolVersion,Type:"service-result",Token:token,ID:received.ID,Service:received.Service,Data:json.RawMessage(expect.response)}
        if err:=json.NewEncoder(inputW).Encode(reply);err!=nil{t.Fatal(err)}
    }
    line,err:=reader.ReadBytes(10)
    if err!=nil{t.Fatal(err)}
    var final persistentFrame
    if err:=json.Unmarshal(line,&final);err!=nil{t.Fatal(err)}
    if final.Type!="result"||final.Text!="success"||final.Values["events"]!="1"||final.Values["sessions"]!="1"{
        t.Fatalf("unexpected extension result: %#v",final)
    }
    _=inputW.Close()
    if err:=<-done;err!=nil{t.Fatal(err)}
}
