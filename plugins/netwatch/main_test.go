package main

import (
 "encoding/json"
 "os"
 "runtime"
 "testing"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

func TestDeltaCounterReset(t *testing.T){
 if delta(50,40)!=10{t.Fatal("counter delta wrong")}
 if delta(2,100)!=0{t.Fatal("counter reset not handled")}
}
func TestUnits(t *testing.T){
 if formatBytes(2048)!="2.00 KiB"{t.Fatal("unit conversion wrong")}
}

func TestInterfacesStructuredResult(t *testing.T) {
 if runtime.GOOS!="linux"{t.Skip("Linux /proc/net/dev integration test")}
 if _,err:=os.Stat("/proc/net/dev");err!=nil{t.Skip("procfs unavailable")}
 res,err:=listInterfaces(sentinelplugin.Request{Args:map[string]string{}})
 if err!=nil{t.Fatal(err)}
 if res.View!="interfaces"{t.Fatalf("expected interfaces SML, got %q",res.View)}
 var rows []map[string]string
 if err:=json.Unmarshal([]byte(res.Values["rows"]),&rows);err!=nil{t.Fatal(err)}
 if len(rows)==0{t.Fatal("no interface rows")}
 for _,row:=range rows{
  if row["name"]==""||row["rx"]==""||row["tx"]==""{t.Errorf("invalid interface row: %#v",row)}
 }
}
