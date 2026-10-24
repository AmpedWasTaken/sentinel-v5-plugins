package main

import (
 "strings"
 "testing"
)

func TestParseSnapshot(t *testing.T){
 s,err:=parseSnapshot("0.50 1.50 2.50 1/99 12345","7200.00 50.00","MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n")
 if err!=nil{t.Fatal(err)}
 if s.uptimeHours!=2||s.totalKiB!=1048576||s.availableKiB!=524288||s.load1!="0.50"||s.load5!="1.50"{
  t.Fatalf("bad snapshot: %#v",s)
 }
}
func TestRejectInvalidProcData(t *testing.T){
 fixtures:=[][3]string{
  {"","7200.0 0.0","MemTotal: 4 kB\nMemAvailable: 2 kB\n"},
  {"0 1 2","not-a-number","MemTotal: 4 kB\nMemAvailable: 2 kB\n"},
  {"0 1 2","7200.0 0.0","MemTotal: 4 kB\nMemAvailable: 5 kB\n"},
  {"0 1 2","7200.0 0.0","MemAvailable: 2 kB\n"},
 }
 for _,f:=range fixtures{
  if _,err:=parseSnapshot(f[0],f[1],f[2]);err==nil{t.Errorf("accepted malformed procfs: %q",strings.Join(f[:],"/"))}
 }
}
