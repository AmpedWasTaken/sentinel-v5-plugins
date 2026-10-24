package main

import (
 "errors"
 "fmt"
 "log"
 "os"
 "runtime"
 "strconv"
 "strings"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

type procSnapshot struct {
 load1,load5,load15 string
 uptimeHours float64
 totalKiB,availableKiB uint64
}

func parseSnapshot(load,uptime,meminfo string)(procSnapshot,error){
 var s procSnapshot
 loads:=strings.Fields(load)
 if len(loads)<3{return s,errors.New("invalid /proc/loadavg")}
 values:=[]*string{&s.load1,&s.load5,&s.load15}
 for i,p:=range values{
  n,err:=strconv.ParseFloat(loads[i],64)
  if err!=nil||n<0||n>100000{return s,errors.New("invalid load average")}
  *p=fmt.Sprintf("%.2f",n)
 }
 up:=strings.Fields(uptime)
 if len(up)==0{return s,errors.New("invalid /proc/uptime")}
 seconds,err:=strconv.ParseFloat(up[0],64)
 if err!=nil||seconds<0{return s,errors.New("invalid uptime value")}
 s.uptimeHours=seconds/3600
 for _,line:=range strings.Split(meminfo,"\n"){
  fields:=strings.Fields(line)
  if len(fields)!=3||fields[2]!="kB"{continue}
  n,e:=strconv.ParseUint(fields[1],10,64)
  if e!=nil{continue}
  switch fields[0]{
   case "MemTotal:":s.totalKiB=n
   case "MemAvailable:":s.availableKiB=n
  }
 }
 if s.totalKiB==0||s.availableKiB>s.totalKiB{return s,errors.New("memory counters unavailable or inconsistent")}
 return s,nil
}
func readSnapshot()(procSnapshot,error){
 var empty procSnapshot
 if runtime.GOOS!="linux"{return empty,errors.New("ServerWatch currently requires Linux procfs")}
 read:=func(path string)(string,error){
  b,err:=os.ReadFile(path)
  if err!=nil{return "",err}
  if len(b)>64*1024{return "",errors.New("procfs read exceeds safety limit")}
  return string(b),nil
 }
 load,err:=read("/proc/loadavg");if err!=nil{return empty,fmt.Errorf("load average unavailable: %w",err)}
 uptime,err:=read("/proc/uptime");if err!=nil{return empty,fmt.Errorf("uptime unavailable: %w",err)}
 mem,err:=read("/proc/meminfo");if err!=nil{return empty,fmt.Errorf("memory unavailable: %w",err)}
 return parseSnapshot(load,uptime,mem)
}
func snapshot(req sentinelplugin.Request)(sentinelplugin.Result,error){
 if len(req.Args)!=0{return sentinelplugin.Result{},errors.New("snapshot takes no arguments")}
 s,err:=readSnapshot()
 if err!=nil{return sentinelplugin.Result{},err}
 used:=s.totalKiB-s.availableKiB
 percent:=float64(used)*100/float64(s.totalKiB)
 status:="OK"
 if percent>=90{status="WARNING / memory pressure"}
 return sentinelplugin.Result{Text:strings.Join([]string{
  "SERVERWATCH / LINUX PROCFS",
  fmt.Sprintf("Load average: %s / %s / %s (1/5/15 min)",s.load1,s.load5,s.load15),
  fmt.Sprintf("Uptime: %.1f hours",s.uptimeHours),
  fmt.Sprintf("Memory: %.1f MiB used of %.1f MiB total (%.1f%%)",float64(used)/1024,float64(s.totalKiB)/1024,percent),
  "Status: "+status,
  "These are procfs counters visible to this plugin. A sandbox/container may report a different scope from the actual host.",
  "Read-only operation; no process, network, or firewall changes.",
 },"\n")},nil
}
func main(){
 app:=sentinelplugin.New()
 if err:=app.Command("snapshot",snapshot);err!=nil{log.Fatal(err)}
 if err:=app.Serve();err!=nil{log.Fatal(err)}
}
