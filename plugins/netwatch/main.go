package main

import (
 "bufio"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "runtime"
 "sort"
 "strconv"
 "strings"
 "time"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

type counters struct {rx uint64; tx uint64; rxPackets uint64; txPackets uint64; rxErrors uint64; txErrors uint64}

// readCounters samples kernel network interface byte counters without opening
// sockets or generating traffic. Linux /proc/net/dev is required for v1.
func readCounters() (map[string]counters,error) {
 f,err:=os.Open("/proc/net/dev"); if err!=nil{return nil,fmt.Errorf("cannot read host interface counters: %w",err)}
 defer f.Close()
 out:=make(map[string]counters)
 s:=bufio.NewScanner(f)
 for s.Scan(){
  line:=s.Text()
  name,fields,ok:=strings.Cut(line,":");if !ok{continue}
  name=strings.TrimSpace(name)
  cols:=strings.Fields(fields)
  if len(cols)<16{continue}
  rx,err1:=strconv.ParseUint(cols[0],10,64)
  tx,err2:=strconv.ParseUint(cols[8],10,64)
  if err1==nil && err2==nil{
   rxPackets,_:=strconv.ParseUint(cols[1],10,64)
   txPackets,_:=strconv.ParseUint(cols[9],10,64)
   rxErrors,_:=strconv.ParseUint(cols[2],10,64)
   txErrors,_:=strconv.ParseUint(cols[10],10,64)
   out[name]=counters{rx,tx,rxPackets,txPackets,rxErrors,txErrors}
  }
 }
 if err:=s.Err();err!=nil{return nil,err}
 if len(out)==0{return nil,errors.New("no host network counters found")}
 return out,nil
}
func formatBytes(v float64)string{
 const unit=1024
 suffix:=[]string{"B","KiB","MiB","GiB","TiB"}
 i:=0
 for v>=unit && i<len(suffix)-1{v/=unit;i++}
 return fmt.Sprintf("%.2f %s",v,suffix[i])
}
func delta(now,prev uint64)uint64{
 if now<prev{return 0} // wrap/reset; do not display a huge false spike
 return now-prev
}
func sample(req sentinelplugin.Request)(sentinelplugin.Result,error){
 var empty sentinelplugin.Result
 if runtime.GOOS!="linux"{return empty,errors.New("NetWatch v1 requires Linux /proc/net/dev")}
 for k:=range req.Args{if k!="interface"{return empty,fmt.Errorf("unknown argument %q",k)}}
 iface:=req.Args["interface"]
 if iface!="" && (len(iface)>32 || strings.ContainsAny(iface,"/\\: \t\r\n")){return empty,errors.New("invalid interface name")}
 before,err:=readCounters();if err!=nil{return empty,err}
 if iface=="" { iface="all" }
 if iface!="all" { if _,ok:=before[iface];!ok{return empty,errors.New("unknown interface")} }
 started:=time.Now()
 time.Sleep(time.Second)
 after,err:=readCounters();if err!=nil{return empty,err}
 var a,b counters
 if iface=="all" {
  for name,now:=range after {
   if name=="lo"{continue}
   prev,ok:=before[name]
   if !ok{continue}
   a.rx+=now.rx; a.tx+=now.tx; a.rxPackets+=now.rxPackets; a.txPackets+=now.txPackets
   a.rxErrors+=now.rxErrors; a.txErrors+=now.txErrors
   b.rx+=prev.rx; b.tx+=prev.tx; b.rxPackets+=prev.rxPackets; b.txPackets+=prev.txPackets
   b.rxErrors+=prev.rxErrors; b.txErrors+=prev.txErrors
  }
 } else {
  var ok bool
  a,ok=after[iface];if !ok{return empty,errors.New("interface disappeared")}
  b=before[iface]
 }
 seconds:=time.Since(started).Seconds()
 return sentinelplugin.Result{View:"traffic",Values:map[string]string{
  "interface":iface,
  "interval":fmt.Sprintf("%.2f s",seconds),
  "rx_rate":formatBytes(float64(delta(a.rx,b.rx))/seconds)+"/s",
  "tx_rate":formatBytes(float64(delta(a.tx,b.tx))/seconds)+"/s",
  "rx_total":formatBytes(float64(a.rx)),
  "tx_total":formatBytes(float64(a.tx)),
  "rx_packets":fmt.Sprint(a.rxPackets),
  "tx_packets":fmt.Sprint(a.txPackets),
  "rx_errors":fmt.Sprint(a.rxErrors),
  "tx_errors":fmt.Sprint(a.txErrors),
  "rx_pps":fmt.Sprintf("%.0f packets/s",float64(delta(a.rxPackets,b.rxPackets))/seconds),
  "tx_pps":fmt.Sprintf("%.0f packets/s",float64(delta(a.txPackets,b.txPackets))/seconds),
  "info":"Real one-second host counter sample. Interface all aggregates non-loopback adapters. Invoke again to refresh.",
 }},nil
}
// listInterfaces reads all visible network interfaces at once. No artificial traffic.
func listInterfaces(req sentinelplugin.Request)(sentinelplugin.Result,error){
 var empty sentinelplugin.Result
 if runtime.GOOS!="linux"{return empty,errors.New("NetWatch requires Linux /proc/net/dev")}
 if len(req.Args)!=0{return empty,errors.New("interfaces accepts no arguments")}
 countersByName,err:=readCounters();if err!=nil{return empty,err}
 names:=make([]string,0,len(countersByName))
 for name:=range countersByName{names=append(names,name)}
 sort.Strings(names)
 rows:=make([]map[string]string,0,min(len(names),48))
 for _,name:=range names {
  if len(rows)>=48{break}
  v:=countersByName[name]
  rows=append(rows,map[string]string{
   "name":name,
   "rx":formatBytes(float64(v.rx)),
   "tx":formatBytes(float64(v.tx)),
   "rx_errors":fmt.Sprint(v.rxErrors),
   "tx_errors":fmt.Sprint(v.txErrors),
  })
 }
 encoded,err:=json.Marshal(rows)
 if err!=nil{return empty,err}
 return sentinelplugin.Result{View:"interfaces",Values:map[string]string{
  "rows":string(encoded),
  "count":strconv.Itoa(len(names)),
 }},nil
}
func main(){
 app:=sentinelplugin.New()
 if err:=app.Command("watch",sample);err!=nil{panic(err)}
 if err:=app.Command("interfaces",listInterfaces);err!=nil{panic(err)}
 if err:=app.Serve();err!=nil{panic(err)}
}
