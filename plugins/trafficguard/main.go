package main

import (
 "bufio"
 "errors"
 "fmt"
 "log"
 "net/netip"
 "regexp"
 "sort"
 "strconv"
 "strings"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

const maxLogBytes = 10000
var httpStatus = regexp.MustCompile(`"\s+([1-5][0-9][0-9])(?:\s|$)`)

type ipCount struct { ip string; requests, denied, errors int }

func analyzeLog(input string) (string,error) {
 if input=="" {return "",errors.New("usage: trafficguard analyze log=<combined access log>")}
 if len(input)>maxLogBytes {return "",errors.New("log exceeds 10 KB; submit a bounded sample")}
 records:=map[string]*ipCount{}
 total,clientErrors,serverErrors,invalid:=0,0,0,0
 scanner:=bufio.NewScanner(strings.NewReader(input))
 scanner.Buffer(make([]byte,4096),maxLogBytes+100)
 for scanner.Scan() {
  line:=scanner.Text()
  fields:=strings.Fields(line)
  if len(fields)<2 {invalid++;continue}
  ip,err:=netip.ParseAddr(fields[0])
  match:=httpStatus.FindStringSubmatch(line)
  if err!=nil || !ip.IsValid() || len(match)!=2 {invalid++;continue}
  status,err:=strconv.Atoi(match[1])
  if err!=nil {invalid++;continue}
  key:=ip.String()
  record:=records[key]
  if record==nil {record=&ipCount{ip:key};records[key]=record}
  record.requests++;total++
  if status==429||status==403 {record.denied++}
  if status>=400 && status<500 {clientErrors++}
  if status>=500 && status<600 {serverErrors++;record.errors++}
 }
 if err:=scanner.Err();err!=nil {return "",err}
 if total==0 {return "",errors.New("no valid combined access log entries found")}
 rows:=make([]*ipCount,0,len(records))
 for _,v:=range records {rows=append(rows,v)}
 sort.Slice(rows,func(i,j int)bool{
  if rows[i].requests==rows[j].requests{return rows[i].ip<rows[j].ip}
  return rows[i].requests>rows[j].requests
 })
 out:=[]string{
  "TRAFFICGUARD / OFFLINE ACCESS LOG ANALYSIS",
  fmt.Sprintf("Requests: %d | Unique clients: %d | 4xx: %d | 5xx: %d | Invalid lines: %d",total,len(records),clientErrors,serverErrors,invalid),
  "CLIENT IP                         REQUESTS   403/429   5xx",
 }
 for i,v:=range rows {
  if i>=10 {break}
  out=append(out,fmt.Sprintf("%-33s %-10d %-9d %d",v.ip,v.requests,v.denied,v.errors))
 }
 out=append(out,
  "This is a bounded pasted sample, not real-time packet capture or proof of an attack.",
  "Confirm with CDN/WAF, host counters, request rates and upstream provider before mitigation.",
  "No firewall changes, network requests or shell commands were executed.")
 return strings.Join(out,"\n"),nil
}

func blockPlan(raw string)(string,error){
 ip,err:=netip.ParseAddr(strings.TrimSpace(raw))
 if err!=nil || !ip.IsValid() || ip.Zone()!="" {return "",errors.New("ip must be one valid IPv4 or IPv6 address (no ranges or CIDR)")}
 if ip.Is4In6()||ip.IsUnspecified()||ip.IsLoopback()||ip.IsMulticast()||ip.IsLinkLocalUnicast()||ip.IsPrivate(){
  return "",errors.New("refusing loopback, private, multicast, link-local or unspecified address; protect management access")
 }
 binary:="iptables"
 if ip.Is6(){binary="ip6tables"}
 addr:=ip.String()
 return strings.Join([]string{
  "TRAFFICGUARD / FIREWALL CHANGE PLAN (NOT EXECUTED)",
  "Target: "+addr,
  "Proposed change: "+binary+" -I INPUT -s "+addr+" -j DROP",
  "Rollback:        "+binary+" -D INPUT -s "+addr+" -j DROP",
  "Before approval: confirm ownership, attack evidence, IPv4/IPv6 ruleset, SSH management exceptions and provider firewall policy.",
  "Use a time-limited, separately approved privileged firewall service with automatic rollback for actual changes.",
  "No OS command executed. This plugin does not require root.",
 },"\n"),nil
}

func analyze(req sentinelplugin.Request)(sentinelplugin.Result,error) {
 if len(req.Args)!=1{return sentinelplugin.Result{},errors.New("usage: trafficguard analyze log=<access log>")}
 for key:=range req.Args {if key!="log"{return sentinelplugin.Result{},errors.New("only log is supported")}}
 text,err:=analyzeLog(req.Args["log"])
 return sentinelplugin.Result{Text:text},err
}
func plan(req sentinelplugin.Request)(sentinelplugin.Result,error) {
 if len(req.Args)!=1{return sentinelplugin.Result{},errors.New("usage: trafficguard block-plan ip=<address>")}
 for key:=range req.Args {if key!="ip"{return sentinelplugin.Result{},errors.New("only ip is supported")}}
 text,err:=blockPlan(req.Args["ip"])
 return sentinelplugin.Result{Text:text},err
}
func main(){
 app:=sentinelplugin.New()
 if err:=app.Command("analyze",analyze);err!=nil{log.Fatal(err)}
 if err:=app.Command("block-plan",plan);err!=nil{log.Fatal(err)}
 if err:=app.Serve();err!=nil{log.Fatal(err)}
}
