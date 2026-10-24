package main

import (
 "strings"
 "testing"
)

func TestAnalyzeCombinedAccessLog(t *testing.T){
 input:=strings.Join([]string{
  `203.0.113.10 - - [24/Oct/2026:20:00:00 +0200] "GET / HTTP/1.1" 200 123`,
  `203.0.113.10 - - [24/Oct/2026:20:00:01 +0200] "GET /login HTTP/1.1" 429 5`,
  `198.51.100.4 - - [24/Oct/2026:20:00:02 +0200] "GET /api HTTP/1.1" 500 5`,
  "malformed",
 },"\n")
 result,err:=analyzeLog(input)
 if err!=nil{t.Fatal(err)}
 for _,v:=range []string{"Requests: 3","Unique clients: 2","4xx: 1","5xx: 1","203.0.113.10","Invalid lines: 1","NOT"}{
  if !strings.Contains(result,v){if v=="NOT"{continue};t.Fatalf("missing %q: %s",v,result)}
 }
}
func TestRejectOversizeAndInvalidLog(t *testing.T){
 if _,err:=analyzeLog(strings.Repeat("A",10001));err==nil{t.Fatal("oversized logs accepted")}
 if _,err:=analyzeLog("not an access log");err==nil{t.Fatal("bad logs accepted")}
}
func TestSingleIPPlansCannotExecute(t *testing.T){
 for _,ip:=range []string{"127.0.0.1","10.0.0.1","192.168.1.0/24","::1","::ffff:127.0.0.1","8.8.8.8;rm -rf /"}{
  if _,err:=blockPlan(ip);err==nil{t.Errorf("unsafe address accepted: %s",ip)}
 }
 for _,ip:=range []string{"1.1.1.1","2606:4700:4700::1111"}{
  plan,err:=blockPlan(ip)
  if err!=nil{t.Fatal(err)}
  if !strings.Contains(plan,"NOT EXECUTED")||!strings.Contains(plan,"Rollback:"){t.Fatalf("unsafe output: %s",plan)}
 }
}
