package main

import (
 "strings"
 "testing"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)
func TestSimulatedAttack(t *testing.T) {
 result,err:=simulateAttack(sentinelplugin.Request{Args:map[string]string{"target":"127.0.0.3","method":"TCP","port":"8080","time":"60"}})
 if err!=nil{t.Fatal(err)}
 if result.View!="attack-sim" || result.Values["status"]!="SIMULATED" || !strings.HasPrefix(result.Values["request_id"],"sim-"){t.Fatalf("unexpected result: %+v",result)}
}
func TestSimulatedAttackRejectsInvalidInputs(t *testing.T){
 cases:=[]map[string]string{
  {"target":"example.com","method":"TCP","port":"0","time":"60"},
  {"target":"example.com","method":"TCP","port":"80","time":"999999"},
  {"target":"example.com","method":"SHELL","port":"80","time":"60"},
  {"target":"example.com/../../","method":"HTTP","port":"80","time":"60"},
  {"target":"example.com","method":"TCP","port":"80","time":"60","extra":"bad"},
 }
 for _,args:=range cases {
  if _,err:=simulateAttack(sentinelplugin.Request{Args:args});err==nil{t.Errorf("accepted invalid input %v",args)}
 }
}
