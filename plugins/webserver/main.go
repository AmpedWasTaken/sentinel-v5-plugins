package main

import (
 "errors"
 "fmt"
 "log"
 "strconv"
 "strings"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

func emptyArgs(args map[string]string)error{
 if len(args)!=0{return errors.New("this command accepts no arguments")}
 return nil
}
func main(){
 service:=newWebService()
 app:=sentinelplugin.NewPersistent()
 app.OnStart(service.startFromDisk)
 app.OnStop(service.close)
 commands:=map[string]sentinelplugin.PersistentHandler{
  "status":func(args map[string]string,_ *sentinelplugin.HostServices)(sentinelplugin.Result,error){
   if err:=emptyArgs(args);err!=nil{return sentinelplugin.Result{},err}
   return sentinelplugin.Result{View:"web-status",Values:service.statusValues()},nil
  },
  "routes":func(args map[string]string,_ *sentinelplugin.HostServices)(sentinelplugin.Result,error){
   if err:=emptyArgs(args);err!=nil{return sentinelplugin.Result{},err}
   return sentinelplugin.Result{Text:service.routeTable()},nil
  },
  "traffic":func(args map[string]string,_ *sentinelplugin.HostServices)(sentinelplugin.Result,error){
   for k:=range args{if k!="limit"{return sentinelplugin.Result{},fmt.Errorf("unknown argument %q",k)}}
   n:=10
   if v:=args["limit"];v!="" {
    number,err:=strconv.Atoi(v)
    if err!=nil || number<1 || number>20{return sentinelplugin.Result{},errors.New("limit must be 1..20")}
    n=number
   }
   return sentinelplugin.Result{Text:service.trafficTable(n)},nil
  },
  "reload":func(args map[string]string,_ *sentinelplugin.HostServices)(sentinelplugin.Result,error){
   if err:=emptyArgs(args);err!=nil{return sentinelplugin.Result{},err}
   if err:=service.reload();err!=nil{return sentinelplugin.Result{},err}
   return sentinelplugin.Result{Text:"WEB SERVER / CONFIG RELOADED\nRoutes, sites and rate limits updated without dropping the listener."},nil
  },
  "start":func(args map[string]string,_ *sentinelplugin.HostServices)(sentinelplugin.Result,error){
   if err:=emptyArgs(args);err!=nil{return sentinelplugin.Result{},err}
   if err:=service.startFromDisk();err!=nil{return sentinelplugin.Result{},err}
   return sentinelplugin.Result{Text:"WEB SERVER / STARTED\n"+strings.TrimSpace(service.statusLine())},nil
  },
  "stop":func(args map[string]string,_ *sentinelplugin.HostServices)(sentinelplugin.Result,error){
   if err:=emptyArgs(args);err!=nil{return sentinelplugin.Result{},err}
   if err:=service.stop();err!=nil{return sentinelplugin.Result{},err}
   return sentinelplugin.Result{Text:"WEB SERVER / STOPPED\nListener closed."},nil
  },
 }
 for name,handler:=range commands{if err:=app.Command(name,handler);err!=nil{log.Fatal(err)}}
 if err:=app.Serve();err!=nil{log.Fatal(err)}
}
