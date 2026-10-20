package main

import (
 "log"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/communitytools"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)
func main() {
 app:=sentinelplugin.New()
 if err:=app.Command("connect",func(req sentinelplugin.Request)(sentinelplugin.Result,error){return communitytools.Run("netcatty","connect",req.Args)});err!=nil{log.Fatal(err)}
 if err:=app.Command("scan",func(req sentinelplugin.Request)(sentinelplugin.Result,error){return communitytools.Run("netcatty","scan",req.Args)});err!=nil{log.Fatal(err)}
 if err:=app.Command("banner",func(req sentinelplugin.Request)(sentinelplugin.Result,error){return communitytools.Run("netcatty","banner",req.Args)});err!=nil{log.Fatal(err)}
 if err:=app.Command("udp",func(req sentinelplugin.Request)(sentinelplugin.Result,error){return communitytools.Run("netcatty","udp",req.Args)});err!=nil{log.Fatal(err)}
 if err:=app.Serve();err!=nil{log.Fatal(err)}
}
