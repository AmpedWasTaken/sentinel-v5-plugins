package main

import (
 "log"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/communitytools"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)
func main() {
 app:=sentinelplugin.New()
 if err:=app.Command("inspect",func(req sentinelplugin.Request)(sentinelplugin.Result,error){return communitytools.Run("certcheck","inspect",req.Args)});err!=nil{log.Fatal(err)}
 if err:=app.Serve();err!=nil{log.Fatal(err)}
}
