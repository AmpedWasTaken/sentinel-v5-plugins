package main
import ("log";"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/communityextras";"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin")
func main(){app:=sentinelplugin.New();if err:=app.Command("digest",func(req sentinelplugin.Request)(sentinelplugin.Result,error){return communityextras.Run("hashkit","digest",req.Args)});err!=nil{log.Fatal(err)};if err:=app.Serve();err!=nil{log.Fatal(err)}}
