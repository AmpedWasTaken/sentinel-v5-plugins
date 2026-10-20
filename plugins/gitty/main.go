package main
import ("log";"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/communityextras";"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin")
func main(){app:=sentinelplugin.New();if err:=app.Command("status",func(req sentinelplugin.Request)(sentinelplugin.Result,error){return communityextras.Run("gitty","status",req.Args)});err!=nil{log.Fatal(err)};if err:=app.Serve();err!=nil{log.Fatal(err)}}
