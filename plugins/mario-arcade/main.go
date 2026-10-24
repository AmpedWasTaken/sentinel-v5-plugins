// Sentinel V5's JSON-framed RPC entrypoint for the shared terminal arcade.
package main

import (
 "encoding/json"
 "errors"
 "log"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
 "github.com/AmpedWasTaken/sentinel-v5-plugins/plugins/mario-arcade/game"
)

const saveKey="arcade-state"

func main(){
 app:=sentinelplugin.NewPersistent()
 for _,action:=range []string{"play","left","right","jump","jump-left","jump-right","wait","show","new"}{
  move:=action
  if err:=app.Command(move,func(args map[string]string,host *sentinelplugin.HostServices)(sentinelplugin.Result,error){
   if len(args)!=0{return sentinelplugin.Result{},errors.New("arcade commands do not accept arguments")}
   data,exists,err:=host.Get(saveKey)
   if err!=nil{return sentinelplugin.Result{},err}
   state:=game.New()
   if exists {
    var restored game.State
    if err:=json.Unmarshal(data,&restored);err==nil&&restored.Valid(){state=restored}
   }
   if err:=state.Step(move);err!=nil{return sentinelplugin.Result{},err}
   if !exists||(move!="show"&&move!="play"){
    bytes,err:=json.Marshal(state)
    if err!=nil{return sentinelplugin.Result{},err}
    if err:=host.Put(saveKey,json.RawMessage(bytes));err!=nil{return sentinelplugin.Result{},err}
   }
   return sentinelplugin.Result{View:"arcade",Values:state.Render()},nil
  });err!=nil{log.Fatal(err)}
 }
 if err:=app.Serve();err!=nil{log.Fatal(err)}
}
