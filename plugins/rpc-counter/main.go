package main

import (
    "errors"
    "log"
    "strconv"

    "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

func main() {
    plugin := sentinelplugin.NewPersistent()
    if err := plugin.Command("counter", func(args map[string]string, host *sentinelplugin.HostServices) (sentinelplugin.Result, error) {
        if len(args) != 0 {
            return sentinelplugin.Result{}, errors.New("counter does not accept arguments")
        }
        metrics,err:=host.ServerMetrics()
        if err!=nil{return sentinelplugin.Result{},err}
        previous,found,err:=sentinelplugin.ReadJSON[int](host,"count")
        if err!=nil{return sentinelplugin.Result{},err}
        if found && (previous<0 || previous>=1000000){
            return sentinelplugin.Result{},errors.New("stored counter is invalid")
        }
        current:=previous+1
        if err:=sentinelplugin.WriteJSON(host,"count",current);err!=nil {
            return sentinelplugin.Result{},err
        }
        // Optional UI/event notifications must not report an operation failure
        // after the persistent state update has already been committed.
        _ = host.Publish("plugin.rpc-counter.changed",strconv.Itoa(current))
        _ = host.PublishUI(map[string]string{
            "count":strconv.Itoa(current),
            "health":"online",
        })
        return sentinelplugin.Result{View:"counter",Values:map[string]string{
            "count": strconv.Itoa(current),
            "sessions":strconv.FormatInt(metrics.ActiveSessions,10),
            "uptime":strconv.FormatInt(metrics.UptimeSeconds,10),
            "message": "The server persisted this counter in the plugin namespace.",
        }},nil
    });err!=nil{log.Fatal(err)}
    if err:=plugin.Serve();err!=nil{log.Fatal(err)}
}
