package main

import (
    "log"
    "strings"

    "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

func main() {
    plugin := sentinelplugin.New()
    if err := plugin.Command("greet", func(req sentinelplugin.Request) (sentinelplugin.Result, error) {
        name := req.Args["name"]
        if name == "" { name = req.Actor }
        name = strings.TrimSpace(name)
        return sentinelplugin.Result{
            View: "greeting",
            Values: map[string]string{"name":name},
        }, nil
    }); err != nil { log.Fatal(err) }
    if err := plugin.Serve(); err != nil { log.Fatal(err) }
}
