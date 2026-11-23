// SML Go Showcase demonstrates a native Go plugin returning safe presentation
// bindings. It does not run shell commands, scan the network, or access files.
package main

import (
  "log"

  "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

func main() {
  plugin := sentinelplugin.New()
  if err := plugin.Command("preview", func(req sentinelplugin.Request) (sentinelplugin.Result, error) {
    return sentinelplugin.Result{
      View: "go-preview",
      Values: map[string]string{
        "status": "ONLINE",
        "cpu": "64",
        "memory": "38",
        "disk": "72",
        "sessions": "14",
        "history": "12,18,32,24,30,41,39,52,64,58,48,64",
        "message": "Synthetic demo data from the Go plugin SDK",
      },
    }, nil
  }); err != nil {
    log.Fatal(err)
  }
  if err := plugin.Serve(); err != nil {
    log.Fatal(err)
  }
}
