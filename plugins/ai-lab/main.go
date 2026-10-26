package main

import (
	"log"
	"os"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

func main() {
	runner, err := newRunner(os.Getenv("SENTINEL_AI_LAB_ENDPOINT"), nil)
	if err != nil {
		log.Fatal(err)
	}
	app := sentinelplugin.NewPersistent()
	app.OnStop(runner.shutdown)
	handlers := map[string]sentinelplugin.PersistentHandler{
		"run": func(args map[string]string, _ *sentinelplugin.HostServices) (sentinelplugin.Result, error) {
			return runner.run(args)
		},
		"status": func(args map[string]string, _ *sentinelplugin.HostServices) (sentinelplugin.Result, error) {
			return runner.status(args)
		},
		"results": func(args map[string]string, _ *sentinelplugin.HostServices) (sentinelplugin.Result, error) {
			return runner.results(args)
		},
		"cancel": func(args map[string]string, _ *sentinelplugin.HostServices) (sentinelplugin.Result, error) {
			return runner.cancel(args)
		},
		"suites": func(args map[string]string, _ *sentinelplugin.HostServices) (sentinelplugin.Result, error) {
			return runner.suites(args)
		},
	}
	for name, handler := range handlers {
		if err := app.Command(name, handler); err != nil {
			log.Fatal(err)
		}
	}
	if err := app.Serve(); err != nil {
		log.Fatal(err)
	}
}
