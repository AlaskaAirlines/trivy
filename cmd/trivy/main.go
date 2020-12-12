package main

import (
	l "log"
	"os"

	"github.com/AlaskaAirlines/trivy/internal"

	"github.com/AlaskaAirlines/trivy/pkg/log"
)

var (
	version = "dev"
)

func main() {
	app := internal.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		if log.Logger != nil {
			log.Fatal(err)
		}
		l.Fatal(err)
	}
}
