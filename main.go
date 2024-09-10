package main

import (
	"flag"
	"fmt"
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/negashev/docker-machine-driver-timeweb/timeweb"
	"os"
)

var version string

func main() {
	versionFlag := flag.Bool("v", false, "prints current docker-machine-driver-timeweb version")
	flag.Parse()
	if *versionFlag {
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	plugin.RegisterDriver(timeweb.NewDriver("", ""))
}
