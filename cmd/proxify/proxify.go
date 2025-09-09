package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/internal/runner"
	"github.com/projectdiscovery/proxify/pkg/templates"
)

func main() {

	options, err := runner.ParseOptions()
	if err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}

	if options.Template != "" {
		templateOptions, err := templates.Parse(options.Template)
		if err != nil {
			gologger.Fatal().Msgf("Could not parse template: %s\n", err)
		}
		if templateOptions.ListenAddrHTTP != "" {
			options.ListenAddrHTTP = templateOptions.ListenAddrHTTP
		}
	}

	proxifyRunner, err := runner.NewRunner(options)

	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// Setup close handler
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		for range c {
			fmt.Println("\r- Ctrl+C pressed in Terminal")
			proxifyRunner.Close()
			os.Exit(0)
		}
	}()

	err = proxifyRunner.Run()
	if err != nil {
		gologger.Fatal().Msgf("Could not run proxify: %s\n", err)
	}
}
