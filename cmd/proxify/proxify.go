package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/internal/runner"
)

func main() {

	options := runner.ParseOptions()

	profixyRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatalf("Could not create runner: %s\n", err)
	}

	// Setup close handler
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			fmt.Println("\r- Ctrl+C pressed in Terminal")
			profixyRunner.Close()
			os.Exit(0)
		}()
	}()

	err = profixyRunner.Run()
	if err != nil {
		gologger.Fatalf("Could not run profixy: %s\n", err)
	}

}
