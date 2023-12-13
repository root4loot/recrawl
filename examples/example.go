package main

import (
	"fmt"

	"github.com/root4loot/recrawl/pkg/options"
	"github.com/root4loot/recrawl/pkg/runner"
)

func main() {
	options := options.Options{
		Include:     []string{"example.com"},
		Exclude:     []string{"support.hackerone.com"},
		Concurrency: 2,
		Timeout:     10,
		Delay:       0,
		DelayJitter: 0,
		Resolvers:   []string{"8.8.8.8", "208.67.222.222"},
		UserAgent:   "recrawl",
	}

	runner := runner.NewRunnerWithOptions(&options)

	// create a separate goroutine to process the results as they come in
	go func() {
		for result := range runner.Results {
			fmt.Println(result.StatusCode, result.RequestURL, result.Error)
		}
	}()

	// single target
	runner.Run("google.com")

	// multiple targets
	// targets := []string{"hackerone.com", "bugcrowd.com"}
	// runner.Run(targets...)
}
