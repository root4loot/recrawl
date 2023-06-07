package main

import (
	"fmt"

	"github.com/root4loot/urlwalk/pkg/options"
	"github.com/root4loot/urlwalk/pkg/runner"
)

func main() {
	options := options.Options{
		Include:     []string{"example.com"},
		Exclude:     []string{"support.hackerone.com"},
		Concurrency: 20,
		Timeout:     10,
		Delay:       0,
		DelayJitter: 0,
		Resolvers:   []string{"8.8.8.8", "208.67.222.222"},
		UserAgent:   "urlwalk",
	}

	runner := runner.NewRunner(&options)

	// create a separate goroutine to process the results as they come in
	go func() {
		for result := range runner.Results {
			fmt.Println(result.StatusCode, result.RequestURL, result.Error)
		}
	}()

	// start the runner and begin processing results
	runner.Run("hackerone.com")
}
