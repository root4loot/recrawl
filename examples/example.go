package main

import (
	"fmt"

	"github.com/root4loot/recrawl/pkg/recrawl"
	"github.com/root4loot/scope"
)

func main() {

	opts := recrawl.NewOptions().WithDefaults()
	s := scope.NewScope()

	_ = s.AddInclude("sub.example.com")     // also follow links here
	_ = s.AddExclude("support.example.com") // but don't follow links here

	opts.Scope = s
	opts.Concurrency = 2
	opts.Timeout = 10
	opts.Resolvers = []string{"8.8.8.8", "208.67.222.222"}
	opts.UserAgent = "recrawl"

	// Defaults already applied by NewOptions(); nothing else needed here

	r := recrawl.NewRecrawlWithOptions(opts)

	// process results as they come in
	go func() {
		for result := range r.Results {
			fmt.Println(result.StatusCode, result.RequestURL, result.Error)
		}
	}()

	// single target
	r.Run("example.com")

	// multiple targets
	targets := []string{"example.org", "example.net"}
	r.Run(targets...)
}
