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
	opts.MineParams = true
	opts.EnableDiscovery = true

	r := recrawl.NewRecrawlWithOptions(opts)

	go func() {
		for result := range r.Results {
			if len(result.RedirectChain) > 0 {
				fmt.Printf("%d %s -> %s (redirects: %d)\n", result.StatusCode, result.RequestURL, result.FinalURL, len(result.RedirectChain))
			} else {
				fmt.Printf("%d %s\n", result.StatusCode, result.RequestURL)
			}
		}
	}()

	// single run
	r.Run("example.com")

	if jsonStr, err := r.ParamMiner.ToJSON(); err == nil && jsonStr != "" {
		fmt.Println("Parameters:")
		fmt.Println(jsonStr)
	}
}
