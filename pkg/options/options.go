// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package options

import (
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/gookit/color"
)

type Options struct {
	Include       []string // domains to be included
	Exclude       []string // domains to be included
	Concurrency   int      // number of concurrent requests
	Timeout       int      // Request timeout duration (in seconds)
	Delay         int      // delay between each request (in ms)
	DelayJitter   int      // maximum jitter to add to delay (in ms)
	UserAgent     string   // custom user-agent
	Proxy         string   // proxy to use for requests
	Silence       bool     // suppress output from console
	Verbose       int      // verbosity level
	Resolvers     []string // resolvers to use for DNS resolution
	SkipRedundant bool     // skip requests that only differ parameter values
	SkipSameBody  bool     // skip crawling responses that have the same response body
	CLI           CLI      // CLI options
}

type CLI struct {
	Include          string // targets to be included (comma separated)
	Exclude          string // targets to be included (comma separated)
	Target           string // target host
	Infile           string // file containin targets (newline separated)
	ResolversFile    string // file containing resolvers (newline separated)
	Outfile          string // file to write results
	FilterStatusCode string // filter by status code (comma separated)
	HideStatusCodes  bool   // show status code
	HideMedia        bool   // hide images and fonts from output
	HideWarning      bool   // hide warnings

	Version bool // print version
	Help    bool // print help
}

// Default returns the default options
func Default() *Options {
	return &Options{
		Concurrency:   20,
		Timeout:       10,
		Delay:         0,
		DelayJitter:   0,
		SkipRedundant: true,
		SkipSameBody:  false,
		UserAgent:     "recrawl",
	}
}

func (from *Options) SetDefaultsMissing() {
	to := Default()
	fromVal := reflect.ValueOf(*from)
	toVal := reflect.ValueOf(to).Elem()

	if fromVal.Kind() != reflect.Struct || toVal.Kind() != reflect.Struct {
		log.Fatal("SetDefaultsMissing: both arguments must be structs")
	}

	for i := 0; i < fromVal.NumField(); i++ {
		fromField := fromVal.Field(i)
		toField := toVal.Field(i)

		if toField.IsZero() && !fromField.IsZero() {
			toField.Set(fromField)
		}
	}
}

func (o *Options) ValidateOptions() {
	if o.Concurrency < 0 || o.Timeout < 0 || o.Delay < 0 || o.DelayJitter < 0 {
		fmt.Printf("%s %s\n", color.FgRed.Text("[!]"), "options must be greater than 0")
	}
	if strings.Contains(o.CLI.Target, ", ") ||
		strings.Contains(o.CLI.Include, ", ") ||
		strings.Contains(o.CLI.Exclude, ", ") {
		log.Fatal("target list must not contain space (must be comma-separated)")
	}
}
