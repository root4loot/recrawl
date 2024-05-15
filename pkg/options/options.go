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

// StringSlice type to handle repeated flag values
type StringSlice []string

type Options struct {
	Include         []string    // domains to be included
	Exclude         []string    // domains to be included
	Concurrency     int         // number of concurrent requests
	Timeout         int         // Request timeout duration (in seconds)
	Delay           int         // delay between each request (in ms)
	DelayJitter     int         // maximum jitter to add to delay (in ms)
	UserAgent       string      // custom user-agent
	Proxy           string      // proxy to use for requests
	Silence         bool        // suppress output from console
	Verbose         int         // verbosity level
	Resolvers       []string    // resolvers to use for DNS resolution
	FollowRedirects bool        // follow redirects
	Headers         StringSlice // custom headers to add to requests
	CLI             CLI         // CLI options
}

type CLI struct {
	Include          string // targets to be included (comma separated)
	Exclude          string // targets to be included (comma separated)
	Target           string // target host
	Infile           string // file containin targets (newline separated)
	ResolversFile    string // file containing resolvers (newline separated)
	Outfile          string // file to write results
	FilterStatusCode string // filter by status code (comma separated)
	FilterExtensions string // filter by extension (comma separated)
	HideStatusCodes  bool   // show status code
	HideMedia        bool   // hide images and fonts from output
	HideWarning      bool   // hide warnings
	Version          bool   // print version
	Help             bool   // print help
}

// Default returns the default options
func Default() *Options {
	return &Options{
		Concurrency:     20,
		Timeout:         10,
		Delay:           0,
		DelayJitter:     0,
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		FollowRedirects: true,
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

// String provides the string representation of the slice
func (s *StringSlice) String() string {
	return strings.Join(*s, ", ")
}

// Set appends a value to the slice
func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}
