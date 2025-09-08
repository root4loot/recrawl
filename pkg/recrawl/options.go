// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package recrawl

import (
	"fmt"
	"log"
	"strings"

	"github.com/gookit/color"
	"github.com/root4loot/scope"
)

type StringSlice []string

// Options holds configuration for the crawler and CLI helpers
type Options struct {
	Scope           *scope.Scope // scope configuration
	Concurrency     int          // number of concurrent requests
	Timeout         int          // Request timeout duration (in seconds)
	Delay           int          // delay between each request (in ms)
	DelayJitter     int          // maximum jitter to add to delay (in ms)
	UserAgent       string       // custom user-agent
	Proxy           string       // proxy to use for requests
	Silence         bool         // suppress output from console
	Verbose         int          // verbosity level
	Resolvers       []string     // resolvers to use for DNS resolution
	FollowRedirects bool         // follow redirects
	Headers         StringSlice  // custom headers to add to requests
	PreferHTTP      bool         // prefer HTTP over HTTPS for non-schemed targets
	CLI             CLI          // CLI options
}

type CLI struct {
	Include          string // targets to be included (comma separated)
	Exclude          string // targets to be excluded (comma separated)
	Target           string // target host
	Infile           string // file containing targets (newline separated)
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

// NewOptions returns an Options struct initialized with default values.
func NewOptions() *Options {
	return &Options{
		Scope:           scope.NewScope(),
		Concurrency:     20,
		Timeout:         10,
		Delay:           0,
		DelayJitter:     0,
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		FollowRedirects: true,
	}
}

// NewEmptyOptions returns a new Options struct with zero-values (no defaults applied).
func NewEmptyOptions() *Options { return &Options{} }

// ApplyDefaults fills zero-value fields on the receiver with default values.
func (o *Options) ApplyDefaults() {
	d := NewOptions()

	// Concurrency
	if o.Concurrency == 0 {
		o.Concurrency = d.Concurrency
	}
	// Timeout
	if o.Timeout == 0 {
		o.Timeout = d.Timeout
	}
	// Delay and jitter
	// Note: keep 0 as valid values; only set if negative
	if o.Delay < 0 {
		o.Delay = d.Delay
	}
	if o.DelayJitter < 0 {
		o.DelayJitter = d.DelayJitter
	}
	// UserAgent
	if o.UserAgent == "" {
		o.UserAgent = d.UserAgent
	}
}

// WithDefaults applies defaults and returns the receiver for chaining.
func (o *Options) WithDefaults() *Options {
	o.ApplyDefaults()
	return o
}

// ValidateOptions validates the configuration values.
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

// String provides the string representation of the StringSlice
func (s *StringSlice) String() string { return strings.Join(*s, ", ") }

// Set appends a value to the StringSlice
func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}
