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
	UseBruteforce   bool         // enable light directory/file bruteforcing
	BruteforceLevel string       // bruteforce intensity level: light, medium, heavy
	WordlistFiles   StringSlice  // custom wordlist files to use
	MineParams      bool         // enable parameter extraction
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
	BruteforceLevel  string // bruteforce intensity level: none, light, medium, heavy
	WordlistFiles    string // custom wordlist files (comma separated)
	MineParams       bool   // enable parameter extraction
	Version          bool   // print version
	Help             bool   // print help
}

func NewOptions() *Options {
	return &Options{
		Scope:           scope.NewScope(),
		Concurrency:     20,
		Timeout:         10,
		Delay:           0,
		DelayJitter:     0,
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		FollowRedirects: true,
		UseBruteforce:   true,
		BruteforceLevel: "light",
	}
}

func NewEmptyOptions() *Options { return &Options{} }

func (o *Options) ApplyDefaults() {
	d := NewOptions()

	if o.Concurrency == 0 {
		o.Concurrency = d.Concurrency
	}
	if o.Timeout == 0 {
		o.Timeout = d.Timeout
	}
	if o.Delay < 0 {
		o.Delay = d.Delay
	}
	if o.DelayJitter < 0 {
		o.DelayJitter = d.DelayJitter
	}
	if o.UserAgent == "" {
		o.UserAgent = d.UserAgent
	}
	if o.BruteforceLevel == "" {
		o.BruteforceLevel = d.BruteforceLevel
	}
}

func (o *Options) WithDefaults() *Options {
	o.ApplyDefaults()
	return o
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

func (s *StringSlice) String() string { return strings.Join(*s, ", ") }

func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}
