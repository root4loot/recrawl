package main

import (
	"flag"
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/root4loot/recrawl/pkg/options"
)

type UsageData struct {
	AppName                string
	DefaultConcurrency     int
	DefaultTimeout         int
	DefaultDelay           int
	DefaultDelayJitter     int
	DefaultFollowRedirects bool
}

const usageTemplate = `
Usage:
  {{.AppName}} [options] (-t <target> | -I <targets.txt>)

TARGETING:
  -i, --infile         file containing targets                   (one per line)
  -t, --target         target domain/url                         (comma-separated)
  -ih, --include-host  also crawls this host (if found)          (comma-separated)
  -eh, --exclude-host  do not crawl this host (if found)         (comma-separated)

CONFIGURATIONS:
  -c, --concurrency       number of concurrent requests          (Default: {{.DefaultConcurrency}})
  -to, --timeout          max request timeout                    (Default: {{.DefaultTimeout}} seconds)
  -d, --delay             delay between requests                 (Default: {{.DefaultDelay}} milliseconds)
  -dj, --delay-jitter     max jitter between requests            (Default: {{.DefaultDelayJitter}} milliseconds)
  -ua, --user-agent       set user agent                         (Default: Mozilla/5.0)
  -fr, --follow-redirects follow redirects                       (Default: {{.DefaultFollowRedirects}})
  -p, --proxy             set proxy                              (Default: none)
  -r, --resolvers         file containing list of resolvers      (Default: System DNS)
  -H, --header            set custom header                      (Default: none)

OUTPUT:
  -fs, --filter-status    filter by status code                  (comma-separated)
  -fe, --filter-ext       filter by extension                    (comma-separated)
  -v, --verbose           verbose output                         (use -vv for added verbosity)
  -o, --outfile           output results to given file
  -hs, --hide-status      hide status code from output
  -hw, --hide-warning     hide warnings from output
  -hm, --hide-media       hide media from output (images, fonts, etc.)
  -s, --silence           silence results from output
  -h, --help              display help
      --version           display version
`

func (c *CLI) banner() {
	fmt.Println("\nrecrawl", version, "by", author)
}

func (c *CLI) usage() {
	data := UsageData{
		AppName:                os.Args[0],
		DefaultConcurrency:     options.Default().Concurrency,
		DefaultTimeout:         options.Default().Timeout,
		DefaultDelay:           options.Default().Delay,
		DefaultDelayJitter:     options.Default().DelayJitter,
		DefaultFollowRedirects: options.Default().FollowRedirects,
	}

	tmpl, err := template.New("usage").Parse(usageTemplate)
	if err != nil {
		panic(err)
	}

	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}

func (c *CLI) parseFlags() {
	opts := new(options.Options)

	var verbose bool

	// TARGET
	flag.StringVar(&opts.CLI.Target, "target", "", "")
	flag.StringVar(&opts.CLI.Target, "t", "", "")
	flag.StringVar(&opts.CLI.Infile, "i", "", "")
	flag.StringVar(&opts.CLI.Infile, "infile", "", "")

	// FILTERING
	flag.StringVar(&opts.CLI.Include, "include-host", "", "")
	flag.StringVar(&opts.CLI.Include, "ih", "", "")
	flag.StringVar(&opts.CLI.Exclude, "exclude-host", "", "")
	flag.StringVar(&opts.CLI.Exclude, "eh", "", "")

	// CONFIGURATIONS
	flag.IntVar(&opts.Concurrency, "concurrency", options.Default().Concurrency, "")
	flag.IntVar(&opts.Concurrency, "c", options.Default().Concurrency, "")
	flag.IntVar(&opts.Timeout, "timeout", options.Default().Timeout, "")
	flag.IntVar(&opts.Timeout, "to", options.Default().Timeout, "")
	flag.IntVar(&opts.Delay, "delay", options.Default().Delay, "")
	flag.IntVar(&opts.Delay, "d", options.Default().Delay, "")
	flag.IntVar(&opts.DelayJitter, "delay-jitter", options.Default().DelayJitter, "")
	flag.IntVar(&opts.DelayJitter, "dj", options.Default().DelayJitter, "")
	flag.StringVar(&opts.UserAgent, "user-agent", options.Default().UserAgent, "")
	flag.StringVar(&opts.UserAgent, "ua", options.Default().UserAgent, "")
	flag.BoolVar(&opts.FollowRedirects, "follow-redirects", options.Default().FollowRedirects, "")
	flag.BoolVar(&opts.FollowRedirects, "fr", options.Default().FollowRedirects, "")
	flag.StringVar(&opts.Proxy, "proxy", options.Default().Proxy, "")
	flag.StringVar(&opts.Proxy, "p", options.Default().Proxy, "")
	flag.StringVar(&opts.CLI.ResolversFile, "resolvers", "", "")
	flag.StringVar(&opts.CLI.ResolversFile, "r", "", "")
	flag.Var(&opts.Headers, "header", "")
	flag.Var(&opts.Headers, "H", "")

	// OUTPUT
	flag.BoolVar(&opts.Silence, "s", false, "")
	flag.BoolVar(&opts.Silence, "silence", false, "")
	flag.BoolVar(&verbose, "v", false, "")
	flag.BoolVar(&verbose, "vv", false, "")
	flag.IntVar(&opts.Verbose, "verbose", 0, "")
	flag.StringVar(&opts.CLI.Outfile, "o", "", "")
	flag.StringVar(&opts.CLI.Outfile, "outfile", "", "")
	flag.StringVar(&opts.CLI.FilterStatusCode, "filter-status", "", "")
	flag.StringVar(&opts.CLI.FilterStatusCode, "fs", "", "")
	flag.StringVar(&opts.CLI.FilterExtensions, "filter-ext", "", "")
	flag.StringVar(&opts.CLI.FilterExtensions, "fe", "", "")
	flag.BoolVar(&opts.CLI.HideWarning, "hw", false, "")
	flag.BoolVar(&opts.CLI.HideWarning, "hide-warning", false, "")
	flag.BoolVar(&opts.CLI.HideStatusCodes, "hs", false, "")
	flag.BoolVar(&opts.CLI.HideStatusCodes, "hide-status", false, "")
	flag.BoolVar(&opts.CLI.HideMedia, "hm", false, "")
	flag.BoolVar(&opts.CLI.HideMedia, "hide-media", false, "")
	flag.BoolVar(&opts.CLI.Help, "help", false, "")
	flag.BoolVar(&opts.CLI.Help, "h", false, "")
	flag.BoolVar(&opts.CLI.Version, "version", false, "")

	flag.Usage = func() {
		c.banner()
		c.usage()
	}

	flag.Parse()
	c.opts = *opts

	// Manually check for verbose flags
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-v") {
			c.opts.Verbose = len(strings.TrimPrefix(arg, "-"))
		}
	}

}
