package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/root4loot/recrawl/pkg/options"
)

func (c *CLI) banner() {
	fmt.Println("\nrecrawl", version, "by", author)
}

func (c *CLI) usage() {
	// create a new tabwriter
	w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)

	// print the usage header
	fmt.Fprintln(w, "Usage:\t"+os.Args[0]+" [options] (-t <target> | -i <targets.txt>)")

	// print the targeting section
	fmt.Fprintln(w, "\nTARGETING:")
	fmt.Fprintf(w, "\t%s,\t%s\t  %s\t                       (%s)\t\n", "-t", "--target", "target domain/url", "comma-separated")
	fmt.Fprintf(w, "\t%s,\t%s\t  %s\t                       (%s)\t\n", "-i", "--infile", "file containing targets", "one per line")
	fmt.Fprintf(w, "\t%s,\t%s\t  %s\t                       (%s)\t\n", "-ih", "--include-host", "also crawls this host (if found)", "comma-separated")
	fmt.Fprintf(w, "\t%s,\t%s\t  %s\t                       (%s)\t\n", "-eh", "--exclude-host", "do not crawl this host (if found)", "comma-separated")

	// print the configurations section
	fmt.Fprintln(w, "\nCONFIGURATIONS:")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v)\n", "-c", "--concurrency", "number of concurrent requests", options.Default().Concurrency)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v seconds)\n", "-to", "--timeout", "max request timeout", options.Default().Timeout)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v milliseconds)\n", "-d", "--delay", "delay between requests", options.Default().Delay)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v milliseconds)\n", "-dj", "--delay-jitter", "max jitter between requests", options.Default().DelayJitter)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v)\n", "-sr", "--skip-redundant", "skip requests that only differ in parameter values", options.Default().SkipRedundant)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v)\n", "-ss", "--skip-same", "skip crawling responses that have the same response body", options.Default().SkipSameBody)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v)\n", "-ua", "--user-agent", "set user agent", "Mozilla/5.0")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v)\n", "-p", "--proxy", "set proxy", "none")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v)\n", "-r", "--resolvers", "file containing list of resolvers", "System DNS")

	// print the output section
	fmt.Fprintln(w, "\nOUTPUT:")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\t            (%s)\t\n", "-fs", "--filter-status", "filter by status code", "comma-separated")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\t            (%s)\t\n", "-fe", "--filter-ext", "filter by extension", "comma-separated")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\t              \t\n", "-v", "--verbose", "verbose output (use -vv for added verbosity)")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\n", "-o", "--outfile", "output results to given file")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\n", "-hs", "--hide-status", "hide status code from output")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\n", "-hw", "--hide-warning", "hide warnings from output")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\n", "-hm", "--hide-media", "hide media from output (images, fonts, etc.)")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\n", "-s", "--silence", "silence results from output")
	fmt.Fprintf(w, "\t%s,\t%s\t %s\n", "-h", "--help", "display help")
	fmt.Fprintf(w, "\t\t%s\t %s\n", "--version", "display version")

	// flush the tabwriter
	w.Flush()
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
	flag.StringVar(&opts.Proxy, "proxy", options.Default().Proxy, "")
	flag.StringVar(&opts.Proxy, "p", options.Default().Proxy, "")
	flag.StringVar(&opts.CLI.ResolversFile, "resolvers", "", "")
	flag.StringVar(&opts.CLI.ResolversFile, "r", "", "")
	flag.BoolVar(&opts.SkipRedundant, "skip-redundant", options.Default().SkipRedundant, "")
	flag.BoolVar(&opts.SkipRedundant, "sr", options.Default().SkipRedundant, "")
	flag.BoolVar(&opts.SkipSameBody, "skip-same", options.Default().SkipSameBody, "")
	flag.BoolVar(&opts.SkipSameBody, "ss", options.Default().SkipSameBody, "")

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
