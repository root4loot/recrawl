package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/root4loot/urldiscover/pkg/options"
)

func (c *CLI) banner() {
	fmt.Println("\nurldiscover", version, "by", author)
}

func (c *CLI) usage() {
	// create a new tabwriter
	w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)

	// print the usage header
	fmt.Fprintln(w, "Usage:\t"+os.Args[0]+" [options] -t <target>")

	// print the targeting section
	fmt.Fprintln(w, "\nTARGETING:")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(%s)\n", "-t", "--target", "target host", "comma-separated")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(%s)\n", "-i", "--infile", "file containing targets", "one per line")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(%s)\n", "-ih", "--include-host", "also crawl this host (if found)", "comma-separated")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(%s)\n", "-eh", "--exclude-host", "do not crawl this host (if found)", "comma-separated")

	// print the configurations section
	fmt.Fprintln(w, "\nCONFIGURATIONS:")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v seconds)\n", "-c", "--concurrency", "number of concurrent requests", options.Default().Concurrency)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v seconds)\n", "-to", "--timeout", "max request timeout", options.Default().Timeout)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v milliseconds)\n", "-d", "--delay", "delay between requests", options.Default().Delay)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v milliseconds)\n", "-dj", "--delay-jitter", "max jitter between requests", options.Default().DelayJitter)
	fmt.Fprintf(w, "\t%s,\t%s\t%s\t(Default: %v)\n", "-ua", "--user-agent", "set user agent", "urldiscover")

	// print the output section
	fmt.Fprintln(w, "\nOUTPUT:")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\n", "-o", "--outfile", "output results to given file")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\n", "-hs", "--hide-status", "hide status code from output")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\n", "-hw", "--hide-warning", "hide warnings from output")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\n", "-s", "--silence", "silence results from output")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\n", "-v", "--version", "display version")
	fmt.Fprintf(w, "\t%s,\t%s\t%s\n", "-h", "--help", "display help")

	// flush the tabwriter
	w.Flush()
}

func (c *CLI) parseFlags() {
	opts := new(options.Options)

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

	// OUTPUT
	flag.BoolVar(&opts.CLI.Silence, "s", false, "")
	flag.BoolVar(&opts.CLI.Silence, "silence", false, "")
	flag.StringVar(&opts.CLI.Outfile, "o", "", "")
	flag.StringVar(&opts.CLI.Outfile, "outfile", "", "")
	flag.BoolVar(&opts.CLI.HideWarning, "hw", false, "")
	flag.BoolVar(&opts.CLI.HideWarning, "hide-warning", false, "")
	flag.BoolVar(&opts.CLI.HideStatusCodes, "hs", false, "")
	flag.BoolVar(&opts.CLI.HideWarning, "hide-status", false, "")
	flag.BoolVar(&opts.CLI.Help, "help", false, "")
	flag.BoolVar(&opts.CLI.Help, "h", false, "")
	flag.BoolVar(&opts.CLI.Version, "version", false, "")

	flag.Usage = func() {
		c.banner()
		c.usage()
	}

	flag.Parse()
	c.opts = *opts
}
