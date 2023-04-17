// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/root4loot/urldiscover/pkg/log"
	"github.com/root4loot/urldiscover/pkg/options"
	"github.com/root4loot/urldiscover/pkg/runner"
	"github.com/root4loot/urldiscover/pkg/util"
)

type CLI struct {
	opts options.Options
}

const author = "@danielantonsen"

// processor is a goroutine that processes the results as they come in
func (c *CLI) processor(runner *runner.Runner) {
	go func() {
		for result := range runner.Results {
			if !runner.Options.CLI.Silence {
				if !runner.Options.CLI.HideStatusCodes {
					fmt.Printf("%d %s\n", result.StatusCode, result.RequestURL)
				} else {
					fmt.Printf("%s\n", result.RequestURL)
				}
			}
			if runner.Options.CLI.Outfile != "" {
				c.appendToFile([]string{strconv.Itoa(result.StatusCode) + " " + result.RequestURL})
			}
		}
	}()
}

func main() {
	var targets []string
	var err error
	cli := newCLI()
	cli.initialize()
	runner := runner.NewRunner(&cli.opts)

	if cli.hasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			cli.processor(runner)
			runner.Run(scanner.Text())
		}
	} else if cli.hasInfile() {
		if targets, err = util.ReadFileLines(cli.opts.CLI.Infile); err != nil {
			log.Fatalf("Error reading file: ", err)
		}
	} else if cli.hasTarget() {
		targets = cli.getTargets()
	}
	for _, target := range targets {
		cli.processor(runner)
		runner.Run(target)
	}
	// example.ExampleRun()
}

// newCLI returns a new CLI instance
func newCLI() *CLI {
	return &CLI{}
}

// initialize parses the command line options and sets the options
func (c *CLI) initialize() {
	// defaults = options.GetDefaultOptions()
	c.parseAndSetOptions()
	c.checkForExits()
	if c.opts.CLI.HideWarning {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	c.opts.Include, c.opts.Exclude = c.setScope()
}

// checkForExits checks for the presence of the -h|--help and -v|--version flags
func (c *CLI) checkForExits() {
	if c.opts.CLI.Help {
		c.banner()
		c.usage()
		os.Exit(0)
	}
	if c.opts.CLI.Version {
		fmt.Println("urldiscover ", version)
		os.Exit(0)
	}

	if !c.hasStdin() && !c.hasInfile() && !c.hasTarget() {
		log.Fatalf("%s", "Missing target -t|--target")
	}
}

// usage prints the usage information
func (c *CLI) usage() {
	fmt.Println("\nUsage: " + os.Args[0] + " [options] -t <target>")
	fmt.Printf("\n%s\n", "TARGETING:")
	fmt.Printf("  %s,  %s\t\t  %s  \t\t\t    (%s)\n", "-t", "--target", "target host", "comma-separated")
	fmt.Printf("  %s,  %s\t\t  %s \t    (%s)\n", "-i", "--infile", "file containing targets", "one per line")
	fmt.Printf("  %s, %s\t  %s   (%s)\n", "-ih", "--include-host", "also crawl this host (if found)", "comma-separated")
	fmt.Printf("  %s, %s\t  %s (%s)\n", "-eh", "--exclude-host", "do not crawl this host (if found)", "comma-separated")

	fmt.Printf("\n%s\n", "CONFIGURATIONS:")
	fmt.Printf("  %s,  %s\t  %s\t (Default: %v)\n", "-c", "--concurrency", "number of concurrent requests", options.Default().Concurrency)
	fmt.Printf("  %s, %s\t  %s\t\t (Default: %v) <%s>\n", "-to", "--timeout", "max request timeout", options.Default().Timeout, "seconds")
	fmt.Printf("  %s,  %s\t\t  %s\t (Default: %v)  <%s>\n", "-d", "--delay", "delay between requests", options.Default().Delay, "milliseconds")
	fmt.Printf("  %s, %s\t  %s\t (Default: %v)  <%s>\n", "-dj", "--delay-jitter", "max jitter between requests", options.Default().DelayJitter, "milliseconds")
	fmt.Printf("  %s, %s\t  %s\t (Default: %v) <%s>\n", "-ht", "--header-timeout", "response-header timeout", options.Default().ResponseHeaderTimeout, "seconds")
	fmt.Printf("  %s, %s\t  %s\t\t (Default: %v)\n", "-ua", "--user-agent", "set user agent", "urldiscover")

	fmt.Printf("\n%s\n", "OUTPUT:")
	fmt.Printf("  %s,  %s\t  %s\n", "-o", "--outfile", "output results to given file")
	fmt.Printf("  %s, %s\t  %s\n", "-hs", "--hide-status", "hide status code from output")
	fmt.Printf("  %s, %s\t  %s\n", "-hw", "--hide-warning", "hide warnings from output")
	fmt.Printf("  %s,  %s\t  %s\n", "-s", "--silence", "silence results from output")
	fmt.Printf("  %s,  %s\t  %s\n", "-v", "--version", "display version")
	fmt.Printf("  %s,  %s\t\t  %s\n", "-h", "--help", "display help")
	fmt.Println("")
}

// parseAndSetOptions parses the command line options and sets the options
func (c *CLI) parseAndSetOptions() {
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
	flag.IntVar(&opts.ResponseHeaderTimeout, "header-timeout", options.Default().ResponseHeaderTimeout, "")
	flag.IntVar(&opts.ResponseHeaderTimeout, "ht", options.Default().ResponseHeaderTimeout, "")
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

// getTargets returns the targets to be used for the scan
func (c *CLI) getTargets() (targets []string) {
	if c.hasTarget() {
		if strings.Contains(c.opts.CLI.Target, ",") {
			c.opts.CLI.Target = strings.ReplaceAll(c.opts.CLI.Target, " ", "")
			targets = strings.Split(c.opts.CLI.Target, ",")
		} else {
			targets = append(targets, c.opts.CLI.Target)
		}
	}
	return
}

// appendToFile appends the given lines to the given file
func (c *CLI) appendToFile(lines []string) {
	file, err := os.OpenFile(c.opts.CLI.Outfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	for i := range lines {
		if _, err := file.WriteString(lines[i] + "\n"); err != nil {
			log.Errorf("could not write line to file: %v", err)
		}
	}
}

// setScope sets the scope for the scan
func (c *CLI) setScope() (inc []string, exc []string) {
	return strings.Split(c.opts.CLI.Include, ","), strings.Split(c.opts.CLI.Exclude, ",")
}

// hasStdin determines if the user has piped input
func (c *CLI) hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	mode := stat.Mode()

	isPipedFromChrDev := (mode & os.ModeCharDevice) == 0
	isPipedFromFIFO := (mode & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

// hasTarget determines if the user has provided a target
func (c *CLI) hasTarget() bool {
	return c.opts.CLI.Target != ""
}

// hasInfile determines if the user has provided an input file
func (c *CLI) hasInfile() bool {
	return c.opts.CLI.Infile != ""
}

// hasOutfile determines if the user has provided an output file
func (c *CLI) hasOutfile() bool {
	return c.opts.CLI.Outfile != ""
}

// banner prints the banner
func (c *CLI) banner() {
	fmt.Println("\nurldiscover", version, "by", author)
}
