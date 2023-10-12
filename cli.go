// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/root4loot/recrawl/pkg/log"
	"github.com/root4loot/recrawl/pkg/options"
	"github.com/root4loot/recrawl/pkg/runner"
	"github.com/root4loot/recrawl/pkg/util"
)

type CLI struct {
	opts options.Options
}

const author = "@danielantonsen"

// processResults is a goroutine that processes the results as they come in
func (c *CLI) processResults(runner *runner.Runner) {
	go func() {
		for result := range runner.Results {
			if !runner.Options.CLI.Silence {
				if !runner.Options.CLI.HideStatusCodes {
					if c.hasStatusCodeFilter() {
						codeFilters := strings.Split(c.opts.CLI.FilterStatusCode, ",")
						if filterStatusContains(codeFilters, strconv.Itoa(result.StatusCode)) {
							fmt.Printf("%d %s\n", result.StatusCode, result.RequestURL)
						}
					} else {
						fmt.Printf("%d %s\n", result.StatusCode, result.RequestURL)
					}
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
			cli.processResults(runner)
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
		cli.processResults(runner)
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
	c.parseFlags()
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
		fmt.Println("recrawl ", version)
		os.Exit(0)
	}

	if !c.hasStdin() && !c.hasInfile() && !c.hasTarget() {
		fmt.Println("")
		log.Errorf("%s\n\n", "Missing target")
		c.usage()
	}
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

// hasStatusCodeFilter determines if the user has provided a status code filter
func (c *CLI) hasStatusCodeFilter() bool {
	return c.opts.CLI.FilterStatusCode != ""
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

// hasResolversFile determines if the user has provided a resolvers file
func (c *CLI) hasResolversFile() bool {
	return c.opts.CLI.ResolversFile != ""
}

// filterStatusContains determines if the given status code is in the filter
func filterStatusContains(filterStatusCodes []string, statusCode string) bool {
	for _, code := range filterStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}
