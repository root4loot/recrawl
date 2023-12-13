// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/gookit/color"
	"github.com/root4loot/recrawl/pkg/options"
	"github.com/root4loot/recrawl/pkg/runner"
	"github.com/root4loot/recrawl/pkg/util"
)

type CLI struct {
	opts options.Options
}

const author = "@danielantonsen"

func main() {
	cli := newCLI()
	cli.initialize()
	r := runner.NewRunnerWithOptions(&cli.opts)

	if cli.hasStdin() {
		processStdinInput(cli, r)
	} else if cli.hasInfile() {
		processInfile(cli, r)
	} else if cli.hasTarget() {
		processTargets(cli, r)
	}
}

// processStdinInput processes the STDIN targets provided by the user
func processStdinInput(cli *CLI, r *runner.Runner) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cli.processResults(r)
		r.Run(scanner.Text())
	}
}

// processInfile processes the infile targets provided by the user
func processInfile(cli *CLI, r *runner.Runner) {
	targets, err := util.ReadFileLines(cli.opts.CLI.Infile)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	cli.processResults(r)
	r.Run(targets...)
}

// processTargets processes the CLI targets provided by the user
func processTargets(cli *CLI, r *runner.Runner) {
	targets := cli.getTargets()
	cli.processResults(r)

	if len(targets) > 1 {
		r.Run(targets...)
	} else {
		r.Run(targets[0])
	}
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
	c.opts.Include, c.opts.Exclude = c.setScope()
}

// processResults is a goroutine that processes the results as they come in
func (c *CLI) processResults(runner *runner.Runner) {
	go func() {
		for result := range runner.Results {
			// Check if HideStatusCodes is false
			if !runner.Options.CLI.HideStatusCodes {
				// Check if hasStatusCodeFilter is true
				if c.hasStatusCodeFilter() {
					// Split the FilterStatusCode into an array of codeFilters
					codeFilters := strings.Split(c.opts.CLI.FilterStatusCode, ",")
					// Check if codeFilters contains the string representation of result.StatusCode
					if filterStatusContains(codeFilters, strconv.Itoa(result.StatusCode)) {
						c.printWithColor(result.StatusCode, result.RequestURL)
					}
				} else {
					c.printWithColor(result.StatusCode, result.RequestURL)
				}
			} else {
				fmt.Printf("%s\n", result.RequestURL)
			}

			// Check if Outfile is not empty
			if runner.Options.CLI.Outfile != "" {
				c.appendToFile([]string{strconv.Itoa(result.StatusCode) + " " + result.RequestURL})
			}
		}
	}()
}

// print with color
func (c *CLI) printWithColor(statusCode int, url string) {
	switch statusCode {
	case 200:
		color.Greenf("%d %s\n", statusCode, url)
	case 404:
		if c.opts.Verbose > 1 {
			color.Redf("%d %s\n", statusCode, url)
		}
	default:
		color.Yellowf("%d %s\n", statusCode, url)
	}
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
		color.Redf("%s\n\n", "Missing Target")
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
		log.Fatalf("Could not open file: %v", err)
	}
	defer file.Close()

	for i := range lines {
		if _, err := file.WriteString(lines[i] + "\n"); err != nil {
			log.Fatalf("Could not write line to file: %v", err)
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
