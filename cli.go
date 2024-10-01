// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/root4loot/goutils/color"
	"github.com/root4loot/goutils/fileutil"
	"github.com/root4loot/goutils/log"
	"github.com/root4loot/goutils/urlutil"
	"github.com/root4loot/recrawl/pkg/options"
	"github.com/root4loot/recrawl/pkg/runner"
)

type CLI struct {
	opts   options.Options
	logger *log.Logger
}

const author = "@danielantonsen"

func main() {
	cli := newCLI()
	cli.initialize()
	r := runner.NewRunnerWithOptions(&cli.opts)

	cli.logActiveOptions()

	if log.IsOutputPiped() {
		log.Notify(log.PipedOutputNotification)
	}

	if cli.hasStdin() {
		processStdinInput(cli, r)
	} else if cli.hasInfile() {
		processInfile(cli, r)
	} else if cli.hasTarget() {
		processTargets(cli, r)
	}
}

func processStdinInput(cli *CLI, r *runner.Runner) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cli.processResults(r)
		r.Run(scanner.Text())
	}
}

func processInfile(cli *CLI, r *runner.Runner) {
	targets, err := fileutil.ReadFile(cli.opts.CLI.Infile)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	cli.processResults(r)
	r.Run(targets...)
}

func processTargets(cli *CLI, r *runner.Runner) {
	targets := cli.getTargets()
	cli.processResults(r)

	if len(targets) > 1 {
		r.Run(targets...)
	} else {
		r.Run(targets[0])
	}
}

func newCLI() *CLI {
	return &CLI{}
}

func (c *CLI) initialize() {
	c.logger = log.NewLogger("recrawl")
	c.parseFlags()
	c.checkForExits()
	c.opts.Include, c.opts.Exclude = c.setScope()
}

func (c *CLI) processResults(runner *runner.Runner) {
	printedURLs := new(sync.Map)

	go func() {
		for result := range runner.Results {
			if c.shouldExcludeMediaURL(result.RequestURL) || c.shouldExcludeByExtension(result.RequestURL) {
				continue
			}

			if _, loaded := printedURLs.LoadOrStore(result.RequestURL, struct{}{}); loaded {
				continue
			}

			c.processStatusCode(result)
			if c.hasOutfile() {
				c.appendToFile([]string{strconv.Itoa(result.StatusCode) + " " + result.RequestURL})
			}
		}
	}()
}

func (c *CLI) shouldExcludeMediaURL(url string) bool {
	if c.hasHideMedia() && urlutil.IsMediaExt(urlutil.GetExt(url)) {
		log.Debugf("Excluding media URL from output: %s", url)
		return true
	}
	return false
}

func (c *CLI) shouldExcludeByExtension(url string) bool {
	if c.hasExtensionFilter() {
		extensions := strings.Split(c.opts.CLI.FilterExtensions, ",")
		if !filterUrlExtensionsContains(url, extensions) {
			log.Debugf("Excluding URL from output: %s", url)
			return true
		}
	}
	return false
}

func (c *CLI) processStatusCode(result runner.Result) {
	if !c.hasHideStatus() {
		if c.hasStatusCodeFilter() {
			codeFilters := strings.Split(c.opts.CLI.FilterStatusCode, ",")
			if filterStatusContains(codeFilters, strconv.Itoa(result.StatusCode)) {
				c.printWithColor(result.StatusCode, result.RequestURL)
			}
		} else {
			c.printWithColor(result.StatusCode, result.RequestURL)
		}
	} else {
		log.Result(result.RequestURL)
	}
}

func (c *CLI) printWithColor(statusCode int, url string) {
	switch {
	case statusCode >= 200 && statusCode < 300:
		log.Result(color.Colorize(color.Green, fmt.Sprintf("%d %s", statusCode, url)))
	case statusCode >= 300 && statusCode < 400:
		log.Result(color.Colorize(color.Orange, fmt.Sprintf("%d %s", statusCode, url)))
	case statusCode >= 400 && statusCode < 500:
		if c.opts.Verbose > 1 {
			log.Result(color.Colorize(color.Red, fmt.Sprintf("%d %s", statusCode, url)))
		}
	case statusCode >= 500:
		log.Result(color.Colorize(color.Purple, fmt.Sprintf("%d %s", statusCode, url)))
	case statusCode >= 100 && statusCode < 200:
		log.Result(color.Colorize(color.Blue, fmt.Sprintf("%d %s", statusCode, url)))
	default:
		log.Result(color.Colorize(color.LightGrey, fmt.Sprintf("%d %s", statusCode, url)))
	}
}

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
		fmt.Println(color.Red, "Missing target", color.Reset)
		c.usage()
	}
}

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

func (c *CLI) setScope() (inc []string, exc []string) {
	return strings.Split(c.opts.CLI.Include, ","), strings.Split(c.opts.CLI.Exclude, ",")
}

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

func (c *CLI) logActiveOptions() {
	tag := c.logger.NewLabel("OPTIONS")
	tag.SetColor(color.Red)

	if c.hasStatusCodeFilter() {
		tag.Logf("Included status codes: %s", c.opts.CLI.FilterStatusCode)
	}
	if c.hasExtensionFilter() {
		tag.Logf("Included extensions: %s", c.opts.CLI.FilterExtensions)
	}
	if c.hasHideStatus() {
		tag.Logf("Hiding status codes: %t", c.opts.CLI.HideStatusCodes)
	}
	if c.hasHideMedia() {
		tag.Logf("Hiding media: %v", urlutil.GetMediaExtensions())
	}
	if c.hasInfile() {
		tag.Logf("Input file: %s", c.opts.CLI.Infile)
	}
	if c.hasOutfile() {
		tag.Logf("Output file: %s", c.opts.CLI.Outfile)
	}
	if c.hasHideWarning() {
		tag.Logf("Hiding warnings: %t", c.opts.CLI.HideWarning)
	}
	if c.hasResolversFile() {
		tag.Logf("Resolvers file: %s", c.opts.CLI.ResolversFile)
	}
	if c.hasProxy() {
		tag.Logf("Proxy: %s", c.opts.Proxy)
	}
	if c.hasDelay() {
		tag.Logf("Delay: %d", c.opts.Delay)
	}
	if c.hasDelayJitter() {
		tag.Logf("Delay jitter: %d", c.opts.DelayJitter)
	}
	if c.hasConcurrency() {
		tag.Logf("Concurrency: %d", c.opts.Concurrency)
	}
	if c.hasTimeout() {
		tag.Logf("Timeout: %d seconds", c.opts.Timeout)
	}
}

func (c *CLI) hasStatusCodeFilter() bool {
	return c.opts.CLI.FilterStatusCode != ""
}

func (c *CLI) hasExtensionFilter() bool {
	return c.opts.CLI.FilterExtensions != ""
}

func (c *CLI) hasHideMedia() bool {
	return c.opts.CLI.HideMedia
}

func (c *CLI) hasHideStatus() bool {
	return c.opts.CLI.HideStatusCodes
}

func (c *CLI) hasInfile() bool {
	return c.opts.CLI.Infile != ""
}

func (c *CLI) hasOutfile() bool {
	return c.opts.CLI.Outfile != ""
}

func (c *CLI) hasHideWarning() bool {
	return c.opts.CLI.HideWarning
}

func (c *CLI) hasResolversFile() bool {
	return c.opts.CLI.ResolversFile != ""
}

func (c *CLI) hasProxy() bool {
	return c.opts.Proxy != ""
}

func (c *CLI) hasDelay() bool {
	return c.opts.Delay > 0
}

func (c *CLI) hasDelayJitter() bool {
	return c.opts.DelayJitter > 0
}

func (c *CLI) hasConcurrency() bool {
	return c.opts.Concurrency > 0
}

func (c *CLI) hasTimeout() bool {
	return c.opts.Timeout > 0
}

func (c *CLI) hasTarget() bool {
	return c.opts.CLI.Target != ""
}

func filterStatusContains(filterStatusCodes []string, statusCode string) bool {
	for _, code := range filterStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

func filterUrlExtensionsContains(url string, filterUrlExtensions []string) bool {
	for _, ext := range filterUrlExtensions {
		if strings.HasSuffix(url, "."+ext) {
			return true
		}
	}
	return false
}
