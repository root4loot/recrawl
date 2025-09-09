// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/root4loot/goutils/color"
	"github.com/root4loot/goutils/fileutil"
	"github.com/root4loot/goutils/log"
	"github.com/root4loot/goutils/urlutil"
	"github.com/root4loot/recrawl/pkg/recrawl"
	"github.com/root4loot/scope"
)

type CLI struct {
	opts   recrawl.Options
	logger *log.Logger
}

const author = "@danielantonsen"

func main() {
	cli := newCLI()
	cli.initialize()
	cli.logActiveOptions()

	if log.IsOutputPiped() {
		log.Notify(log.PipedOutputNotification)
	}

	if cli.hasStdin() {
		processStdinInput(cli)
	} else if cli.hasInfile() {
		processInfile(cli)
	} else if cli.hasTarget() {
		processTargets(cli)
	}
}

func processStdinInput(cli *CLI) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		r := recrawl.NewRecrawlWithOptions(&cli.opts)
		done := cli.processResults(r)
		r.Run(scanner.Text())
		<-done
	}
}

func processInfile(cli *CLI) {
	targets, err := fileutil.ReadFile(cli.opts.CLI.Infile)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	r := recrawl.NewRecrawlWithOptions(&cli.opts)
	done := cli.processResults(r)
	r.Run(targets...)
	<-done
}

func processTargets(cli *CLI) {
	targets := cli.getTargets()
	r := recrawl.NewRecrawlWithOptions(&cli.opts)
	done := cli.processResults(r)

	if len(targets) > 1 {
		r.Run(targets...)
	} else {
		r.Run(targets[0])
	}
	<-done
}

func newCLI() *CLI {
	return &CLI{}
}

func (c *CLI) initialize() {
	c.logger = log.NewLogger("recrawl")
	c.parseFlags()
	c.checkForExits()
	c.opts.Scope = c.setScope()
	c.processCliOptions()
}

func (c *CLI) processCliOptions() {
	c.opts.MineParams = c.opts.CLI.MineParams
	c.opts.EnableDiscovery = c.opts.CLI.EnableDiscovery
	c.loadResolvers()
}

func (c *CLI) loadResolvers() {
	if c.hasResolversFile() {
		resolvers, err := fileutil.ReadFile(c.opts.CLI.ResolversFile)
		if err != nil {
			log.Fatalf("Error reading resolvers file: %v", err)
		}
		c.opts.Resolvers = resolvers
		log.Debugf("Loaded %d resolvers from file", len(resolvers))
	}
}

func (c *CLI) processResults(runner *recrawl.Crawler) chan struct{} {
	printedURLs := new(sync.Map)
	done := make(chan struct{})

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

		if c.opts.MineParams {
			c.displayParameters(runner)
		}
		close(done)
	}()
	return done
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

func (c *CLI) processStatusCode(result recrawl.Result) {
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

func (c *CLI) setScope() *scope.Scope {
	s := scope.NewScope()
	// Includes
	if c.opts.CLI.Include != "" {
		inc := strings.Split(strings.ReplaceAll(c.opts.CLI.Include, " ", ""), ",")
		var filtered []string
		for _, v := range inc {
			if v != "" {
				filtered = append(filtered, v)
			}
		}
		_ = s.AddIncludes(filtered)
	}
	// Excludes
	if c.opts.CLI.Exclude != "" {
		exc := strings.Split(strings.ReplaceAll(c.opts.CLI.Exclude, " ", ""), ",")
		var filtered []string
		for _, v := range exc {
			if v != "" {
				filtered = append(filtered, v)
			}
		}
		_ = s.AddExcludes(filtered)
	}
	return s
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
	if c.opts.MineParams {
		tag.Logf("Parameter mining: enabled")
	}
	if c.opts.Scope != nil {
		inc := c.opts.Scope.GetIncludes()
		exc := c.opts.Scope.GetExcludes()
		if len(inc) > 0 {
			tag.Logf("Scope includes: %s", strings.Join(inc, ","))
		}
		if len(exc) > 0 {
			tag.Logf("Scope excludes: %s", strings.Join(exc, ","))
		}
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

func (c *CLI) displayParameters(runner *recrawl.Crawler) {
	uniq := runner.ParamMiner.GetUniqueParams()
	if len(uniq) == 0 {
		return
	}

	byCert := map[string]map[string]struct{}{
		recrawl.CertaintyHigh:   {},
		recrawl.CertaintyMedium: {},
		recrawl.CertaintyLow:    {},
	}
	for _, p := range uniq {
		if _, ok := byCert[p.Certainty]; ok {
			byCert[p.Certainty][p.Name] = struct{}{}
		}
	}

	// helper to convert set->sorted list
	toSorted := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	if names := toSorted(byCert[recrawl.CertaintyHigh]); len(names) > 0 {
		label := color.Colorize(color.Green, "params-certainty-high")
		log.Result(label + ": " + strings.Join(names, ", "))
	}
	if names := toSorted(byCert[recrawl.CertaintyMedium]); len(names) > 0 {
		label := color.Colorize(color.Orange, "params-certainty-medium")
		log.Result(label + ": " + strings.Join(names, ", "))
	}
	if names := toSorted(byCert[recrawl.CertaintyLow]); len(names) > 0 {
		label := color.Colorize(color.Red, "params-certainty-low")
		log.Result(label + ": " + strings.Join(names, ", "))
	}
}
