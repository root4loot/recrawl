// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package runner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/purell"
	"github.com/glaslos/ssdeep"
	"github.com/root4loot/goscope"
	"github.com/root4loot/goutils/domainutil"
	"github.com/root4loot/goutils/httputil"
	"github.com/root4loot/goutils/log"
	"github.com/root4loot/goutils/sliceutil"
	"github.com/root4loot/goutils/urlutil"
	"github.com/root4loot/recrawl/pkg/options"
	"github.com/root4loot/recrawl/pkg/util"
)

var (
	re_path    = regexp.MustCompile(`(?:"|')(?:(((?:[a-zA-Z]{1,10}:(?:\\)?/(?:\\)?/|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']*)|((?:/|\.\./|\./|\\/)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]*[^"'><,;|()]*))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]*\.[a-zA-Z0-9_]+(?:[\?|#][^"|']*)?)|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']*)?)|([a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_]{1,})+)|([a-zA-Z0-9_\-/]+/))(?:"|')`)
	re_robots  = regexp.MustCompile(`(?:Allow|Disallow): \s*(.*)`)
	hostHashes = make(map[string]map[string]bool) // Map of host to map of hash to bool
)

type Runner struct {
	Options *options.Options
	Results chan Result
	Scope   *goscope.Scope
	client  *http.Client
}

type Result struct {
	RequestURL string
	StatusCode int
	Error      error
}

type Results struct {
	Results []Result
}

var (
	visitedURL  sync.Map
	visitedHost sync.Map
)

func init() {
	log.Init("recrawl")
}

// NewRunnerWithDefaults creates a new runner with default options
func NewRunnerWithDefaults() *Runner {
	return newRunner(options.Default())
}

// NewRunnerWithOptions creates a new runner with options
func NewRunnerWithOptions(o *options.Options) *Runner {
	return newRunner(o)
}

// newRunner creates a new runner with given options
func newRunner(o *options.Options) *Runner {
	runner := &Runner{
		Results: make(chan Result),
		Options: o,
	}

	runner.setLogLevel()
	runner.initializeScope()
	runner.client = NewHTTPClient(o).client

	return runner
}

// Run handles single or multiple targets based on the number of targets provided
func (r *Runner) Run(targets ...string) {
	log.Debug("Run() called!") // Debug log

	r.Options.ValidateOptions()
	r.Options.SetDefaultsMissing()
	c_queue, c_urls, c_wait := r.InitializeWorkerPool()

	log.Debug("number of targets: ", len(targets))

	for _, target := range targets {
		mainTarget, err := r.initializeTargetProcessing(target)
		if err != nil {
			log.Warn("Error preparing target:", err)
			continue
		}

		logInfo("Crawling target:", mainTarget.String())
		go r.queueURL(c_queue, mainTarget)
	}

	// If only one target is provided, set concurrency to 1
	if len(targets) == 1 {
		r.Options.Concurrency = 1
	}

	log.Debug("starting workers")
	r.startWorkers(c_urls, c_queue, c_wait)
}

// InitializeWorkerPool creates a queue of URLs to be processed by workers
func (r *Runner) InitializeWorkerPool() (chan<- *url.URL, <-chan *url.URL, chan<- int) {
	c_wait := make(chan int)
	c_urls := make(chan *url.URL)
	c_queue := make(chan *url.URL)
	queueCount := 0

	// Initialize timeout duration
	timeoutDuration := time.Second * 7 // gracefully close after 10 seconds of inactivity

	go func() {
		for delta := range c_wait {
			queueCount += delta
			if queueCount == 0 {
				close(c_queue)
				close(c_wait)
			}
		}
	}()

	go func() {
		timeoutTimer := time.NewTimer(timeoutDuration) // Create a new timer
		defer timeoutTimer.Stop()

		for {
			select {
			case q := <-c_queue:
				if q != nil {
					if r.Scope.IsTargetInScope(q.Host) && !r.isVisitedURL(q.String()) {
						c_urls <- q
					}
					// Only reset the timer if there's activity on c_queue
					if !timeoutTimer.Stop() {
						<-timeoutTimer.C
					}
					timeoutTimer.Reset(timeoutDuration)
				}
			case <-c_urls:
				// No timer reset here
			case <-timeoutTimer.C:
				log.Debug("Timeout reached, closing channels.")
				close(c_urls)
				return
			}
		}
	}()

	return c_queue, c_urls, c_wait
}

// initializeTargetProcessing initializes the target processing
// ensures the target is reachable and adds it to the processing scope
func (r *Runner) initializeTargetProcessing(target string) (*url.URL, error) {
	// Check if the target already includes a scheme
	if !strings.Contains(target, "://") {
		// If no scheme is present, use FindScheme to determine and prepend it
		scheme, _, err := httputil.FindScheme(target)
		if err != nil {
			return nil, err
		}
		target = scheme + "://" + target
	}

	// Now that the target has a scheme, parse it
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	// Normalize the target by removing the default port if it's explicitly specified
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		// Reconstruct the target without the default port
		target = u.Scheme + "://" + u.Hostname()
	}

	if urlutil.HasScheme(u.Host) {
		r.Scope.AddInclude(u.Host)
	} else {
		r.Scope.AddInclude("*."+u.Host, u.Host)
	}

	// Add target to the scope if it hasn't been visited
	if !r.isVisitedHost(u.Hostname()) {
		r.addVisitedHost(u.Hostname()) // Mark as visited
	}

	// Parse the potentially modified target again to reflect any changes made
	u, err = url.Parse(target)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// initializeScope initializes the scope
func (r *Runner) initializeScope() {
	if r.Scope == nil {
		r.Scope = goscope.NewScope()
	}

	// add includes
	for _, include := range r.Options.Include {
		r.Scope.AddInclude(include)
	}

	// add excludes
	for _, exclude := range r.Options.Exclude {
		r.Scope.AddExclude(exclude)
	}
}

// startWorkers starts the workers
func (r *Runner) startWorkers(c_urls <-chan *url.URL, c_queue chan<- *url.URL, c_wait chan<- int) {

	var wg sync.WaitGroup
	for i := 0; i < r.Options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Worker(c_urls, c_queue, c_wait, r.Results)
		}()
	}
	wg.Wait()
}

// queueURL adds a URL to the queue
func (r *Runner) queueURL(c_queue chan<- *url.URL, url *url.URL) {
	url, err := url.Parse(r.cleanURL(url.String()))
	if err == nil {
		c_queue <- url
	}
}

// worker is a worker that processes URLs from the queue
func (r *Runner) Worker(c_urls <-chan *url.URL, c_queue chan<- *url.URL, c_wait chan<- int, c_result chan<- Result) {
	for c_url := range c_urls {

		var rawURLs []string
		if c_url == nil || c_url.Host == "" {
			continue
		} else {
			log.Debugf("Processing %s", c_url)
		}

		if r.shouldAddRobotsTxt(c_url) {
			r.addRobotsTxtToQueue(c_url, c_queue, c_wait)
		}

		// avoid example.com/foo/bar/foo/bar/foo/bar
		if r.isTrapped(c_url.Path) {
			log.Infof("Skipping URL (trapped in loop): %s", c_url.String())
			continue
		}

		// skip URLs that only differ in parameter values
		if r.isRedundantURL(c_url.String()) {
			log.Infof("Skipping URL (redundant): %s", c_url.String())
			continue
		}

		_, resp, err := r.request(c_url)

		if resp == nil {
			continue
		}

		if httputil.IsBinaryResponse(resp) || resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			r.Results <- Result{RequestURL: c_url.String(), StatusCode: resp.StatusCode, Error: nil}
		}

		if err != nil {
			if !strings.Contains(err.Error(), "already visited") {
				log.Infof("%v", err.Error())
				r.Results <- Result{RequestURL: c_url.String(), StatusCode: 0, Error: err}
			}
			continue
		}

		// Skip processing similar content if the option is set
		if !shouldProcessSimilarContent(c_url.Host, resp) {
			continue
		}

		landingURL := resp.Request.URL.String()

		paths, err := r.scrape(resp)

		if err != nil {
			log.Warnf("Failed to scrape %s: %v", landingURL, err)
			continue
		}

		rawURLs, err = r.setURL(landingURL, paths)

		if err != nil {
			log.Warnf("%v", err)
			continue
		}

		for i := range rawURLs {
			u, err := url.Parse(rawURLs[i])

			if err != nil {
				log.Warnf("%v", err)
				continue
			}

			// Skip paths that have two or more dots
			if strings.Count(u.Path, ".") >= 2 {
				continue
			}

			time.Sleep(r.getDelay() * time.Millisecond)
			go r.queueURL(c_queue, u)
		}
		r.Results <- Result{RequestURL: c_url.String(), StatusCode: resp.StatusCode, Error: nil}
	}
}

// shouldAddRobotsTxt checks if robots.txt should be added to the queue for a given URL
func (r *Runner) shouldAddRobotsTxt(c_url *url.URL) bool {
	// Check if the URL path is either empty or "/" and not already pointing to robots.txt
	// and ensure it hasn't been visited yet
	return (c_url.Path == "" || c_url.Path == "/") && !strings.HasSuffix(c_url.Path, "robots.txt") && !r.isVisitedURL(c_url.String()+"/robots.txt")
}

// addRobotsTxtToQueue adds the robots.txt file to the queue for a given URL
func (r *Runner) addRobotsTxtToQueue(c_url *url.URL, c_queue chan<- *url.URL, c_wait chan<- int) {
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", c_url.Scheme, c_url.Host)
	robotsParsedURL, err := url.Parse(robotsURL)
	if err == nil {
		time.Sleep(r.getDelay() * time.Millisecond)
		c_wait <- 1
		go r.queueURL(c_queue, robotsParsedURL)
	}
}

// shouldProcessSimilarContent checks if a page should be processed based on the fuzzy hash of the response body
func shouldProcessSimilarContent(host string, resp *http.Response) bool {
	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return false
	}
	// It's important to reset the response body so it can be read again later
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Generate a fuzzy hash of the response body
	hash, _ := ssdeep.FuzzyBytes(bodyBytes)

	// Initialize the nested map if not already done
	if hostHashes[host] == nil {
		hostHashes[host] = make(map[string]bool)
	}

	// Check the similarity of the new hash against existing hashes for the host
	for existingHash := range hostHashes[host] {
		score, _ := ssdeep.Distance(existingHash, hash)

		// Threshold for considering content the same
		if score > 95 {
			log.Info("Skipping page as similar content has been processed: ", resp.Request.URL.String())
			return false
		}
	}

	// If no similar hash exists, store the new hash and proceed
	hostHashes[host][hash] = true
	return true
}

// request makes a request to a URL
func (r *Runner) request(u *url.URL) (req *http.Request, resp *http.Response, err error) {
	log.Debug("Requesting ", u.String())

	// Check if URL has already been visited
	if r.isVisitedURL(u.String()) {
		return nil, nil, nil
	}

	// add visited
	r.addVisitedURL(u.String())

	req, err = http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return
	}

	if r.Options.UserAgent != "" {
		req.Header.Add("User-Agent", r.Options.UserAgent)
	}

	// Only follow redirects if the new URL has not been visited
	r.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}

		nextURL, err := req.URL.Parse(req.Response.Header.Get("Location"))
		if err != nil {
			return err
		}

		if !r.isVisitedURL(nextURL.String()) {
			r.addVisitedURL(nextURL.String())
			return nil
		}

		return errors.New("already visited")
	}

	resp, err = r.client.Do(req)

	if err != nil {
		if strings.Contains(fmt.Sprint(err), "gave HTTP response to HTTPS client") {
			u.Scheme = strings.Replace(u.Scheme, "https://", "http://", 1)
			r.request(u)
		}
	}
	return
}

// setURL sets the URL for a request
func (r *Runner) setURL(rawURL string, paths []string) (rawURLs []string, err error) {
	log.Debugf("Setting URL for %s", rawURL)

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	for _, path := range paths {
		if r.shouldSkipPath(u, path) || util.IsBinaryString(path) || !util.IsPrintable(path) {
			continue
		}

		if util.IsFile(path) {
			rawURLs = append(rawURLs, rawURL+"/"+path)
		}

		// Skip paths that have two or more dots
		if strings.Count(u.Path, ".") >= 2 {
			continue
		}

		formattedURL := formatURL(u, path)
		normaizedURL, _ := r.normalizeURLString(formattedURL)
		rawURLs = append(rawURLs, normaizedURL)
	}

	return
}

func (r *Runner) shouldSkipPath(u *url.URL, path string) bool {
	return path == u.Host || r.isMedia(path) || path == "" || strings.HasSuffix(u.Host, path)
}

func formatURL(u *url.URL, path string) string {
	path = strings.ReplaceAll(path, "\\", "") // Remove backslashes

	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http") && strings.Contains(path, ".") {
		path = "/" + path
	}

	// if util.HasFile(u.String()) && u.Path == "/robots.txt" {
	// 	return u.String()
	// }

	if urlutil.HasScheme(path) || domainutil.IsValidDomain(path) || strings.HasPrefix(path, "//") {
		return path
	}

	if strings.ContainsAny(path, ".") {
		if strings.HasPrefix(path, "/") {
			return u.Scheme + "://" + u.Host + path
		} else {
			return u.String() + "/" + path
		}
	}

	if strings.HasPrefix(path, "/") && strings.ContainsAny(path, ".") {
		return u.Scheme + "://" + u.Host + path
	}

	if strings.HasPrefix(path, "/") {
		return u.Scheme + "://" + u.Host + path + "/"
	}

	if util.HasFile(path) || util.HasParam(path) {
		return u.Scheme + "://" + u.Host + u.Path + "/" + path
	}

	return u.Scheme + "://" + u.Host + u.Path + "/" + path + "/"
}

// scrape scrapes a response for paths
func (r *Runner) scrape(resp *http.Response) ([]string, error) {
	log.Debugf("Scraping %s", resp.Request.URL.String())

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(resp.Request.URL.String(), "robots.txt") {
		return r.scrapeRobotsTxt(body), nil
	}

	return r.scrapePaths(body), nil
}

// scrapeRobotsTxt handles the scraping of robots.txt files
func (r *Runner) scrapeRobotsTxt(body []byte) []string {
	var res []string
	// Match a forward slash followed by a dot and an extension
	reExtension := regexp.MustCompile(`/\.[a-z0-9]+$`)

	matches := re_robots.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		path := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(match[1]), "*", ""), "$", "")
		path = strings.TrimSuffix(path, "?")
		path = reExtension.ReplaceAllString(path, "/")

		if len(path) > 1 {
			res = append(res, path)
		}
	}
	return sliceutil.Unique(res)
}

// scrapePaths handles the scraping of general paths
func (r *Runner) scrapePaths(body []byte) []string {
	var res []string
	matches := re_path.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		for _, path := range match {
			if path != "" {
				res = append(res, r.removeQuotes(path))
			}
		}
	}
	return sliceutil.Unique(res)
}

// URL normalization flag rules
const normalizationFlags purell.NormalizationFlags = purell.FlagRemoveDefaultPort |
	purell.FlagLowercaseScheme |
	purell.FlagLowercaseHost |
	purell.FlagDecodeDWORDHost |
	purell.FlagDecodeOctalHost |
	purell.FlagDecodeHexHost |
	purell.FlagRemoveUnnecessaryHostDots |
	purell.FlagRemoveTrailingSlash |
	purell.FlagRemoveDotSegments |
	purell.FlagRemoveDuplicateSlashes |
	purell.FlagUppercaseEscapes |
	purell.FlagRemoveEmptyPortSeparator |
	purell.FlagDecodeUnnecessaryEscapes |
	purell.FlagRemoveTrailingSlash |
	purell.FlagEncodeNecessaryEscapes |
	purell.FlagSortQuery

// normalizeURLString normalizes a URL string
func (r *Runner) normalizeURLString(rawURL string) (normalizedURL string, err error) {
	// Replace backslashes with their percent-encoded form
	normalizedURL = strings.ReplaceAll(rawURL, `\`, `%5C`)
	normalizedURL, err = purell.NormalizeURLString(normalizedURL, normalizationFlags)
	return normalizedURL, err
}

func (r *Runner) isMedia(path string) bool {
	mimes := []string{"audio/", "application/", "font/", "image/", "multipart/", "text/", "video/"}
	for _, mime := range mimes {
		if strings.HasPrefix(path, mime) {
			return true
		}
	}
	return false
}

// returns true if path contains words of high occurence
func (r *Runner) isTrapped(path string) bool {
	var tot int
	parts := strings.Split(path, "/")
	if len(parts) >= 10 {
		for _, part := range parts[1:] {
			if part != "" {
				tot += strings.Count(path, part)
			}
		}
		return tot/len(parts) >= 3
	}
	return false
}

// delay returns total delay from options
func (r *Runner) getDelay() time.Duration {
	if r.Options.DelayJitter != 0 {
		return time.Duration(r.Options.Delay + rand.Intn(r.Options.DelayJitter))
	}
	return time.Duration(r.Options.Delay)
}

// addVisitedURL adds a URL to the visitedURL sync.Map
func (r *Runner) addVisitedURL(key string) {
	visitedURL.Store(key, true)
}

// addVisitedHost adds a host to the visitedHost sync.Map
func (r *Runner) addVisitedHost(key string) {
	visitedHost.Store(key, true)
}

// isVisitedURL checks if a URL has been visited
func (r *Runner) isVisitedURL(key string) bool {
	_, ok := visitedURL.Load(key)
	return ok
}

// isVisitedHost checks if a host has been visited
func (r *Runner) isVisitedHost(key string) bool {
	_, ok := visitedHost.Load(key)
	return ok
}

// cleanURL cleans a domain for use in a URL
func (r *Runner) cleanURL(url string) string {
	url = util.TrimDoubleSlashes(url)
	url = util.EnsureScheme(url)
	url = util.AddSlashIfNeeded(url)
	url = util.RemoveSlashUnwanted(url)
	return url
}

// isRedundantURL determines if a given URL has already been encountered with only query parameter differences.
// It checks for two scenarios:
//  1. If the URL has no query parameters, it verifies if the path has been visited.
//  2. If the URL has query parameters, it compares the base URL (excluding parameters) and parameter names
//     with previously visited URLs to determine if it's essentially the same page that has been visited.
//
// This helps in avoiding re-processing of pages that have already been parsed but might have different
// parameter values in the URL.
func (r *Runner) isRedundantURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Normalize the URL path
	u.Path = path.Clean(u.Path)

	if u.RawQuery == "" {
		// Check if the URL without query parameters is already visited
		return r.isVisitedURL(u.String())
	} else {
		// Extract and sort query parameter names
		params := u.Query()
		var paramNames []string
		for name := range params {
			paramNames = append(paramNames, name)
		}
		sort.Strings(paramNames)

		// Create the canonical URL without query parameters
		u.RawQuery = ""
		canonicalURL := u.String()

		// Check if a URL with the same base path and parameter names has been visited
		foundAlias := false
		visitedURL.Range(func(key, value interface{}) bool {
			visitedURLStr, ok := key.(string)
			if !ok {
				return true // Continue iteration
			}

			visitedURL, err := url.Parse(visitedURLStr)
			if err != nil {
				return true // Continue iteration
			}

			// Normalize the visited URL path
			visitedURL.Path = path.Clean(visitedURL.Path)

			// Check if base URLs match
			visitedURL.RawQuery = ""
			if visitedURL.String() != canonicalURL {
				return true // Continue iteration, not the same base URL
			}

			// Extract and sort visited URL query parameter names
			visitedParams := visitedURL.Query()
			var visitedParamNames []string
			for name := range visitedParams {
				visitedParamNames = append(visitedParamNames, name)
			}
			sort.Strings(visitedParamNames)

			// Check if parameter names match
			if reflect.DeepEqual(paramNames, visitedParamNames) {
				foundAlias = true
				return false // Stop iteration
			}

			return true // Continue iteration
		})

		return foundAlias
	}
}

// removeQuotes takes a string as input and removes single and double quotes if they are both prefixed and trailing.
func (r *Runner) removeQuotes(input string) string {
	if len(input) < 2 {
		return input
	}

	// Check if the string starts and ends with quotes (single or double)
	if (input[0] == '"' && input[len(input)-1] == '"') || (input[0] == '\'' && input[len(input)-1] == '\'') {
		// Remove the first and last characters (quotes) from the string
		return input[1 : len(input)-1]
	}
	return input
}

// setLogLevel sets the log level based on user-defined flags
func (r *Runner) setLogLevel() {
	if r.Options.Verbose == 1 {
		log.SetLevel(log.InfoLevel) // Set log level to Info if Verbose is set to 1
	} else if r.Options.Verbose == 2 {
		log.SetLevel(log.DebugLevel) // Set log level to Debug if Verbose is set to 2
	} else if r.Options.Silence {
		log.SetLevel(log.FatalLevel) // Set log level to Fatal if Silence flag is set; only fatal errors will be logged
	} else {
		log.SetLevel(log.ErrorLevel) // Default to Error level logging
	}
}

// temporarily sets the log level to Info and logs the Info message
func logInfo(str1 string, str2 string) {
	originalLevel := log.GetLevel() // Store the original log level
	log.SetLevel(log.InfoLevel)     // Temporarily set level to Info
	log.Info(str1, str2)            // Log the Info message
	log.SetLevel(originalLevel)     // Restore original log level
}
