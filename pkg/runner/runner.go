// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/purell"
	"github.com/jpillora/go-tld"
	"github.com/root4loot/godns"
	"github.com/root4loot/goscope"
	"github.com/root4loot/goutils/iputil"
	"github.com/root4loot/goutils/log"
	"github.com/root4loot/recrawl/pkg/options"
	"github.com/root4loot/recrawl/pkg/util"
)

var (
	mainTarget           *tld.URL
	re_path              = regexp.MustCompile(`(?:"|')(?:(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']*)|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]*[^"'><,;|()]*))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']*)?)|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']*)?)|([a-zA-Z0-9_\-]+(?:\.[a-zA-Z]{1,4})+))(?:"|')`)
	re_robots            = regexp.MustCompile(`(?:Allow|Disallow):\s*([a-zA-Z0-9_\-/]+\.[a-zA-Z0-9]{1,4}(?:\?[^\s]*)?|[a-zA-Z0-9_\-/]+(?:/[a-zA-Z0-9_\-/]+)*(?:\?[^\s]*)?|[a-zA-Z0-9_\-/]+(?:\?[^\s]*|$))`)
	dnsResolutionTimeout = 3 * time.Second
	domainHashes         = make(map[string]map[string]bool) // map of domain/IP to map of response body hashes
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
			log.Debug("Error preparing target:", err)
			continue
		}

		// log info to prepare target for crawling
		logInfo("Preparing target for crawling: ", target)
		go r.queueURL(c_queue, mainTarget)
		c_wait <- 1
	}

	// If only one target is provided, set concurrency to 1
	if len(targets) == 1 {
		r.Options.Concurrency = 1
	}

	log.Debug("starting workers")
	r.startWorkers(c_urls, c_queue, c_wait)
}

// InitializeWorkerPool creates a queue of URLs to be processed by workers
func (r *Runner) InitializeWorkerPool() (chan<- *tld.URL, <-chan *tld.URL, chan<- int) {
	c_wait := make(chan int)
	c_urls := make(chan *tld.URL)
	c_queue := make(chan *tld.URL)
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
					} else {
						c_wait <- -1
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
func (r *Runner) initializeTargetProcessing(target string) (*tld.URL, error) {
	// Ensure the target URL has a scheme (http or https)
	target = util.EnsureScheme(target)

	// Parse the target URL
	mainTarget, _ := tld.Parse(target)

	// If the target is not an IP address, check its reachability
	if !iputil.IsURLIP(target) {
		if r.canReachURL(target, dnsResolutionTimeout) {
			// Add the target to the processing scope
			r.Scope.AddInclude(target)
			r.Scope.AddInclude("*."+mainTarget.Host, mainTarget.Host)
		} else {
			// Target is not reachable, return an error
			return nil, fmt.Errorf("target %s could not be reached", target)
		}
	}

	// Return the parsed URL object
	return mainTarget, nil
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
func (r *Runner) startWorkers(c_urls <-chan *tld.URL, c_queue chan<- *tld.URL, c_wait chan<- int) {

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
func (r *Runner) queueURL(c_queue chan<- *tld.URL, url *tld.URL) {
	url, _ = tld.Parse(r.cleanDomain(url.String()))
	c_queue <- url
}

// worker is a worker that processes URLs from the queue
func (r *Runner) Worker(c_urls <-chan *tld.URL, c_queue chan<- *tld.URL, c_wait chan<- int, c_result chan<- Result) {
	for c_url := range c_urls {
		var rawURLs []string
		if c_url == nil || c_url.Host == "" {
			c_wait <- -1
			continue
		} else {
			log.Debugf("Processing %s", c_url)
		}

		// Check if robots.txt is present for the host and add it to the queue
		robotsURL := fmt.Sprintf("%s://%s/robots.txt", c_url.Scheme, c_url.Host)
		robotsParsedURL, err := tld.Parse(robotsURL)
		if err == nil && !r.isVisitedURL(robotsParsedURL.String()) {
			time.Sleep(r.getDelay() * time.Millisecond)
			c_wait <- 1
			go r.queueURL(c_queue, robotsParsedURL)
		}

		// avoid example.com/foo/bar/foo/bar/foo/bar
		if r.isTrapped(c_url.Path) {
			log.Infof("Trapped in a loop %s", c_url.String())
			c_wait <- -1
			continue
		}

		// avoid URLs that only differ in parameter values
		if r.isRedundantURL(c_url.String()) {
			log.Infof("Skipping redundant URL: %s", c_url.String())
			c_wait <- -1
			continue
		}

		_, resp, err := r.request(c_url)

		if resp == nil {
			c_wait <- -1
			continue
		}

		if err != nil {
			if !strings.Contains(err.Error(), "already visited") {
				log.Infof("%v", err.Error())
				r.Results <- Result{RequestURL: c_url.String(), StatusCode: 0, Error: err}
			}
			c_wait <- -1
			continue
		}

		// Check if the url should be processed based on the response body hash
		if !shouldProcessPage(c_url.Host, resp) {
			c_wait <- -1
			continue
		}

		// landingURL, _ := tld.Parse(resp.Request.URL.String())
		landingURL := resp.Request.URL.String()

		if util.IsTextContentType(resp.Header.Get("Content-Type")) {
			c_wait <- len(rawURLs) - 1
			continue
		}

		paths, err := r.scrape(resp)

		if err != nil {
			log.Warnf("Timeout exceeded for %v", landingURL)
			c_wait <- len(rawURLs) - 1
			continue
		}

		rawURLs, err = r.setURL(landingURL, paths)

		if err != nil {
			log.Warnf("%v", err)
			c_wait <- len(rawURLs) - 1
			continue
		}

		c_wait <- len(rawURLs) - 1

		for i := range rawURLs {
			var u *tld.URL
			if u, err = tld.Parse(rawURLs[i]); err != nil {
				log.Warnf("%v", err)
				c_wait <- len(rawURLs) - 1
				continue
			}
			time.Sleep(r.getDelay() * time.Millisecond)
			go r.queueURL(c_queue, u)
		}
		r.Results <- Result{RequestURL: c_url.String(), StatusCode: resp.StatusCode, Error: nil}
	}
}

// shouldProcessPage checks if a page should be processed (based on the hash of the response body)
func shouldProcessPage(domainOrIP string, resp *http.Response) bool {
	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false // or handle the error as you see fit
	}

	// Convert it back to io.ReadCloser
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Hash of responseBody
	hasher := sha256.New()
	hasher.Write(bodyBytes)
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Initialize the nested map if not already done
	if domainHashes[domainOrIP] == nil {
		domainHashes[domainOrIP] = make(map[string]bool)
	}

	// Check whether the hash already exists for the given domain or IP
	_, exists := domainHashes[domainOrIP][hash]
	if exists {
		log.Debug("Skipping page as it has already been processed")
		return false
	}

	// If it doesn't exist, store it and return true
	domainHashes[domainOrIP][hash] = true
	return true
}

// request makes a request to a URL
func (r *Runner) request(u *tld.URL) (req *http.Request, resp *http.Response, err error) {
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
		if shouldSkipPath(u, path, r) {
			continue
		}

		newPath := formatPath(u, path)
		normalized, _ := r.normalizeURLString(newPath)
		rawURLs = append(rawURLs, normalized)
	}

	return
}

func shouldSkipPath(u *url.URL, path string, r *Runner) bool {
	return path == u.Host || r.isMime(path) || path == "" || strings.HasSuffix(u.Host, path)
}

func formatPath(u *url.URL, path string) string {
	// Add leading slash on single words (likely files) if missing
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http") {
		path = "/" + path
	}

	if util.HasFile(u.Host) {
		if u.Path == "/robots.txt" {
			return u.Scheme + "://" + u.Host + "/" + path
		}
		return u.Host
	}

	if util.HasScheme(path) || util.IsDomain(path) || strings.HasPrefix(path, "//") {
		return path
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

func (r *Runner) resolveDomain(domain string, timeout time.Duration) (string, error) {
	options := godns.DefaultOptions()
	options.Timeout = int(timeout.Seconds())
	options.Resolvers = r.Options.Resolvers

	godnsRunner := godns.NewRunnerWithOptions(*options)

	// resolve the domain
	results := godnsRunner.Multiple([]string{domain})
	for _, result := range results {
		if len(result.IPv4) > 0 {
			return result.IPv4[0], nil
		} else if len(result.IPv6) > 0 {
			return result.IPv6[0], nil
		}
	}
	return "", fmt.Errorf("DNS resolution failed for %s", domain)
}

// canDial checks if a port can be dialed
func (r *Runner) canDial(ip string, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", ip+":"+port, timeout)
	if err != nil {
		return false // Return false as the dial was not successful
	}
	if conn != nil {
		conn.Close() // Close the connection only if it's not nil
	}
	return true
}

// canReachURL checks if a URL can be connected to
func (r *Runner) canReachURL(rawURL string, timeout time.Duration) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Warn("URL parsing failed:", err)
	}

	// has been reached before
	if r.isVisitedHost(u.Host) {
		return true
	}

	// ensure port is set
	if u.Port() == "" {
		if u.Scheme == "http" {
			u.Host = u.Hostname() + ":80"
		} else if u.Scheme == "https" {
			u.Host = u.Hostname() + ":443"
		}
	}

	// check if URL is an IP address
	// if so, check if it can be dialed
	if iputil.IsURLIP(rawURL) {
		if r.canDial(u.Hostname(), u.Port(), timeout) {
			r.addVisitedHost(u.Host)
			return true
		}
	}

	// resolve the domain
	ip, err := r.resolveDomain(u.Hostname(), timeout)
	if err != nil {
		log.Warn("DNS resolution failed:", err)
		return false
	}

	// check if the port can be dialed
	if r.canDial(ip, u.Port(), timeout) {
		r.addVisitedHost(u.Host)
		return true
	}

	return false
}

// scrape scrapes a response for paths
func (r *Runner) scrape(resp *http.Response) (res []string, err error) {
	log.Debugf("Scraping %s", resp.Request.URL.String())
	body, err := io.ReadAll(resp.Body)
	var matches [][]string

	if err == nil {
		if strings.HasSuffix(resp.Request.URL.String(), "robots.txt") {
			matches = re_robots.FindAllStringSubmatch(string(body), -1)
		} else {
			matches = re_path.FindAllStringSubmatch(string(body), -1)
		}
	} else {
		return nil, err
	}

	for _, match := range matches {
		if len(match) > 1 {
			// Extract the path after "Disallow:" or "Allow:" from the second capturing group
			path := strings.TrimSpace(match[1])
			res = append(res, path)
		}
	}

	return util.Unique(res), err
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
	normalizedURL, err = purell.NormalizeURLString(rawURL, normalizationFlags)
	return normalizedURL, err
}

// isMime checks if a URL is a mime type
func (r *Runner) isMime(rawURL string) bool {
	mimes := []string{"audio", "application", "font", "image", "multipart", "text", "video"}
	for _, mime := range mimes {
		if strings.HasPrefix(rawURL, mime) {
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

// cleanDomain cleans a domain for use in a URL
func (r *Runner) cleanDomain(domain string) string {
	domain = util.TrimDoubleSlashes(domain)
	domain = util.EnsureScheme(domain)
	domain = util.AddSlashIfNeeded(domain)
	domain = util.RemoveSlashUnwanted(domain)
	return domain
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

	if u.RawQuery == "" {
		// Check if the canonical URL is already visited
		if r.isVisitedURL(u.Path) {
			return true
		}
	} else {
		// extract query parameters
		params, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return false
		}

		// create the canonical URL without query parameters
		u.RawQuery = ""
		canonicalURL := u.String()

		// check if the canonical URL is already visited
		if r.isVisitedURL(canonicalURL) {
			return true
		}

		// check if the alias URL only differs in the query parameter values
		aliasValues := make(map[string]string)
		for name, paramValues := range params {
			if len(paramValues) > 0 {
				aliasValues[name] = paramValues[0]
			}
		}

		// iterate over the visitedURLs using sync.Map's Range method
		foundAlias := false
		visitedURL.Range(func(key, value interface{}) bool {
			vURL, ok := key.(string)
			if !ok {
				return true // continue the iteration
			}

			v, err := url.Parse(vURL)
			if err != nil {
				return true // continue the iteration
			}

			if v.RawQuery == "" {
				if v.Path == u.Path && len(v.Query()) == len(params) {
					foundAlias = true
					return false // stop the iteration
				}
			} else {
				// extract query parameters
				vParams, err := url.ParseQuery(v.RawQuery)
				if err != nil {
					return true // continue the iteration
				}

				// create the canonical URL without query parameters
				v.RawQuery = ""
				vCanonicalURL := v.String()

				if vCanonicalURL == canonicalURL {
					foundAlias = true
					return false // stop the iteration
				}

				// check if the alias URL only differs in the query parameter values
				vAliasValues := make(map[string]string)
				for name, paramValues := range vParams {
					if len(paramValues) > 0 {
						vAliasValues[name] = paramValues[0]
					}
				}

				alias := true
				for name, value := range aliasValues {
					if vAliasValues[name] != value {
						alias = false
						break
					}
				}
				if alias {
					foundAlias = true
					return false // stop the iteration
				}
			}

			return true // continue the iteration
		})

		if foundAlias {
			return true
		}
	}

	return false
}

// mergeRegexMatches merges regex matches
func mergeRegexMatches(regexPattern, input string) []string {
	regex := regexp.MustCompile(regexPattern)
	allMatches := regex.FindAllString(input, -1)
	return allMatches
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
	log.Debug("Setting logger level...") // Log a debug message to indicate setting of log level

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
