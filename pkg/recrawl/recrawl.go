// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package recrawl

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/purell"
	"github.com/glaslos/ssdeep"
	"github.com/root4loot/goutils/domainutil"
	"github.com/root4loot/goutils/log"
	"github.com/root4loot/goutils/sliceutil"
	"github.com/root4loot/goutils/strutil"
	"github.com/root4loot/goutils/urlutil"
	"github.com/root4loot/scope"
)

var (
	re_path     = regexp.MustCompile(`(?:"|')(?:(((?:[a-zA-Z]{1,10}:(?:\\)?/(?:\\)?/|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']*)|((?:/|\.\./|\./|\\/)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]*[^"'><,;|()]*))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]*\.[a-zA-Z0-9_]+(?:[\?|#][^"|']*)?)|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']*)?)|([a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_]{1,})+)|([a-zA-Z0-9_\-/]+/))(?:"|')`)
	re_robots   = regexp.MustCompile(`(?:Allow|Disallow): \s*(.*)`)
	fuzzyHashes = make(map[string]map[string]bool) // Map of host to map of hash to bool
)

type Crawler struct {
	Options *Options
	Results chan Result
	Scope   *scope.Scope
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

func NewRecrawl() *Crawler { return newCrawler(NewOptions()) }

func NewRecrawlWithOptions(o *Options) *Crawler { return newCrawler(o) }

func newCrawler(o *Options) *Crawler {
    runner := &Crawler{
        Results: make(chan Result),
        Options: o,
    }

	runner.Options.ApplyDefaults()
	runner.setLogLevel()
	runner.initializeScope()
    runner.client = NewHTTPClient(o).client

	return runner
}

func (r *Crawler) Run(targets ...string) {
	log.Debug("Run() called!")

	r.Options.ValidateOptions()
	c_queue, c_urls, c_wait := r.InitializeWorkerPool()

	log.Debug("number of targets: ", len(targets))

	for _, target := range targets {
		mainTarget, err := r.initializeTargetProcessing(target)

		if err != nil {
			log.Warn("Error preparing target:", err)
			continue
		}

		go r.queueURL(c_queue, mainTarget)
		
		if (strings.ToLower(r.Options.BruteforceLevel) != "none" && r.Options.UseBruteforce) || len(r.Options.WordlistFiles) > 0 || r.Options.CLI.WordlistFiles != "" {
			go r.queueWordlistPaths(mainTarget, c_queue, c_wait)
		}
	}

	if len(targets) == 1 {
		r.Options.Concurrency = 1
	}

	log.Debug("starting workers")
	r.startWorkers(c_urls, c_queue, c_wait)
}

func (r *Crawler) InitializeWorkerPool() (chan<- *url.URL, <-chan *url.URL, chan<- int) {
	c_wait := make(chan int)
	c_urls := make(chan *url.URL)
	c_queue := make(chan *url.URL, 10000)
	queueCount := 0

	timeoutDuration := time.Second * 7

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
		timeoutTimer := time.NewTimer(timeoutDuration)
		defer timeoutTimer.Stop()

		for {
			select {
			case q := <-c_queue:
				if q != nil {
					if r.Scope.IsInScope(q.Host) && !r.isVisitedURL(q.String()) {
						c_urls <- q
					}

					if !timeoutTimer.Stop() {
						<-timeoutTimer.C
					}
					timeoutTimer.Reset(timeoutDuration)
				}
			case <-c_urls:

			case <-timeoutTimer.C:
				log.Debug("Timeout reached, closing channels.")
				close(c_urls)
				return
			}
		}
	}()

	return c_queue, c_urls, c_wait
}

func (r *Crawler) initializeTargetProcessing(target string) (*url.URL, error) {
	if !strings.Contains(target, "://") {
		if r.Options.PreferHTTP {
			target = "http://" + target
		} else {
			target = "https://" + target
		}
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format '%s': %v", target, err)
	}

	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		target = u.Scheme + "://" + u.Hostname()
	}

	if u.Host != "" {
		_ = r.Scope.AddInclude(u.Host)
	}

	if !r.isVisitedHost(u.Hostname()) {
		r.addVisitedHost(u.Hostname())
	}

	u, err = url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format '%s': %v", target, err)
	}

	return u, nil
}

func (r *Crawler) initializeScope() {
	if r.Options.Scope != nil {
		r.Scope = r.Options.Scope
	}
	if r.Scope == nil {
		r.Scope = scope.NewScope()
	}
}

func (r *Crawler) startWorkers(c_urls <-chan *url.URL, c_queue chan<- *url.URL, c_wait chan<- int) {
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

func (r *Crawler) queueURL(c_queue chan<- *url.URL, url *url.URL) {
	url, err := url.Parse(r.cleanURL(url.String()))
	if err == nil {
		c_queue <- url
	}
}

func (r *Crawler) Worker(c_urls <-chan *url.URL, c_queue chan<- *url.URL, c_wait chan<- int, c_result chan<- Result) {
	for c_url := range c_urls {
		log.Debugf("Processing URL: %s", c_url.String())

		if c_url == nil || c_url.Host == "" || r.isTrapped(c_url.Path) || r.isRedundantURL(c_url.String()) {
			log.Debugf("Skipping URL due to initial checks: %s", c_url)
			continue
		}

		if r.shouldAddRobotsTxt(c_url) {
			r.addRobotsTxtToQueue(c_url, c_queue, c_wait)
		}

		currentURL := c_url
		redirectCount := 0
		for {
			if redirectCount >= 10 {
				log.Infof("Redirect limit reached for %s", currentURL)
				break
			}

			_, resp, err := r.request(currentURL)
			if err != nil {
				log.Infof("Error requesting %s: %v", currentURL, err)
				r.Results <- Result{RequestURL: currentURL.String(), StatusCode: 0, Error: err}
				break
			}
			if resp == nil {
				break
			}

			if r.isRedundantURL(currentURL.String()) {
				log.Infof("Skipping URL as it's redundant: %s", currentURL)
				break
			}

			if r.isRedundantBody(currentURL.Host, resp, 97) {
				log.Infof("Skipping URL as similar content has been processed: %s", currentURL)
				break
			}

			r.Results <- Result{RequestURL: currentURL.String(), StatusCode: resp.StatusCode, Error: nil}

			if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
				location, err := resp.Location()
				if err != nil || location == nil {
					log.Warnf("Failed to handle redirect from %s", currentURL)
					break
				}
				currentURL = location
				redirectCount++
			} else {
				paths, err := r.scrape(resp)
				if err != nil {
					log.Warnf("Failed to scrape %s: %v", currentURL, err)
					break
				}

				rawURLs, err := r.setURL(currentURL.String(), paths)
				if err != nil {
					log.Warnf("Failed to set URLs from %s: %v", currentURL, err)
					break
				}

				for _, rawURL := range rawURLs {
					u, err := url.Parse(rawURL)
					if err != nil {
						log.Warnf("Error parsing URL %s: %v", rawURL, err)
						continue
					}
					go r.queueURL(c_queue, u)
				}
				break
			}
		}
	}
}

func (r *Crawler) shouldAddRobotsTxt(c_url *url.URL) bool {
	return (c_url.Path == "" || c_url.Path == "/") && !strings.HasSuffix(c_url.Path, "robots.txt") && !r.isVisitedURL(c_url.String()+"/robots.txt")
}

func (r *Crawler) addRobotsTxtToQueue(c_url *url.URL, c_queue chan<- *url.URL, c_wait chan<- int) {
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", c_url.Scheme, c_url.Host)
	robotsParsedURL, err := url.Parse(robotsURL)
	if err == nil {
		time.Sleep(r.getDelay() * time.Millisecond)
		c_wait <- 1
		go r.queueURL(c_queue, robotsParsedURL)
	}
}

func (r *Crawler) isRedundantBody(host string, resp *http.Response, threshold int) bool {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return false
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	hash, _ := ssdeep.FuzzyBytes(bodyBytes)

	if fuzzyHashes[host] == nil {
		fuzzyHashes[host] = make(map[string]bool)
	}

	for existingHash := range fuzzyHashes[host] {
		score, _ := ssdeep.Distance(existingHash, hash)

		if score >= threshold {
			return true
		}
	}

	fuzzyHashes[host][hash] = true
	return false
}

func (r *Crawler) isRedundantURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.RawQuery == "" {
		if r.isVisitedURL(u.Path) {
			return true
		}
	} else {
		params, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return false
		}
		u.RawQuery = ""
		canonicalURL := u.String()
		if r.isVisitedURL(canonicalURL) {
			return true
		}
		aliasValues := make(map[string]string)
		for name, paramValues := range params {
			if len(paramValues) > 0 {
				aliasValues[name] = paramValues[0]
			}
		}
		foundAlias := false
		visitedURL.Range(func(key, value interface{}) bool {
			vURL, ok := key.(string)
			if !ok {
				return true
			}
			v, err := url.Parse(vURL)
			if err != nil {
				return true
			}
			if v.RawQuery == "" {
				if v.Path == u.Path && len(v.Query()) == len(params) {
					foundAlias = true
					return false
				}
			} else {
				vParams, err := url.ParseQuery(v.RawQuery)
				if err != nil {
					return true
				}
				v.RawQuery = ""
				vCanonicalURL := v.String()
				if vCanonicalURL == canonicalURL {
					foundAlias = true
					return false
				}
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
					return false
				}
			}
			return true
		})
		if foundAlias {
			return true
		}
	}
	return false
}

func (r *Crawler) request(u *url.URL) (req *http.Request, resp *http.Response, err error) {
	log.Debug("Requesting ", u.String())

	if r.isVisitedURL(u.String()) {
		log.Debugf("URL already visited: %s", u.String())
		return nil, nil, fmt.Errorf("URL already visited")
	}

	r.addVisitedURL(u.String())

	req, err = http.NewRequest("GET", u.String(), nil)
	if err != nil {
		log.Warnf("Failed to create request for %s: %v", u.String(), err)
		return
	}

	if r.Options.UserAgent != "" {
		req.Header.Add("User-Agent", r.Options.UserAgent)
	}

	r.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err = r.client.Do(req)
	if err != nil {
		log.Warnf("HTTP request failed for %s: %v", u.String(), err)
		return
	}

	return req, resp, nil
}

func (r *Crawler) setURL(rawURL string, paths []string) (rawURLs []string, err error) {
	log.Debugf("Setting URL for %s", rawURL)

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}


	for _, path := range paths {
		if r.shouldSkipPath(u, path) || strutil.IsBinaryString(path) || !strutil.IsPrintable(path) || strings.Count(u.Path, ".") >= 2 {
			continue
		}

		if domainutil.IsDomainName(path) {
			rawURLs = append(rawURLs, rawURL+"/"+path)
		}

		formattedURL := formatURL(u, path)
		normaizedURL, _ := r.normalizeURLString(formattedURL)
		rawURLs = append(rawURLs, normaizedURL)
	}

	return
}

func (r *Crawler) shouldSkipPath(u *url.URL, path string) bool {
	return path == u.Host || r.isMedia(path) || path == "" || strings.HasSuffix(u.Host, path)
}

func formatURL(u *url.URL, path string) string {
	path = strings.ReplaceAll(path, "\\", "")

	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http") && strings.Contains(path, ".") {
		path = "/" + path
	}

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

	if urlutil.HasFileExtension(path) || urlutil.HasParam(path) {
		return u.Scheme + "://" + u.Host + u.Path + "/" + path
	}

	return u.Scheme + "://" + u.Host + u.Path + "/" + path + "/"
}

func (r *Crawler) scrape(resp *http.Response) ([]string, error) {
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

func (r *Crawler) scrapeRobotsTxt(body []byte) []string {
	var res []string

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

func (r *Crawler) scrapePaths(body []byte) []string {
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

func (r *Crawler) normalizeURLString(rawURL string) (normalizedURL string, err error) {

	normalizedURL = strings.ReplaceAll(rawURL, `\`, `%5C`)
	normalizedURL, err = purell.NormalizeURLString(normalizedURL, normalizationFlags)
	return normalizedURL, err
}

func (r *Crawler) isMedia(path string) bool {
	mimes := []string{"audio/", "application/", "font/", "image/", "multipart/", "text/", "video/"}
	for _, mime := range mimes {
		if strings.HasPrefix(path, mime) {
			return true
		}
	}
	return false
}

func (r *Crawler) isTrapped(path string) bool {
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

func (r *Crawler) getDelay() time.Duration {
	if r.Options.DelayJitter != 0 {
		return time.Duration(r.Options.Delay + rand.Intn(r.Options.DelayJitter))
	}
	return time.Duration(r.Options.Delay)
}

func (r *Crawler) addVisitedURL(key string) {
	visitedURL.Store(key, true)
}

func (r *Crawler) addVisitedHost(key string) {
	visitedHost.Store(key, true)
}

func (r *Crawler) isVisitedURL(key string) bool {
	_, ok := visitedURL.Load(key)
	return ok
}

func (r *Crawler) isVisitedHost(key string) bool {
	_, ok := visitedHost.Load(key)
	return ok
}

func (r *Crawler) cleanURL(url string) string {
	url = urlutil.NormalizeSlashes(url)
	url = urlutil.EnsureHTTP(url)
	url = urlutil.EnsureTrailingSlash(url)
	return url
}

func (r *Crawler) removeQuotes(input string) string {
	if len(input) < 2 {
		return input
	}

	if (input[0] == '"' && input[len(input)-1] == '"') || (input[0] == '\'' && input[len(input)-1] == '\'') {

		return input[1 : len(input)-1]
	}
	return input
}

func (r *Crawler) setLogLevel() {
	if r.Options.Verbose == 1 {
		log.SetLevel(log.InfoLevel)
	} else if r.Options.Verbose == 2 {
		log.SetLevel(log.DebugLevel)
	} else if r.Options.Silence {
		log.SetLevel(log.FatalLevel)
	} else {
		log.SetLevel(log.ErrorLevel)
	}
}

func (r *Crawler) loadWordlists() []string {
	var wordlistEntries []string
	
	if strings.ToLower(r.Options.BruteforceLevel) != "none" && r.Options.UseBruteforce {
		builtinWordlists := r.getBuiltinWordlistsForLevel(r.Options.BruteforceLevel)
		for _, wordlist := range builtinWordlists {
			if entries := r.loadWordlistFile(wordlist); len(entries) > 0 {
				wordlistEntries = append(wordlistEntries, entries...)
				log.Debugf("Loaded %d entries from built-in wordlist: %s", len(entries), wordlist)
			}
		}
	}
	
	var wordlistFiles []string
	if len(r.Options.WordlistFiles) > 0 {
		wordlistFiles = r.Options.WordlistFiles
	} else if r.Options.CLI.WordlistFiles != "" {
		wordlistFiles = strings.Split(r.Options.CLI.WordlistFiles, ",")
	}
	
	for _, file := range wordlistFiles {
		file = strings.TrimSpace(file)
		if entries := r.loadWordlistFile(file); len(entries) > 0 {
			wordlistEntries = append(wordlistEntries, entries...)
			log.Debugf("Loaded %d entries from custom wordlist: %s", len(entries), file)
		}
	}
	
	return sliceutil.Unique(wordlistEntries)
}

func (r *Crawler) getBuiltinWordlistsForLevel(level string) []string {
	var wordlists []string
	
	wordlists = append(wordlists, filepath.Join("wordlists", "recrawl.txt"))
	
	switch strings.ToLower(level) {
	case "none":
		return []string{}
	case "light":
		wordlists = append(wordlists, filepath.Join("wordlists", "raft-small-dirs.txt"))
	case "medium":
		wordlists = append(wordlists, filepath.Join("wordlists", "raft-medium-dirs.txt"))
	case "heavy":
		wordlists = append(wordlists, filepath.Join("wordlists", "raft-large-dirs.txt"))
	default:
		log.Warnf("Unknown bruteforce level '%s', defaulting to 'light'", level)
		return r.getBuiltinWordlistsForLevel("light")
	}
	
	return wordlists
}

// loadWordlistFile loads entries from a single wordlist file
func (r *Crawler) loadWordlistFile(filename string) []string {
	var entries []string
	
	file, err := os.Open(filename)
	if err != nil {
		log.Debugf("Could not open wordlist file %s: %v", filename, err)
		return entries
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	
	if err := scanner.Err(); err != nil {
		log.Warnf("Error reading wordlist file %s: %v", filename, err)
	}
	
	return entries
}

// queueWordlistPaths adds wordlist paths for a target to the queue
func (r *Crawler) queueWordlistPaths(targetURL *url.URL, c_queue chan<- *url.URL, c_wait chan<- int) {
	wordlistEntries := r.loadWordlists()
	if len(wordlistEntries) == 0 {
		return
	}
	
	log.Debugf("Queuing %d wordlist entries for %s", len(wordlistEntries), targetURL.Host)
	
	for _, entry := range wordlistEntries {
		// Skip directory entries for now (ending with /)
		if strings.HasSuffix(entry, "/") {
			continue
		}
		
		// Construct URL for this wordlist entry
		wordlistURL := fmt.Sprintf("%s://%s/%s", targetURL.Scheme, targetURL.Host, entry)
		if parsedURL, err := url.Parse(wordlistURL); err == nil {
			c_wait <- 1
			go r.queueURL(c_queue, parsedURL)
		}
	}
}
