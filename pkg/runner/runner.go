// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package runner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/purell"
	"github.com/jpillora/go-tld"
	"github.com/root4loot/urlwalk/pkg/log"
	"github.com/root4loot/urlwalk/pkg/options"
	"github.com/root4loot/urlwalk/pkg/util"
)

var (
	mainTarget *tld.URL
	re         = regexp.MustCompile(`(?:"|')(?:(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:[\?|#][^"|']{0,}|))))(?:"|')`)
)

type Runner struct {
	Options *options.Options
	Results chan Result
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
	visited map[string]bool
	mutex   = &sync.Mutex{}
)

// NewRunner creates a new runner
func NewRunner(o *options.Options) (runner *Runner) {
	runner = &Runner{}

	runner.Results = make(chan Result)
	runner.Options = o

	runner.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost:   o.Concurrency,
			ResponseHeaderTimeout: time.Duration(o.Timeout) * time.Second,
		},
		Timeout: time.Duration(o.Timeout) * time.Second,
	}

	if o.Proxy != "" {
		if !util.HasScheme(o.Proxy) {
			o.Proxy = "http://" + o.Proxy
		}
		proxy, err := url.Parse(o.Proxy)
		if err != nil {
			log.Fatalf("Error parsing proxy URL: %s", err)
		}

		runner.client = &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyURL(proxy),
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
				MaxIdleConnsPerHost:   o.Concurrency,
				ResponseHeaderTimeout: time.Duration(o.Timeout) * time.Second,
			},
			Timeout: time.Duration(o.Timeout) * time.Second,
		}
	}

	return runner
}

// Run starts the runner
func (r *Runner) Run(target string) {
	r.Results = make(chan Result)
	r.Options.ValidateOptions()
	r.Options.SetDefaultsMissing()
	target = util.EnsureScheme(target)
	mainTarget, _ = tld.Parse(target)

	r.SetScope(target)
	c_queue, c_urls, c_wait := r.makeQueue()
	c_wait <- 1

	var wg sync.WaitGroup
	for i := 0; i < r.Options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.worker(c_urls, c_queue, c_wait, r.Results)
		}()
	}
	r.queueURL(c_queue, mainTarget)
	wg.Wait()

	// close the r.Results channel after all workers have finished
	close(r.Results)
}

// makeQueue creates a queue of URLs to be processed by workers
func (r *Runner) makeQueue() (chan<- *tld.URL, <-chan *tld.URL, chan<- int) {
	visited = make(map[string]bool)
	c_wait := make(chan int)
	c_urls := make(chan *tld.URL)
	c_queue := make(chan *tld.URL)
	queueCount := 0

	go func() {
		for delta := range c_wait {
			queueCount += delta
			if queueCount == 0 {
				close(c_queue)
			}
		}
	}()

	go func() {
		for q := range c_queue {
			if r.InScope(q) && !r.isVisited(q.String()) {
				c_urls <- q
			} else {
				c_wait <- -1
			}
		}
		close(c_urls)
		close(c_wait)
	}()

	return c_queue, c_urls, c_wait
}

// queueURL adds a URL to the queue
func (r *Runner) queueURL(c_queue chan<- *tld.URL, url *tld.URL) {
	url, _ = tld.Parse(r.cleanDomain(url.String()))
	c_queue <- url
}

// worker is a worker that processes URLs from the queue
func (r *Runner) worker(c_urls <-chan *tld.URL, c_queue chan<- *tld.URL, c_wait chan<- int, c_result chan<- Result) {
	for c_url := range c_urls {
		var rawURLs []string
		if c_url == nil || c_url.Host == "" {
			c_wait <- -1
			continue
		}

		// avoid example.com/foo/bar/foo/bar/foo/bar
		if r.isTrapped(c_url.Path) {
			// log.Debugf("Trapped in a loop %s", c_url.String())
			c_wait <- -1
			continue
		}

		// avoid URLs that only differ in parameter values
		if r.isSimilarToVisitedURL(c_url.String()) {
			// log.Debugf("Found similar for %s", c_url.String())
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
				log.Warningf("%v", err.Error())
				r.Results <- Result{RequestURL: c_url.String(), StatusCode: 0, Error: err}
			}
			c_wait <- -1
			continue
		}

		landingURL, _ := tld.Parse(resp.Request.URL.String())

		if util.IsTextContentType(resp.Header.Get("Content-Type")) {
			c_wait <- len(rawURLs) - 1
			continue
		}

		paths, err := r.scrape(resp)
		if err != nil {
			log.Warningf("Timeout exceeded for %v", landingURL)
			c_wait <- len(rawURLs) - 1
			continue
		}

		rawURLs, err = r.setURL(landingURL, paths)
		if err != nil {
			log.Warningf("%v", err)
			c_wait <- len(rawURLs) - 1
			continue
		}

		c_wait <- len(rawURLs) - 1
		for i := range rawURLs {
			var u *tld.URL
			if u, err = tld.Parse(rawURLs[i]); err != nil {
				log.Warningf("%v", err)
				c_wait <- len(rawURLs) - 1
				continue
			}
			time.Sleep(r.getDelay() * time.Millisecond)
			go r.queueURL(c_queue, u)
		}
		r.Results <- Result{RequestURL: c_url.String(), StatusCode: resp.StatusCode, Error: nil}
	}

}

// request makes a request to a URL
func (r *Runner) request(u *tld.URL) (req *http.Request, resp *http.Response, err error) {

	defer r.addVisited(u.String())

	// Check if URL has already been visited
	if r.isVisited(u.String()) {
		return nil, nil, nil
	}

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

		if !r.isVisited(nextURL.String()) {
			r.addVisited(nextURL.String())
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
func (r *Runner) setURL(u *tld.URL, paths []string) (rawURLs []string, err error) {
	var line string
	for i := range paths {
		if paths[i] == u.String() || r.isMime(paths[i]) || paths[i] == "" || strings.HasSuffix(u.String(), paths[i]) {
			continue
		}
		if util.HasFile(u.String()) {
			line = u.String()
		} else if util.HasScheme(paths[i]) {
			line = paths[i]
		} else if util.IsDomain(paths[i]) {
			line = paths[i]
		} else if strings.HasPrefix(paths[i], "//") {
			line = strings.TrimLeft(paths[i], "/")
		} else if strings.HasPrefix(paths[i], "/") && strings.ContainsAny(paths[i], ".") {
			line = u.Scheme + "://" + u.Host + "/" + paths[i]
		} else if strings.HasPrefix(paths[i], "/") {
			line = u.Scheme + "://" + u.Host + "/" + paths[i] + "/"
		} else {
			if util.HasFile(paths[i]) || util.HasParam(paths[i]) {
				line = u.Scheme + "://" + u.Host + "/" + u.Path + "/" + paths[i]
			} else {
				line = u.Scheme + "://" + u.Host + "/" + u.Path + "/" + paths[i] + "/"
			}
		}

		normalized, _ := r.normalizeURLString(line)
		rawURLs = append(rawURLs, normalized)
	}
	return
}

// scrape scrapes a response for paths
func (r *Runner) scrape(resp *http.Response) (res []string, err error) {
	body, err := ioutil.ReadAll(resp.Body)
	var matches [][]string

	if err == nil {
		matches = re.FindAllStringSubmatch(string(body), -1)
	} else {
		return nil, err
	}
	for _, match := range matches {
		if len(match) > 0 {
			res = append(res, match[1])
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

// addVisited adds a URL to the visited map
func (r *Runner) addVisited(key string) {
	mutex.Lock()
	visited[key] = true
	mutex.Unlock()
}

// isVisited checks if a URL has been visited
func (r *Runner) isVisited(key string) bool {
	mutex.Lock()
	defer mutex.Unlock()
	_, ok := visited[key]
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

// isSimilarToVisitedURL checks if a URL is similar to a visited URL
func (r *Runner) isSimilarToVisitedURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	if u.RawQuery == "" {
		if r.isVisited(u.Path) {
			return true
		}
	} else {
		// extract query parameters
		params, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return false
		}
		// create a map of query parameter values
		values := make(map[string]string)
		for name, paramValues := range params {
			if len(paramValues) > 0 {
				values[name] = paramValues[0]
			}
		}
		// create the canonical URL without query parameters
		u.RawQuery = ""
		canonicalURL := u.String()

		// check if the canonical URL is already visited
		if r.isVisited(canonicalURL) {
			return true
		}

		// check if the alias URL only differs in the query parameter values
		aliasValues := make(map[string]string)
		for name, paramValues := range params {
			if len(paramValues) > 0 {
				aliasValues[name] = paramValues[0]
			}
		}

		mutex.Lock()
		defer mutex.Unlock()

		for visitedURL := range visited {
			v, err := url.Parse(visitedURL)
			if err != nil {
				continue
			}
			if v.RawQuery == "" {
				if v.Path == u.Path && len(v.Query()) == len(params) {
					return true
				}
			} else {
				// extract query parameters
				vParams, err := url.ParseQuery(v.RawQuery)
				if err != nil {
					continue
				}
				// create a map of query parameter values
				vValues := make(map[string]string)
				for name, paramValues := range vParams {
					if len(paramValues) > 0 {
						vValues[name] = paramValues[0]
					}
				}
				// create the canonical URL without query parameters
				v.RawQuery = ""
				vCanonicalURL := v.String()

				// check if the canonical URL matches the current URL
				if vCanonicalURL == canonicalURL {
					return true
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
					if vValues[name] != value {
						alias = false
						break
					}
				}
				if alias {
					return true
				}
			}
		}
	}
	return false
}
