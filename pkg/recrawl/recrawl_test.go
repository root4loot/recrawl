// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package recrawl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/root4loot/scope"
)

func TestBasicCrawlerInitialization(t *testing.T) {
	crawler := NewRecrawl()
	if crawler == nil {
		t.Fatal("NewRecrawl() returned nil")
	}
	if crawler.Options == nil {
		t.Fatal("Options not initialized")
	}
	if crawler.Scope == nil {
		t.Fatal("Scope not initialized")
	}
	if crawler.Results == nil {
		t.Fatal("Results channel not initialized")
	}

	// Test with custom options
	opts := &Options{
		Concurrency: 5,
		Timeout:     15,
		UserAgent:   "Test-Agent",
	}
	crawler = NewRecrawlWithOptions(opts)
	if crawler.Options.Concurrency != 5 {
		t.Errorf("Expected concurrency 5, got %d", crawler.Options.Concurrency)
	}
	if crawler.Options.Timeout != 15 {
		t.Errorf("Expected timeout 15, got %d", crawler.Options.Timeout)
	}
	if crawler.Options.UserAgent != "Test-Agent" {
		t.Errorf("Expected UserAgent 'Test-Agent', got %s", crawler.Options.UserAgent)
	}
}

func TestBasicScopeIntegration(t *testing.T) {
	customScope := scope.NewScope()
	customScope.AddInclude("example.com")

	opts := &Options{Scope: customScope}
	crawler := NewRecrawlWithOptions(opts)

	if crawler.Scope != customScope {
		t.Error("Crawler should use provided custom scope")
	}

	if !crawler.Scope.IsInScope("example.com") {
		t.Error("example.com should be in scope")
	}

	if crawler.Scope.IsInScope("other.com") {
		t.Error("other.com should not be in scope")
	}
}

func TestHTMLScraping(t *testing.T) {
	crawler := NewRecrawl()

	testHTML := `<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
	<a href="/about">About</a>
	<a href="/contact">Contact</a>
	<a href="/api/users">API Users</a>
	<script src="/js/main.js"></script>
	<img src="/images/logo.png" alt="Logo">
</body>
</html>`

	paths := crawler.scrapePaths([]byte(testHTML))

	expectedPaths := []string{"/about", "/contact", "/api/users", "/js/main.js", "/images/logo.png"}

	for _, expected := range expectedPaths {
		found := false
		for _, path := range paths {
			if strings.Contains(path, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected path %q not found in scraping results", expected)
		}
	}
}

func TestRobotsTxtScraping(t *testing.T) {
	crawler := NewRecrawl()

	robotsContent := `User-agent: *
Disallow: /admin
Disallow: /private
Allow: /public
Disallow: /temp/*.tmp
Allow: /downloads/`

	paths := crawler.scrapeRobotsTxt([]byte(robotsContent))

	if len(paths) == 0 {
		t.Error("Expected to find paths in robots.txt")
	}

	// Check for key paths
	foundAdmin := false
	foundPrivate := false
	foundPublic := false

	for _, path := range paths {
		if strings.Contains(path, "admin") {
			foundAdmin = true
		}
		if strings.Contains(path, "private") {
			foundPrivate = true
		}
		if strings.Contains(path, "public") {
			foundPublic = true
		}
	}

	if !foundAdmin || !foundPrivate || !foundPublic {
		t.Error("Expected to find admin, private, and public paths in robots.txt scraping")
	}
}

func TestURLNormalization(t *testing.T) {
	crawler := NewRecrawl()

	testCases := []struct {
		input    string
		expected string
		name     string
	}{
		{"HTTP://EXAMPLE.COM/PATH", "http://example.com/PATH", "lowercase scheme and host"},
		{"http://example.com:80/path", "http://example.com/path", "remove default port"},
		{"http://example.com/path//", "http://example.com/path", "remove duplicate slashes"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := crawler.normalizeURLString(tc.input)
			if err != nil {
				t.Errorf("normalizeURLString(%q) returned error: %v", tc.input, err)
				return
			}
			if result != tc.expected {
				t.Errorf("normalizeURLString(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestURLCleaning(t *testing.T) {
	crawler := NewRecrawl()

	testCases := []struct {
		input    string
		expected string
		name     string
	}{
		{"http://example.com", "http://example.com/", "add trailing slash"},
		{"example.com", "http://example.com/", "add scheme and slash"},
		{"http://example.com/path", "http://example.com/path/", "add trailing slash to path"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := crawler.cleanURL(tc.input)
			if result != tc.expected {
				t.Errorf("cleanURL(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestPathTrapping(t *testing.T) {
	crawler := NewRecrawl()

	testCases := []struct {
		path     string
		expected bool
		name     string
	}{
		{"/normal/path", false, "normal path"},
		{"/a/b/c/d/e", false, "short path"},
		{"/repeat/repeat/repeat/repeat/repeat/repeat/repeat/repeat/repeat/repeat", true, "obvious trap"},
		{"", false, "empty path"},
		{"/single", false, "single segment"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := crawler.isTrapped(tc.path)
			if result != tc.expected {
				t.Errorf("isTrapped(%q) = %v, expected %v", tc.path, result, tc.expected)
			}
		})
	}
}

func TestMediaDetection(t *testing.T) {
	crawler := NewRecrawl()

	testCases := []struct {
		path     string
		expected bool
		name     string
	}{
		{"image/jpeg", true, "image mime"},
		{"audio/mp3", true, "audio mime"},
		{"video/mp4", true, "video mime"},
		{"text/css", true, "text mime"},
		{"/normal/path", false, "normal path"},
		{"javascript", false, "non-mime string"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := crawler.isMedia(tc.path)
			if result != tc.expected {
				t.Errorf("isMedia(%q) = %v, expected %v", tc.path, result, tc.expected)
			}
		})
	}
}

func TestVisitedTracking(t *testing.T) {
	crawler := NewRecrawl()

	testURL := "http://example.com/test"

	// Initially not visited
	if crawler.isVisitedURL(testURL) {
		t.Error("URL should not be visited initially")
	}

	// Mark as visited
	crawler.addVisitedURL(testURL)

	// Should now be visited
	if !crawler.isVisitedURL(testURL) {
		t.Error("URL should be visited after adding")
	}

	// Different URL should not be visited
	if crawler.isVisitedURL("http://example.com/other") {
		t.Error("Different URL should not be visited")
	}
}

func TestQuoteRemoval(t *testing.T) {
	crawler := NewRecrawl()

	testCases := []struct {
		input    string
		expected string
		name     string
	}{
		{`"quoted"`, "quoted", "double quotes"},
		{`'single'`, "single", "single quotes"},
		{`"mixed'`, `"mixed'`, "mismatched quotes"},
		{"no quotes", "no quotes", "no quotes"},
		{`""`, "", "empty quotes"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := crawler.removeQuotes(tc.input)
			if result != tc.expected {
				t.Errorf("removeQuotes(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestMockServerIntegration(t *testing.T) {
	// Simple mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/test">Test Link</a></body></html>`)
	}))
	defer server.Close()

	crawler := NewRecrawl()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal("Failed to parse server URL:", err)
	}

	_, resp, err := crawler.request(u)
	if err != nil {
		t.Fatal("Request failed:", err)
	}

	if resp == nil {
		t.Fatal("Response is nil")
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Test scraping the response
	paths, err := crawler.scrape(resp)
	if err != nil {
		t.Fatal("Scraping failed:", err)
	}

	if len(paths) == 0 {
		t.Error("Expected to find paths in response")
	}
}

func TestTargetProcessing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>Test</body></html>")
	}))
	defer server.Close()

	crawler := NewRecrawl()

	// Test processing server URL
	u, err := crawler.initializeTargetProcessing(server.URL)
	if err != nil {
		t.Fatal("Failed to process target:", err)
	}

	if u == nil {
		t.Fatal("Returned URL is nil")
	}

	// Test that target gets added to scope
	serverURL, _ := url.Parse(server.URL)
	if !crawler.Scope.IsInScope(serverURL.Host) {
		t.Error("Target host should be added to scope")
	}
}

func TestDelayCalculation(t *testing.T) {
	// Test without jitter (delay is returned as raw nanoseconds)
	opts := &Options{Delay: 100, DelayJitter: 0}
	crawler := NewRecrawlWithOptions(opts)

	delay := crawler.getDelay()
	expectedDelay := time.Duration(100) // 100 nanoseconds
	if delay != expectedDelay {
		t.Errorf("Expected delay %v, got %v", expectedDelay, delay)
	}

	// Test with jitter (delay is returned as raw nanoseconds)
	opts = &Options{Delay: 100, DelayJitter: 50}
	crawler = NewRecrawlWithOptions(opts)

	delay = crawler.getDelay()
	minDelay := time.Duration(100) // 100 nanoseconds
	maxDelay := time.Duration(150) // 150 nanoseconds
	if delay < minDelay || delay > maxDelay {
		t.Errorf("Expected delay between %v-%v, got %v", minDelay, maxDelay, delay)
	}
}

func TestErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/404" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/500" {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "<html><body>OK</body></html>")
	}))
	defer server.Close()

	crawler := NewRecrawl()

	// Test 404
	u, _ := url.Parse(server.URL + "/404")
	_, resp, err := crawler.request(u)
	if err != nil {
		t.Fatal("Request failed:", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", resp.StatusCode)
	}

	// Test 500
	u, _ = url.Parse(server.URL + "/500")
	_, resp, err = crawler.request(u)
	if err != nil {
		t.Fatal("Request failed:", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", resp.StatusCode)
	}
}
