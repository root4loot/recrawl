package recrawl

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/root4loot/goutils/urlutil"
)

type HTTPClient struct {
	client *http.Client
}

// HeaderRoundTripper wraps an http.RoundTripper, adding a set of headers to each request
type HeaderRoundTripper struct {
	Transport http.RoundTripper
	Headers   http.Header
}

// RoundTrip executes a single HTTP transaction and adds custom headers
func (hrt *HeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range hrt.Headers {
		req.Header[k] = v
	}
	return hrt.Transport.RoundTrip(req)
}

// NewHTTPClient returns a new HTTP client with custom headers if provided
func NewHTTPClient(options *Options) *HTTPClient {
	// Initializing transport with the creation line
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost:   options.Concurrency,
		ResponseHeaderTimeout: time.Duration(options.Timeout) * time.Second,
	}

	if options.Proxy != "" {
		if !urlutil.HasScheme(options.Proxy) {
			options.Proxy = "http://" + options.Proxy
		}
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			log.Fatalf("Error parsing proxy URL: %s", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	headers := make(http.Header)
	for _, header := range options.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	client := &http.Client{
		Transport: &HeaderRoundTripper{
			Transport: transport,
			Headers:   headers,
		},
		Timeout: time.Duration(options.Timeout) * time.Second,
	}

	return &HTTPClient{client: client}
}
