package recrawl

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/root4loot/goutils/urlutil"
)

type HTTPClient struct {
	client *http.Client
}

// HeaderRoundTripper wraps an http.RoundTripper
type HeaderRoundTripper struct {
	Transport http.RoundTripper
	Headers   http.Header
}

// RoundTrip executes HTTP transaction with custom headers
func (hrt *HeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range hrt.Headers {
		req.Header[k] = v
	}
	return hrt.Transport.RoundTrip(req)
}

// NewHTTPClient creates HTTP client with options
func NewHTTPClient(options *Options) *HTTPClient {
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost:   options.Concurrency,
		MaxConnsPerHost:       options.Concurrency,
		TLSHandshakeTimeout:   time.Duration(options.Timeout) * time.Second,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: time.Duration(options.Timeout) * time.Second,
	}

	if len(options.Resolvers) > 0 {
		transport.DialContext = createCustomDialer(options.Resolvers, time.Duration(options.Timeout)*time.Second)
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

// createCustomDialer creates a dialer with custom DNS resolvers using miekg/dns
func createCustomDialer(resolvers []string, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		if net.ParseIP(host) != nil {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
		}

		ip, err := resolveHostWithCustomResolvers(host, resolvers, timeout)
		if err != nil {
			return nil, err
		}

		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

// resolveHostWithCustomResolvers resolves hostname with custom DNS
func resolveHostWithCustomResolvers(hostname string, resolvers []string, timeout time.Duration) (string, error) {
	c := &dns.Client{Timeout: timeout}
	
	for _, resolver := range resolvers {
		if !strings.Contains(resolver, ":") {
			resolver = resolver + ":53"
		}
		
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
		r, _, err := c.Exchange(m, resolver)
		if err == nil && len(r.Answer) > 0 {
			for _, ans := range r.Answer {
				if a, ok := ans.(*dns.A); ok {
					return a.A.String(), nil
				}
			}
		}
		
		m.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
		r, _, err = c.Exchange(m, resolver)
		if err == nil && len(r.Answer) > 0 {
			for _, ans := range r.Answer {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					return aaaa.AAAA.String(), nil
				}
			}
		}
	}
	
	return "", &net.DNSError{Err: "no IP addresses found", Name: hostname, IsNotFound: true}
}
