// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package util

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// HasFile checks if a URL has a file extension
func HasFile(url string) bool {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	parts := strings.Split(url, "/")
	if len(parts) > 1 {
		if strings.Contains(parts[len(parts)-1], ".") {
			return true
		}
	}
	return false
}

// HasScheme checks if a URL has a scheme
func HasScheme(url string) bool {
	re := regexp.MustCompile(`^\w+?:\/\/\w+`)
	return re.MatchString(url)
}

// HasParam checks if a URL has a parameter
func HasParam(str string) bool {
	re := regexp.MustCompile(`\?.*`)
	return re.MatchString(str)
}

// Ensure ensures a URL has a scheme
func EnsureScheme(target string) string {
	if target != "" && !HasScheme(target) {
		return "http://" + target
	}
	return target
}

// IsDomain checks if string looks like a domain
func IsDomain(str string) bool {
	re := regexp.MustCompile(`^\w+\.\w+.*`)
	return re.MatchString(str)
}

// IsIP checks if a string is an IP
func IsIP(str string) bool {
	re := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	return re.MatchString(str)
}

// IsURL checks if a string is a URL
func IsURL(str string) bool {
	re := regexp.MustCompile(`^(https?:\/\/).*[a-zA-Z]$`)
	return re.MatchString(str)
}

// HasURL checks if a string has URL
func HasURL(str string) bool {
	re := regexp.MustCompile(`(https?:\/\/).*[a-zA-Z]$`)
	return re.MatchString(str)
}

// GetURL gets a URL from a string
func GetURL(host string) string {
	re := regexp.MustCompile(`(https?:\/\/).*[a-zA-Z]$`)
	return re.FindString(host)
}

// isTextContentType checks if a string is a certain content-type
func IsTextContentType(str string) bool {
	var nonTextContentTypes = []string{
		"application/octet-stream",
		"image/*",
		"audio/*",
		"video/*",
		"application/pdf",
		"application/zip",
		"application/x-gzip",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
		"application/vnd.ms-word",
	}
	for _, i := range nonTextContentTypes {
		if i == str {
			return false
		}
		part := strings.Split(i, "/")[0]
		if part == "image" || part == "audio" || part == "video" {
			return false
		}
	}
	return true
}

// Remove removes a string from a slice
func Remove(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

// Unique removes duplicates from a slice
func Unique(str []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range str {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			if entry != "" {
				list = append(list, entry)
			}
		}
	}
	return list
}

// IsPrintable checks if a string is printable
func IsPrintable(str string) bool {
	for _, r := range str {
		if !unicode.IsPrint(r) && !strconv.IsPrint(r) {
			return false
		}
	}
	return true
}

// IsBinaryString checks if a string is binary
func IsBinaryString(str string) bool {
	for _, b := range []byte(str) {
		if b < 32 || b > 126 {
			return true
		}
	}
	return false
}

// ReadFileLines reads a file line by line
func ReadFileLines(filepath string) (lines []string, err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return
}

// IPv4 returns the IPv4 address of a domain
func IPv4(domain string) ([]string, error) {
	addrs, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}
	var aRecords []string
	for _, addr := range addrs {
		if addr.To4() != nil {
			aRecords = append(aRecords, addr.String())
		}
	}
	if len(aRecords) == 0 {
		return nil, fmt.Errorf("no A records found for domain: %s", domain)
	}
	return aRecords, nil
}
