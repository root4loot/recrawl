// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package util

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/root4loot/goutils/urlutil"
)

// HasParam checks if a URL has a parameter
func HasParam(str string) bool {
	re := regexp.MustCompile(`\?.*`)
	return re.MatchString(str)
}

// Ensure ensures a URL has a scheme
func EnsureScheme(target string) string {
	if target != "" && !urlutil.HasScheme(target) {
		return "http://" + target
	}
	return target
}

// AddSlashIfNeeded adds a "/" suffix to a URL if needed
func AddSlashIfNeeded(url string) string {
	if !strings.HasSuffix(url, "/") {
		if strings.Contains(url, "?") || strings.Contains(url, "#") || strings.Contains(url, "=") {
			// URL has query params or a fragment, don't add a "/" suffix
			return url
		} else if strings.Contains(filepath.Ext(url), ".") {
			// URL ends with a file extension, don't add a "/" suffix
			return url
		} else {
			// URL needs a "/" suffix
			return url + "/"
		}
	} else {
		// URL already has a "/" suffix
		return url
	}
}

// RemoveSlashUnwanted removes an unwanted "/" suffix from a URL
func RemoveSlashUnwanted(url string) string {
	if strings.HasSuffix(url, "/") && (strings.Contains(url, "?") || strings.Contains(url, "#") || strings.Contains(url, "=")) {
		return url[:len(url)-1]
	}
	return url
}

// TrimDoubleSlashes trims double slashes from a URL
func TrimDoubleSlashes(target string) string {
	if strings.HasPrefix(target, "http://") {
		target = "http://" + strings.Replace(target[len("http://"):], "//", "/", -1)
	} else if strings.HasPrefix(target, "https://") {
		target = "https://" + strings.Replace(target[len("https://"):], "//", "/", -1)
	} else {
		// Replace all other occurrences of "//"
		target = strings.Replace(target, "//", "/", -1)
	}
	return target
}

// IsFile checks if string looks like a domain
func IsFile(str string) bool {
	re := regexp.MustCompile(`^\w+\.\w+.*`)
	return re.MatchString(str)
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
