// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package util

import (
	"path/filepath"
	"strings"

	"github.com/root4loot/goutils/urlutil"
)

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

// GetMediaExtensions returns a slice of common media file extensions
func GetMediaExtensions() []string {
	return []string{
		".png", ".jpg", ".jpeg", ".woff", ".woff2", ".ttf", ".eot", ".svg", ".gif", ".ico", ".webp",
		".mp4", ".webm", ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".flv", ".avi", ".mov",
		".wmv", ".swf", ".mkv", ".m4v", ".3gp", ".3g2",
	}
}
