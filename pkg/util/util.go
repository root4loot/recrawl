// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package util

// GetMediaExtensions returns a slice of common media file extensions
func GetMediaExtensions() []string {
	return []string{
		".png", ".jpg", ".jpeg", ".woff", ".woff2", ".ttf", ".eot", ".svg", ".gif", ".ico", ".webp",
		".mp4", ".webm", ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".flv", ".avi", ".mov",
		".wmv", ".swf", ".mkv", ".m4v", ".3gp", ".3g2",
	}
}
