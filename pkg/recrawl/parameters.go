// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package recrawl

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

const (
	CertaintyHigh   = "high"
	CertaintyMedium = "medium"
	CertaintyLow    = "low"
)

type ParamMine struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	Certainty string `json:"certainty"`
	URL       string `json:"url"`
}

type ParamMiner struct {
	Parameters []ParamMine `json:"parameters"`
	mu         sync.RWMutex
}

var (
	reFormInput    = regexp.MustCompile(`<input[^>]*\bname\s*=\s*["']?([^"'\s>]+)`)
	reFormTextarea = regexp.MustCompile(`<textarea[^>]*\bname\s*=\s*["']?([^"'\s>]+)`)
	reFormSelect   = regexp.MustCompile(`<select[^>]*\bname\s*=\s*["']?([^"'\s>]+)`)

	reJSFetch     = regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)`)
	reJSXMLHttp   = regexp.MustCompile(`(?:xhr|xmlhttp)\.open\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']+)`)
	reJSPostData  = regexp.MustCompile(`(?:data|body)\s*:\s*(?:JSON\.stringify\()?\{([^}]*)\}`)
	reFetchBody   = regexp.MustCompile(`body\s*:\s*(?:JSON\.stringify\()?\{([^}]*)\}`)
	reJSAjaxData  = regexp.MustCompile(`\$\.(?:post|ajax)\s*\([^,]*,?\s*\{([^}]*)\}`)
	reDataAttr    = regexp.MustCompile(`data-([a-zA-Z][a-zA-Z0-9-]*)\s*=`)
	reHiddenInput = regexp.MustCompile(`<input[^>]*(?:type\s*=\s*["']?hidden["']?[^>]*name\s*=\s*["']?([^"'\s>]+)|name\s*=\s*["']?([^"'\s>]+)[^>]*type\s*=\s*["']?hidden["']?)`)
	reMetaContent = regexp.MustCompile(`<meta[^>]*name\s*=\s*["']([^"']+)["'][^>]*content\s*=\s*["']([^"']*api[^"']*)["']`)

	reGraphQLVar = regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*[a-zA-Z![\]]+`)

	reWebSocketURL = regexp.MustCompile(`new\s+WebSocket\s*\(\s*["']([^"']+)`)

	reObjKey = regexp.MustCompile(`["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*:`)
)

// NewParamMiner creates a new parameter miner
func NewParamMiner() *ParamMiner {
	return &ParamMiner{
		Parameters: make([]ParamMine, 0),
	}
}

// AddParameter adds a parameter (thread-safe)
func (pc *ParamMiner) AddParameter(param ParamMine) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.Parameters = append(pc.Parameters, param)
}

// GetUniqueParams returns unique parameters by name
func (pc *ParamMiner) GetUniqueParams() []ParamMine {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	seen := make(map[string]bool)
	var unique []ParamMine

	for _, param := range pc.Parameters {
		if !seen[param.Name] {
			unique = append(unique, param)
			seen[param.Name] = true
		}
	}

	return unique
}

// ExtractParameters extracts parameters from content and URL
func ExtractParameters(requestURL string, body []byte) []ParamMine {
	var params []ParamMine
	seen := make(map[string]bool)
	bodyStr := string(body)

	params = extractURLParams(requestURL, params, seen)
	params = extractFormParams(bodyStr, requestURL, params, seen)
	params = extractJSParams(bodyStr, requestURL, params, seen)
	params = extractDataAttributes(bodyStr, requestURL, params, seen)
	params = extractHiddenFields(bodyStr, requestURL, params, seen)
	params = extractMetaTags(bodyStr, requestURL, params, seen)

	return params
}

func extractURLParams(requestURL string, params []ParamMine, seen map[string]bool) []ParamMine {
	if u, err := url.Parse(requestURL); err == nil && u.RawQuery != "" {
		for key := range u.Query() {
			if !seen[key] && isValidParamName(key) {
				params = append(params, ParamMine{
					Name:      key,
					Type:      "query",
					Source:    "url",
					Certainty: CertaintyHigh,
					URL:       requestURL,
				})
				seen[key] = true
			}
		}
	}
	return params
}

func extractFormParams(body, requestURL string, params []ParamMine, seen map[string]bool) []ParamMine {
	matches := reFormInput.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] && isValidParamName(match[1]) {
			params = append(params, ParamMine{
				Name:      match[1],
				Type:      "form",
				Source:    "input",
				Certainty: CertaintyHigh,
				URL:       requestURL,
			})
			seen[match[1]] = true
		}
	}

	matches = reFormTextarea.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] && isValidParamName(match[1]) {
			params = append(params, ParamMine{
				Name:      match[1],
				Type:      "form",
				Source:    "textarea",
				Certainty: CertaintyHigh,
				URL:       requestURL,
			})
			seen[match[1]] = true
		}
	}

	matches = reFormSelect.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] && isValidParamName(match[1]) {
			params = append(params, ParamMine{
				Name:      match[1],
				Type:      "form",
				Source:    "select",
				Certainty: CertaintyHigh,
				URL:       requestURL,
			})
			seen[match[1]] = true
		}
	}

	return params
}

func extractJSParams(body, requestURL string, params []ParamMine, seen map[string]bool) []ParamMine {
	matches := reJSFetch.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = extractURLParamsFromString(match[1], requestURL, params, seen, "fetch", "api")
		}
	}

	matches = reJSXMLHttp.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = extractURLParamsFromString(match[1], requestURL, params, seen, "xhr", "api")
		}
	}

	matches = reJSPostData.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = extractObjectKeys(match[1], requestURL, params, seen, "post", "data", CertaintyMedium)
		}
	}

	matches = reJSAjaxData.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = extractObjectKeys(match[1], requestURL, params, seen, "ajax", "data", CertaintyMedium)
		}
	}

	matches = reFetchBody.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = extractObjectKeys(match[1], requestURL, params, seen, "fetch", "body", CertaintyMedium)
		}
	}

	matches = reGraphQLVar.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] && isValidParamName(match[1]) {
			params = append(params, ParamMine{
				Name:      match[1],
				Type:      "graphql",
				Source:    "variable",
				Certainty: CertaintyMedium,
				URL:       requestURL,
			})
			seen[match[1]] = true
		}
	}

	matches = reWebSocketURL.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = extractURLParamsFromString(match[1], requestURL, params, seen, "websocket", "url")
		}
	}

	return params
}

func extractDataAttributes(body, requestURL string, params []ParamMine, seen map[string]bool) []ParamMine {
	matches := reDataAttr.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] && isValidParamName(match[1]) {
			params = append(params, ParamMine{
				Name:      match[1],
				Type:      "data",
				Source:    "attribute",
				Certainty: CertaintyMedium,
				URL:       requestURL,
			})
			seen[match[1]] = true
		}
	}
	return params
}

func extractHiddenFields(body, requestURL string, params []ParamMine, seen map[string]bool) []ParamMine {
	matches := reHiddenInput.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		var name string
		if len(match) > 1 && match[1] != "" {
			name = match[1]
		} else if len(match) > 2 && match[2] != "" {
			name = match[2]
		}

		if name != "" && !seen[name] && isValidParamName(name) {
			params = append(params, ParamMine{
				Name:      name,
				Type:      "hidden",
				Source:    "input",
				Certainty: CertaintyMedium,
				URL:       requestURL,
			})
			seen[name] = true
		}
	}
	return params
}

func extractMetaTags(body, requestURL string, params []ParamMine, seen map[string]bool) []ParamMine {
	matches := reMetaContent.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] && isValidParamName(match[1]) {
			params = append(params, ParamMine{
				Name:      match[1],
				Type:      "meta",
				Source:    "tag",
				Certainty: CertaintyMedium,
				URL:       requestURL,
			})
			seen[match[1]] = true
		}
	}
	return params
}

func extractURLParamsFromString(urlStr, requestURL string, params []ParamMine, seen map[string]bool, paramType, source string) []ParamMine {
	if u, err := url.Parse(urlStr); err == nil && u.RawQuery != "" {
		for key := range u.Query() {
			if !seen[key] && isValidParamName(key) {
				params = append(params, ParamMine{
					Name:      key,
					Type:      paramType,
					Source:    source,
					Certainty: CertaintyMedium,
					URL:       requestURL,
				})
				seen[key] = true
			}
		}
	}
	return params
}

func extractObjectKeys(objStr, requestURL string, params []ParamMine, seen map[string]bool, paramType, source, certainty string) []ParamMine {
	matches := reObjKey.FindAllStringSubmatch(objStr, -1)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] && isValidParamName(match[1]) && !isCommonNonParam(match[1]) {
			params = append(params, ParamMine{
				Name:      match[1],
				Type:      paramType,
				Source:    source,
				Certainty: certainty,
				URL:       requestURL,
			})
			seen[match[1]] = true
		}
	}
	return params
}

func isValidParamName(name string) bool {
	if len(name) < 1 || len(name) > 50 {
		return false
	}
	if !regexp.MustCompile(`^[a-zA-Z_]`).MatchString(name) {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(name)
}

func isCommonNonParam(name string) bool {
	commonNonParams := []string{
		"type", "class", "style", "src", "href", "alt", "title",
		"width", "height", "method", "action", "target", "rel",
		"version", "status", "code", "message", "error", "success",
		"length", "size", "count", "total", "offset", "limit",
		"prototype", "constructor", "toString", "valueOf", "hasOwnProperty",
		"div", "span", "button", "form", "input", "img", "a",
	}

	name = strings.ToLower(name)
	for _, nonParam := range commonNonParams {
		if name == nonParam {
			return true
		}
	}
	return false
}

// FilterByType returns parameters filtered by type
func (pc *ParamMiner) FilterByType(paramType string) []ParamMine {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	var filtered []ParamMine
	for _, param := range pc.Parameters {
		if param.Type == paramType {
			filtered = append(filtered, param)
		}
	}
	return filtered
}

// FilterByCertainty returns parameters filtered by certainty
func (pc *ParamMiner) FilterByCertainty(certainty string) []ParamMine {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	var filtered []ParamMine
	for _, param := range pc.Parameters {
		if param.Certainty == certainty {
			filtered = append(filtered, param)
		}
	}
	return filtered
}

// ToJSON converts parameters to JSON
func (pc *ParamMiner) ToJSON() (string, error) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	data, err := json.MarshalIndent(pc.Parameters, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
