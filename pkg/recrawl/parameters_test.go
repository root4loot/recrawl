// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package recrawl

import (
	"strings"
	"testing"
)

func TestParameterExtraction(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		html     string
    		expected map[string]ParamMine
	}{
		{
			name: "URL query parameters",
			url:  "https://example.com/search?q=test&page=1&category=books",
			html: "<html><body>Simple page</body></html>",
			expected: map[string]ParamMine{
				"q":        {Name: "q", Type: "query", Source: "url", Certainty: CertaintyHigh},
				"page":     {Name: "page", Type: "query", Source: "url", Certainty: CertaintyHigh},
				"category": {Name: "category", Type: "query", Source: "url", Certainty: CertaintyHigh},
			},
		},
		{
			name: "HTML form fields",
			url:  "https://example.com/form",
			html: `<html><body>
				<form>
					<input type="text" name="username" />
					<input type="password" name="password" />
					<textarea name="message"></textarea>
					<select name="country">
						<option value="us">US</option>
					</select>
				</form>
			</body></html>`,
			expected: map[string]ParamMine{
				"username": {Name: "username", Type: "form", Source: "input", Certainty: CertaintyHigh},
				"password": {Name: "password", Type: "form", Source: "input", Certainty: CertaintyHigh},
				"message":  {Name: "message", Type: "form", Source: "textarea", Certainty: CertaintyHigh},
				"country":  {Name: "country", Type: "form", Source: "select", Certainty: CertaintyHigh},
			},
		},
		{
			name: "JavaScript fetch calls",
			url:  "https://example.com/api",
			html: `<html><body>
				<script>
					fetch('/api/users?limit=10&offset=20');
					fetch('/api/posts', {
						method: 'POST',
						body: JSON.stringify({title: 'test', content: 'hello'})
					});
				</script>
			</body></html>`,
			expected: map[string]ParamMine{
				"limit":   {Name: "limit", Type: "fetch", Source: "api", Certainty: CertaintyMedium},
				"offset":  {Name: "offset", Type: "fetch", Source: "api", Certainty: CertaintyMedium},
				"content": {Name: "content", Type: "post", Source: "data", Certainty: CertaintyMedium},
			},
		},
		{
			name: "Data attributes",
			url:  "https://example.com/data",
			html: `<html><body>
				<div data-user-id="123" data-api-key="abc"></div>
				<button data-action="submit" data-target-url="/api"></button>
			</body></html>`,
			expected: map[string]ParamMine{
				"user-id":    {Name: "user-id", Type: "data", Source: "attribute", Certainty: CertaintyMedium},
				"api-key":    {Name: "api-key", Type: "data", Source: "attribute", Certainty: CertaintyMedium},
				"action":     {Name: "action", Type: "data", Source: "attribute", Certainty: CertaintyMedium},
				"target-url": {Name: "target-url", Type: "data", Source: "attribute", Certainty: CertaintyMedium},
			},
		},
		{
			name: "Hidden form fields",
			url:  "https://example.com/hidden",
			html: `<html><body>
				<form>
					<input type="hidden" name="csrf_token" value="abc123" />
					<input type="hidden" name="session_id" value="xyz789" />
				</form>
			</body></html>`,
			expected: map[string]ParamMine{
				"csrf_token": {Name: "csrf_token", Type: "form", Source: "input", Certainty: CertaintyHigh},
				"session_id": {Name: "session_id", Type: "form", Source: "input", Certainty: CertaintyHigh},
			},
		},
		{
			name: "AJAX data objects",
			url:  "https://example.com/ajax",
			html: `<html><body>
				<script>
					$.post('/api/update', {
						user_id: 123,
						email: 'test@example.com'
					});
					
					$.ajax({
						url: '/api/save',
						data: {
							name: 'John',
							age: 30
						}
					});
				</script>
			</body></html>`,
			expected: map[string]ParamMine{
				"user_id": {Name: "user_id", Type: "ajax", Source: "data", Certainty: CertaintyMedium},
				"email":   {Name: "email", Type: "ajax", Source: "data", Certainty: CertaintyMedium},
				"name":    {Name: "name", Type: "post", Source: "data", Certainty: CertaintyMedium},
				"age":     {Name: "age", Type: "post", Source: "data", Certainty: CertaintyMedium},
			},
		},
		{
			name: "GraphQL variables",
			url:  "https://example.com/graphql",
			html: `<html><body>
				<script>
					const query = '
						query GetUser($userId: ID!, $includeProfile: Boolean) {
							user(id: $userId) {
								name
							}
						}
					';
				</script>
			</body></html>`,
			expected: map[string]ParamMine{
				"userId":         {Name: "userId", Type: "graphql", Source: "variable", Certainty: CertaintyMedium},
				"includeProfile": {Name: "includeProfile", Type: "graphql", Source: "variable", Certainty: CertaintyMedium},
			},
		},
		{
			name: "WebSocket URLs",
			url:  "https://example.com/ws",
			html: `<html><body>
				<script>
					const ws = new WebSocket('wss://example.com/ws?token=abc123&room=general');
				</script>
			</body></html>`,
			expected: map[string]ParamMine{
				"token": {Name: "token", Type: "websocket", Source: "url", Certainty: CertaintyMedium},
				"room":  {Name: "room", Type: "websocket", Source: "url", Certainty: CertaintyMedium},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := ExtractParameters(tc.url, []byte(tc.html))

			// Create map of extracted parameters for easy comparison
			extracted := make(map[string]ParamMine)
			for _, param := range params {
				extracted[param.Name] = param
			}

			// Check that all expected parameters were found
			for expectedName, expectedParam := range tc.expected {
				found, exists := extracted[expectedName]
				if !exists {
					t.Errorf("Expected parameter %q not found", expectedName)
					continue
				}

				if found.Type != expectedParam.Type {
					t.Errorf("Parameter %q: expected type %q, got %q", expectedName, expectedParam.Type, found.Type)
				}

				if found.Source != expectedParam.Source {
					t.Errorf("Parameter %q: expected source %q, got %q", expectedName, expectedParam.Source, found.Source)
				}

				if found.Certainty != expectedParam.Certainty {
					t.Errorf("Parameter %q: expected certainty %q, got %q", expectedName, expectedParam.Certainty, found.Certainty)
				}
			}

			// Check for unexpected parameters (basic validation)
			for extractedName := range extracted {
				if _, expected := tc.expected[extractedName]; !expected {
					t.Logf("Unexpected parameter found: %q (this might be OK depending on extraction logic)", extractedName)
				}
			}
		})
	}
}

func TestParameterValidation(t *testing.T) {
	testCases := []struct {
		name     string
		param    string
		expected bool
	}{
		{"valid alphanumeric", "username123", true},
		{"valid underscore", "user_name", true},
		{"valid hyphen", "user-name", true},
		{"starts with letter", "abc123", true},
		{"starts with underscore", "_private", true},
		{"single char", "a", true},
		{"too long", strings.Repeat("a", 51), false},
		{"starts with number", "123abc", false},
		{"contains space", "user name", false},
		{"contains special char", "user@name", false},
		{"empty string", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidParamName(tc.param)
			if result != tc.expected {
				t.Errorf("isValidParamName(%q) = %v, expected %v", tc.param, result, tc.expected)
			}
		})
	}
}

func TestCommonNonParamFiltering(t *testing.T) {
	commonNonParams := []string{"type", "class", "style", "src", "href", "div", "span", "button"}

	for _, nonParam := range commonNonParams {
		if !isCommonNonParam(nonParam) {
			t.Errorf("isCommonNonParam(%q) should return true", nonParam)
		}
	}

	validParams := []string{"username", "api_key", "user_id", "search_query"}
	for _, param := range validParams {
		if isCommonNonParam(param) {
			t.Errorf("isCommonNonParam(%q) should return false", param)
		}
	}
}

func TestParameterCollection(t *testing.T) {
    collection := NewParamMiner()

    if collection == nil {
        t.Fatal("NewParamMiner() returned nil")
    }

	// Test adding parameters
	param1 := ParamMine{Name: "username", Type: "form", Source: "input", Certainty: CertaintyHigh, URL: "http://test.com"}
	param2 := ParamMine{Name: "password", Type: "form", Source: "input", Certainty: CertaintyHigh, URL: "http://test.com"}
	param3 := ParamMine{Name: "api_key", Type: "query", Source: "url", Certainty: CertaintyMedium, URL: "http://test.com"}

	collection.AddParameter(param1)
	collection.AddParameter(param2)
	collection.AddParameter(param3)

	// Test GetUniqueParams
	unique := collection.GetUniqueParams()
	if len(unique) != 3 {
		t.Errorf("Expected 3 unique parameters, got %d", len(unique))
	}

	// Test duplicate handling
	collection.AddParameter(param1) // Add duplicate
	unique = collection.GetUniqueParams()
	if len(unique) != 3 {
		t.Errorf("Expected 3 unique parameters after adding duplicate, got %d", len(unique))
	}

	// Test FilterByType
	formParams := collection.FilterByType("form")
	if len(formParams) != 3 {
		t.Errorf("Expected 3 form parameters, got %d", len(formParams))
	}

	queryParams := collection.FilterByType("query")
	if len(queryParams) != 1 {
		t.Errorf("Expected 1 query parameter, got %d", len(queryParams))
	}

	// Test FilterByCertainty
	highCertainty := collection.FilterByCertainty(CertaintyHigh)
	if len(highCertainty) != 3 {
		t.Errorf("Expected 3 high certainty parameters, got %d", len(highCertainty))
	}

	mediumCertainty := collection.FilterByCertainty(CertaintyMedium)
	if len(mediumCertainty) != 1 {
		t.Errorf("Expected 1 medium certainty parameter, got %d", len(mediumCertainty))
	}
}

func TestParameterExtractionWithCrawler(t *testing.T) {
	// Test that parameter extraction integrates properly with the crawler
	opts := NewOptions()
	opts.MineParams = true

	crawler := NewRecrawlWithOptions(opts)

	if crawler.ParamMiner == nil {
		t.Fatal("ParamMiner should be initialized when MineParams is true")
	}

	// Test HTML with parameters
	testHTML := `<html><body>
		<form>
			<input type="text" name="search" />
			<input type="hidden" name="token" value="abc123" />
		</form>
		<script>
			fetch('/api/data?limit=10');
		</script>
	</body></html>`

	params := ExtractParameters("https://example.com/test?page=1", []byte(testHTML))

	// Should extract at least: page (query), search (form), token (hidden), limit (fetch)
	if len(params) < 4 {
		t.Errorf("Expected at least 4 parameters, got %d", len(params))
	}

	// Add parameters to collection
	for _, param := range params {
		crawler.ParamMiner.AddParameter(param)
	}

	unique := crawler.ParamMiner.GetUniqueParams()
	if len(unique) < 4 {
		t.Errorf("Expected at least 4 unique parameters in collection, got %d", len(unique))
	}
}

func TestJSONOutput(t *testing.T) {
    collection := NewParamMiner()

	param1 := ParamMine{Name: "username", Type: "form", Source: "input", Certainty: CertaintyHigh, URL: "http://test.com"}
	param2 := ParamMine{Name: "api_key", Type: "query", Source: "url", Certainty: CertaintyMedium, URL: "http://test.com"}

	collection.AddParameter(param1)
	collection.AddParameter(param2)

	jsonStr, err := collection.ToJSON()
	if err != nil {
		t.Errorf("ToJSON() returned error: %v", err)
	}

	if jsonStr == "" {
		t.Error("ToJSON() returned empty string")
	}

	// Basic JSON validation
	if !strings.Contains(jsonStr, "username") || !strings.Contains(jsonStr, "api_key") {
		t.Error("JSON output doesn't contain expected parameter names")
	}
}

func TestEdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		html     string
		minCount int
		maxCount int
	}{
		{
			name:     "empty HTML",
			url:      "https://example.com",
			html:     "",
			minCount: 0,
			maxCount: 0,
		},
		{
			name:     "malformed HTML",
			url:      "https://example.com",
			html:     "<input name=username><input name='password'><input name=\"email\">",
			minCount: 2, // Should handle various quote patterns
			maxCount: 5,
		},
		{
			name:     "JavaScript with complex quotes",
			url:      "https://example.com",
			html:     `<script>fetch("/api/test?param='value'&other=\"test\"")</script>`,
			minCount: 1, // Should extract at least some parameters
			maxCount: 3,
		},
		{
			name:     "mixed parameter sources",
			url:      "https://example.com/search?q=test",
			html:     `<form><input name="username"/></form><script>$.post('/api', {data: 'value'})</script>`,
			minCount: 2, // q (URL) + username (form) + possibly data (JS)
			maxCount: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := ExtractParameters(tc.url, []byte(tc.html))
			count := len(params)

			if count < tc.minCount {
				t.Errorf("Expected at least %d parameters, got %d", tc.minCount, count)
			}

			if count > tc.maxCount {
				t.Errorf("Expected at most %d parameters, got %d", tc.maxCount, count)
			}
		})
	}
}
