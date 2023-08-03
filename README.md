![Go version](https://img.shields.io/badge/Go-v1.19-blue.svg) [![Contribute](https://img.shields.io/badge/Contribute-Welcome-green.svg)](CONTRIBUTING.md)
# urlwalk

urlwalk is a Go library and command-line interface tool for recursively crawling websites and extracting URLs. It provides a simple yet flexible API for developers to integrate URL discovery into their projects. It's particularly useful for security professionals, web developers, and anyone who needs to extract and analyze URLs from websites.

### Key Features

- Discover hidden endpoints with urlwalk's versatile, regex-based approach.
- Avoid duplicate URLs and crawl traps for more accurate results.
- Customize your crawl with scoping capabilities for greater control.
- Target IPv4 addresses in addition to hostnames.
- Use urlwalk's easy-to-use CLI with piped input support.
- Integrate endpoint discovery into your own tools with urlwalk's library.
- Optimized for performance with the use of standard HTTP library and concurrent crawling.

## Installation

### Go
```
go install github.com/root4loot/urlwalk@master
```

### Docker
```
git clone https://github.com/root4loot/urlwalk.git && cd urlwalk
docker build -t urlwalk .
docker run -it urlwalk -h
```

## Usage
```
Usage: ./urlwalk [options] (-t <target>|-i targets.txt)

TARGETING:
   -t,    --target         target host                         (comma-separated)
   -i,    --infile         file containing targets             (one per line)
   -ih,   --include-host   also crawl this host (if found)     (comma-separated)
   -eh,   --exclude-host   do not crawl this host (if found)   (comma-separated)

CONFIGURATIONS:
   -c,    --concurrency    number of concurrent requests       (Default: 20 seconds)
   -to,   --timeout        max request timeout                 (Default: 10 seconds)
   -d,    --delay          delay between requests              (Default: 0 milliseconds)
   -dj,   --delay-jitter   max jitter between requests         (Default: 0 milliseconds)
   -ua,   --user-agent     set user agent                      (Default: urlwalk)
   -p,    --proxy          set proxy                           (Default: none)
   -r,    --resolvers      file containing list of resolvers   (Default: System DNS)

OUTPUT:
   -o,    --outfile        output results to given file
   -hs,   --hide-status    hide status code from output
   -hw,   --hide-warning   hide warnings from output
   -s,    --silence        silence results from output
   -v,    --version        display version
   -h,    --help           display help
```

## Example

Target `*.example.com`
```
➜ urlwalk -t example.com
``` 

Target `*.example.com` and `103.196.38.38`
```
➜ urlwalk -t example.com,103.196.38.38
```

Target all hosts in given file
```
➜ urlwalk -i targets.txt
```

Target `*.example.com` and `*.andme.com` (if found)
```
➜ urlwalk -t example.com -ih andme.com
```

Target all domains that contain `example`
```
➜ urlwalk -t example.com -ih example
```

Target `*.example.com` but avoid `me.example.com`  
```
➜ urlwalk -t example.com -eh me.example.com
```

### Example running

Extract URL's that end in `js`
```
➜ urlwalk -t hackerone.com -hs | grep 'js$'

https://www.hackerone.com/sites/default/files/js/js_Ikd9nsZ0AFAesOLgcgjc7F6CRoODbeqOn7SVbsXgALQ.js
https://www.hackerone.com/sites/default/files/js/js_hg8lQy2HP5Rw6yIz03HhGKfvnyySwjoFdqpvXgRJD6I.js
https://www.hackerone.com/sites/default/files/js/js_4FuDbOJrjJz7g2Uu2GQ6ZFtnbdPymNgBpNtoRkgooH8.js
https://www.hackerone.com/sites/default/files/js/js_zApVJ5sm-YHSWP4O5K9MqZ_6q4nDR3MciTUC3Pr1ogA.js
https://www.hackerone.com/sites/default/files/js/js_edjgXnk09wjvbZfyK_TkFKU4uhpo1LGgJBnFdeu6aH8.js
https://www.hackerone.com/themes/hacker_one/arg-tool/dist/js/chunk-vendors.7c6c2794.js
https://www.hackerone.com/themes/hacker_one/arg-tool/dist/js/app.ae1971c0.js
https://www.hackerone.com/sites/default/files/js/js_uj-ULd1j2hO5xijovTKN3LjREthKCuw6pep7CFoH0vQ.js

...
```

## As lib
```
go get github.com/root4loot/urlwalk@master
```

```go
package main

import (
	"fmt"

	"github.com/root4loot/urlwalk/pkg/options"
	"github.com/root4loot/urlwalk/pkg/runner"
)

func main() {
	options := options.Options{
		Include:     []string{"example.com"},
		Exclude:     []string{"support.hackerone.com"},
		Concurrency: 20,
		Timeout:     10,
		Delay:       0,
		DelayJitter: 0,
		Resolvers:   []string{"8.8.8.8", "208.67.222.222"},
		UserAgent:   "urlwalk",
	}

	runner := runner.NewRunner(&options)

	// create a separate goroutine to process the results as they come in
	go func() {
		for result := range runner.Results {
			fmt.Println(result.StatusCode, result.RequestURL, result.Error)
		}
	}()

	// single target
	runner.Run("hackerone.com")

	// multiple targets
	targets := []string{"hackerone.com", "bugcrowd.com"}
	runner.Run(targets...)
}

```

---

## Contributing

Contributions are welcome and greatly appreciated. To contribute to the project, please follow these steps:

1. Create an issue to discuss the change you would like to make.
2. Fork the repository and create a new branch for your feature or bug fix.
3. Make your changes and ensure that your code passes any existing tests.
4. Submit a pull request and explain your changes. Please reference the issue number that you created in step 1.
