<br>
<div align="center">
  <br>
  <img src="assets/logo.png" alt="recrawl logo" width="350">
</div>

<br>

<div align="center">
 <strong>recrawl</strong> is a Go library and command-line interface tool for crawling and extracting URLs from websites.
</div>

<br>

### Features

- Finds hidden links using pattern matching.
- Skips repeated URLs and traps to give cleaner results.
- Allows fine-tuned control over what to search for.
- Works with both web addresses and IP addresses.
- Simple command-line interface that supports chained commands.
- Easily add recrawl's features to your own projects.

## Installation

### Go
```
go install github.com/root4loot/recrawl@master
```

### Docker
```
git clone https://github.com/root4loot/recrawl.git && cd recrawl
docker build -t recrawl .
docker run -it recrawl -h
```

## Usage
```sh
Usage: ./recrawl [options] (-t <target> | -i <targets.txt>)

TARGETING:
   -t,    --target           target domain/url                                          (comma-separated)   
   -i,    --infile           file containing targets                                    (one per line)      
   -ih,   --include-host     also crawls this host (if found)                           (comma-separated)   
   -eh,   --exclude-host     do not crawl this host (if found)                          (comma-separated)   

CONFIGURATIONS:
   -c,    --concurrency      number of concurrent requests                              (Default: 20)
   -to,   --timeout          max request timeout                                        (Default: 10 seconds)
   -d,    --delay            delay between requests                                     (Default: 0 milliseconds)
   -dj,   --delay-jitter     max jitter between requests                                (Default: 0 milliseconds)
   -sr,   --skip-redundant   skip requests that only differ in parameter values         (Default: true)
   -ss,   --skip-same        skip crawling responses that have the same response body   (Default: false)
   -ua,   --user-agent       set user agent                                             (Default: recrawl)
   -p,    --proxy            set proxy                                                  (Default: none)
   -r,    --resolvers        file containing list of resolvers                          (Default: System DNS)

OUTPUT:
   -fs,   --filter-status    filter by status code                                      (comma-separated)   
   -v,    --verbose          verbose output (can be set multiple times)                                     
   -o,    --outfile          output results to given file
   -hs,   --hide-status      hide status code from output
   -hw,   --hide-warning     hide warnings from output
   -hm,   --hide-media       hide media from output (images, fonts, etc.)
   -s,    --silence          silence results from output
   -h,    --help             display help
          --version          display version
```

## Example

```sh
# Crawl *.example.com
➜ recrawl -t example.com

# Crawl *.example.com and IP address
➜ recrawl -t example.com,103.196.38.38

# Crawl all hosts in given file
➜ recrawl -i targets.txt

# Crawl *.example.com and also include *.example2.com if found
➜ recrawl -t example.com -ih example2.com

# Crawl all domains in target that contain the word example
➜ recrawl -t example.com -ih example

# Crawl *.example.com but avoid foo.example.com
➜ recrawl -t example.com -eh foo.example.com
```

### Example running

Crawl hackerone.com, hide status code and grep for lines ending in .js

```
➜ recrawl -t hackerone.com --hide-status | grep 'js$'

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
go get github.com/root4loot/recrawl@master
```

```go
package main

import (
	"fmt"

	"github.com/root4loot/recrawl/pkg/options"
	"github.com/root4loot/recrawl/pkg/runner"
)

func main() {
	options := options.Options{
		Include:     []string{"example.com"},
		Exclude:     []string{"support.hackerone.com"},
		Concurrency: 2,
		Timeout:     10,
		Delay:       0,
		DelayJitter: 0,
		Resolvers:   []string{"8.8.8.8", "208.67.222.222"},
		UserAgent:   "recrawl",
	}

	runner := runner.NewRunnerWithOptions(&options)

	// create a separate goroutine to process the results as they come in
	go func() {
		for result := range runner.Results {
			fmt.Println(result.StatusCode, result.RequestURL, result.Error)
		}
	}()

	// single target
	runner.Run("google.com")

	// multiple targets
	targets := []string{"hackerone.com", "bugcrowd.com"}
	runner.Run(targets...)
}

```

---

## Contributing

Contributions are very welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
