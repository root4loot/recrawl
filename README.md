<br>
<div align="center">
  <br>
  <img src="assets/logo.png" alt="recrawl logo" width="310">
</div>

<br>

<div align="center">
   <strong>recrawl</strong>: A Web URL crawler written in Go
</div>

<br>

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
   -ua,   --user-agent       set user agent                                             (Default: Mozilla/5.0)
   -p,    --proxy            set proxy                                                  (Default: none)
   -r,    --resolvers        file containing list of resolvers                          (Default: System DNS)

OUTPUT:
   -fs,   --filter-status    filter by status code                                      (comma-separated)   
   -fe,   --filter-ext       filter by extension                                        (comma-separated)   
   -v,    --verbose          verbose output (use -vv for added verbosity)                                   
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

Running recrawl against hackerone.com to filter JavaScript files:

```sh
➜ recrawl -t hackerone.com --filter-ext js
```

<details open style="background-color: #f0f0f0;">
<summary style="font-weight: bold; color: #333; background-color: #ddd; padding: 5px;">Other ways to set target</summary>

Pipe the target URL
```sh
➜ echo hackerone.com | recrawl
```

Pipe a file containing targets 
```sh
➜ echo targets.txt | recrawl
```

Use the -i option to provide a file with targets
```sh
➜ recrawl -i targets.txt
```
</details>


This will crawl hackerone.com and filter JavaScript files. Here's a sample output:

```sh
[recrawl] (INF) Included extensions: js
[recrawl] (INF) Concurrency: 20
[recrawl] (INF) Timeout: 10 seconds
[recrawl] (INF) Crawling target: http://hackerone.com
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_EOrKavGmjAkpIaCW_cpGJ240OpVZev_5NI-WGIx5URg.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_5JbqBIuSpSQJk1bRx1jnlE-pARPyPPF5H07tKLzNC80.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_a7_tjanmGpd_aITZ38ofV8QT2o2axkGnWqPwKna1Wf0.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_xF9mKu6OVNysPMy7w3zYTWNPFBDlury_lEKDCfRuuHs.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_coYiv6lRieZN3l0IkRYgmvrMASvFk2BL-jdq5yjFbGs.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_Z1eePR_Hbt8TCXBt3JlFoTBdW2k9-IFI3f96O21Dwdw.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_LEbRIvnUToqIQrjG9YpPgaIHK6o77rKVGouOaWLGI5k.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_ol7H2KkxPxe7E03XeuZQO5qMcg0RpfSOgrm_Kg94rOs.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_p5BLPpvjnAGGBCPUsc4EmBUw9IUJ0jMj-QY_1ZpOKG4.js
[recrawl] (RES) 200 https://www.hackerone.com/sites/default/files/js/js_V5P0-9GKw8QQe-7oWrMD44IbDva6o8GE-cZS7inJr-g.js
...
```

Results can be piped to stdout:

```sh
➜ recrawl -t hackerone.com --hide-status --filter-ext js | cat
```

Or saved to specified file:

```sh
➜ recrawl -t hackerone.com --hide-status --filter-ext js -o results.txt
```

## As lib
```sh
go get -u github.com/root4loot/recrawl
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

## Todo

- Clean up worker
- Headless browsing
- Output and filter by MIME
- Option to perform dirbusting / custom wordlist
- Dirbusting / custom wordlist
- Respect robots.txt option

---

## Contributing

Contributions are very welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
