<!-- <div align="center">
  <br>
  <img src="recrawl.png" alt="recrawl logo" width="310">
</div>

<br> -->

<div align="center">
   <strong>recrawl</strong>: A Web URL crawler written in Go
</div>

<br>

<div align="center">
   <a href="https://github.com/root4loot/recrawl/actions/workflows/ci.yml">
      <img src="https://github.com/root4loot/recrawl/actions/workflows/ci.yml/badge.svg" alt="Build Status">
   </a>
   <a href="https://goreportcard.com/report/github.com/root4loot/recrawl">
      <img src="https://goreportcard.com/badge/github.com/root4loot/recrawl" alt="Go Report Card">
   </a>
</div>

<br>

<div align="center" style="color:red">
   <strong>Warning:</strong> This project is under active development. Expect bugs!
</div>

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
TARGETING:
  -i, --infile         file containing targets                   (one per line)
  -t, --target         target domain/url                         (comma-separated)
  -ih, --include-host  also crawls this host (if found)          (comma-separated)
  -eh, --exclude-host  do not crawl this host (if found)         (comma-separated)

CONFIGURATIONS:
  -c, --concurrency       number of concurrent requests          (Default: 20)
  -to, --timeout          max request timeout                    (Default: 10 seconds)
  -d, --delay             delay between requests                 (Default: 0 milliseconds)
  -dj, --delay-jitter     max jitter between requests            (Default: 0 milliseconds)
  -ua, --user-agent       set user agent                         (Default: Mozilla/5.0)
  -fr, --follow-redirects follow redirects                       (Default: true)
  -p, --proxy             set proxy                              (Default: none)
  -r, --resolvers         file containing list of resolvers      (Default: System DNS)
  -H, --header            set custom header                      (Default: none)
  -ph, --prefer-http      prefer HTTP over HTTPS for targets     (Default: false)
  -mp, --mine-params      mine HTTP parameters from responses     (Default: false)
  -ed, --enable-discovery enable web discovery fuzzing           (Default: false)

OUTPUT:
  -fs, --filter-status    filter by status code                  (comma-separated)
  -fe, --filter-ext       filter by extension                    (comma-separated)
  -v, --verbose           verbose output                         (use -vv for added verbosity)
  -o, --outfile           output results to given file
  -hs, --hide-status      hide status code from output
  -hw, --hide-warning     hide warnings from output
  -hm, --hide-media       hide media from output (images, fonts, etc.)
  -s, --silence           silence results from output
  -h, --help              display help
      --version           display version
```

## Parameter Mining

When enabled with `-mp/--mine-params`, recrawl mines likely HTTP parameters from:
- URL queries (e.g., `?q=term&page=2`)
- HTML forms (`<input>`, `<textarea>`, `<select>`)
- JavaScript bodies in `fetch`, `XMLHttpRequest`, and jQuery `$.post/$.ajax`
- HTML `data-*` attributes
- Hidden inputs
- GraphQL variable declarations
- WebSocket URLs (query string)

Parameters are grouped by certainty: high (URL/query + form fields), medium (JS/data/hidden/meta), low (reserved for weaker heuristics). Common non-parameters like `class`, `style`, etc. are ignored.

Notes:
- The parameter summary prints after the crawl finishes.
- Parameter names must be simple identifiers (letters, numbers, `_`, `-`) and start with a letter or underscore.

## Web Discovery

When enabled with `-ed/--enable-discovery`, recrawl performs web discovery fuzzing after normal crawling. Uses a curated 1022-entry wordlist containing:
- Common files and directories (from SecLists raft-small)
- API endpoints (`api/`, `api/auth`, etc.)
- NPM/dev paths (`package.json`, `node_modules`, `.env`, etc.)

**Scope Behavior**
- If no includes are defined, everything is in scope unless explicitly excluded.
- If includes are defined, only those targets are in scope; everything else is out of scope by default.
- Exclusions always take priority over inclusions.


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

# Only crawl hosts within explicit scope
➜ recrawl -t example.com -ih example.com,example.net

# Crawl and output mined params
➜ recrawl -t "https://example.org/?q=abc&page=1" --mine-params
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


This will crawl hackerone.com and filter JavaScript files. Sample output:

```sh
[recrawl] (INF) Included extensions: js
[recrawl] (INF) Concurrency: 20
[recrawl] (INF) Timeout: 10 seconds
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

    "github.com/root4loot/recrawl/pkg/recrawl"
    "github.com/root4loot/scope"
)

func main() {

	opts := recrawl.NewOptions().WithDefaults()
	s := scope.NewScope()

	_ = s.AddInclude("sub.example.com")     // also follow links here
	_ = s.AddExclude("support.example.com") // but don't follow links here

	opts.Scope = s
	opts.Concurrency = 2
	opts.Timeout = 10
	opts.Resolvers = []string{"8.8.8.8", "208.67.222.222"}
	opts.UserAgent = "recrawl"
    // Enable parameter mining
    opts.MineParams = true

	// Defaults already applied by NewOptions(); nothing else needed here

	r := recrawl.NewRecrawlWithOptions(opts)

    // process results as they come in
    go func() {
        for result := range r.Results {
            fmt.Println(result.StatusCode, result.RequestURL, result.Error)
        }
    }()

    // single run
    r.Run("example.com")

    if jsonStr, err := r.ParamMiner.ToJSON(); err == nil && jsonStr != "" {
        fmt.Println("Parameters:")
        fmt.Println(jsonStr)
    }

```

## Contributing

Contributions are very welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
