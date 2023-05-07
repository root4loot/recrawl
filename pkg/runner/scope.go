// Author: Daniel Antonsen (@danielantonsen)
// Distributed Under MIT License

package runner

import (
	"net"
	"regexp"
	"strings"

	"github.com/root4loot/urlwalk/pkg/log"
	"github.com/root4loot/urlwalk/pkg/util"

	"github.com/jpillora/go-tld"
)

type include struct {
	domain *tld.URL
	ip     *tld.URL
	word   string
}

type exclude struct {
	domain *tld.URL
	ip     *tld.URL
	word   string
}

var (
	re_singleWord = regexp.MustCompile(`^[A-Za-z0-9]+$`)
)

var includes []include
var excludes []exclude

// check checks if the url matches the include rule
func isIncluded(target *tld.URL, includes []include) bool {
	if target == nil {
		return false
	}

	for _, include := range includes {
		if util.IsIP(mainTarget.Host) {
			if ips, err := util.IPv4(target.Host); err == nil {
				for _, ip := range ips {
					if ip == mainTarget.Host {
						return true
					}
				}
			}
		}
		if include.domain != nil {
			match := func() bool {
				match1 := false
				// word
				if include.word != "" {
					if net.ParseIP(target.String()) == nil { // not IP
						match1 = target.Domain+"."+target.TLD == mainTarget.Domain+"."+mainTarget.TLD && target.Port == mainTarget.Port
					}
					return match1 || strings.Contains(target.Host, include.word)
					// IP
				} else if include.ip != nil {
					isTargetIP := func() bool {
						if ips, err := util.IPv4(target.Host); err == nil {
							for _, ip := range ips {
								if ip == include.ip.Host {
									return true
								}
							}
						}
						return false
					}
					return target.Host == include.ip.Host || isTargetIP()
					// domain
				} else if include.domain != nil && target.Domain != "" && target.TLD != "" {
					match2 := target.Domain == mainTarget.Domain &&
						target.TLD == mainTarget.TLD &&
						target.Port == mainTarget.Port

					match3 := target.Subdomain == include.domain.Subdomain &&
						target.Domain == include.domain.Domain &&
						target.TLD == include.domain.TLD &&
						target.Port == include.domain.Port

					match4 := target.Subdomain != "" &&
						include.domain.Subdomain == "" &&
						target.Domain == include.domain.Domain &&
						target.TLD == include.domain.TLD &&
						target.Port == include.domain.Port

					if match1 || match2 || match3 || match4 {
						return true
					}
				}
				return false
			}
			if match() {
				return true
			}
		}
	}
	return false
}

// check checks if the url matches the exclude rule
func isExcluded(u *tld.URL, excludes []exclude) bool {
	for _, exclude := range excludes {
		value := func() bool {
			if exclude.word != "" {
				return strings.Contains(u.Host, exclude.word)
			} else if exclude.domain != nil {
				return exclude.domain.Subdomain == u.Subdomain && exclude.domain.Domain == u.Domain && u.TLD == exclude.domain.TLD && u.Port == exclude.domain.Port
			} else if exclude.ip != nil {
				return exclude.ip.Host == u.Host
			}
			return false
		}
		if value() {
			return true
		}
	}
	return false
}

// setIncludes sets the includes for the runner
func (r *Runner) setIncludes() {
	for _, target := range r.Options.Include {
		u, _ := tld.Parse(target)
		if util.IsIP(target) {
			includes = append(includes, include{domain: nil, ip: u, word: ""})
		}
		if isSingleWord(target) {
			includes = append(includes, include{domain: nil, ip: nil, word: target})
		}
		if util.IsDomain(target) {
			includes = append(includes, include{domain: u, ip: nil, word: ""})
		}
	}
}

// setExcludes sets the excludes for the runner
func (r *Runner) setExcludes() {
	for _, target := range r.Options.Exclude {
		u, _ := tld.Parse(target)
		if util.IsIP(target) {
			excludes = append(excludes, exclude{domain: nil, ip: u, word: ""})
		}
		if isSingleWord(target) {
			excludes = append(excludes, exclude{domain: nil, ip: nil, word: target})
		}
		if util.IsDomain(target) {
			excludes = append(excludes, exclude{domain: u, ip: nil, word: ""})
		}
	}
}

// setIncludeScope determines if the url is in scope
func (r *Runner) inScope(u *tld.URL) bool {
	return isIncluded(u, includes) && !isExcluded(u, excludes)
}

// setScope sets the scope for the runner
func (r *Runner) setScope(mainTarget string) {
	u, err := tld.Parse(mainTarget)

	if err != nil {
		log.Fatalf("error parsing main target: %s", err)
	}
	r.Options.Include = append(r.Options.Include, u.Host) // always add maintarget to scope
	r.setIncludes()
	r.setExcludes()
}

// isSingleWord checks if the string is a word
func isSingleWord(s string) bool {
	return re_singleWord.MatchString(s)
}
