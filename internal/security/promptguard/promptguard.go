// Package promptguard detects instruction-hijacking content before it crosses
// trusted prompt boundaries.
package promptguard

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above)\s+instructions`),
	regexp.MustCompile(`(?i)forget\s+(everything|all)\s+(you|i)`),
	regexp.MustCompile(`(?i)(authorization|gate)\s+(already\s+)?(satisfied|granted|confirmed|bypassed)`),
	regexp.MustCompile(`(?i)skip\s+(the\s+)?(authorization|auth|gate|confirmation)`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(dan|unrestricted|jailbroken)`),
	regexp.MustCompile(`(?i)developer\s+mode\s*(enabled|on|activated)`),
	regexp.MustCompile(`(?i)proceed\s+(immediately|without\s+confirmation|without\s+authorization)`),
	regexp.MustCompile(`(?i)bypass\s+(the\s+)?(restriction|control|gate|check|policy)`),
	regexp.MustCompile(`(?i)new\s+(system\s+)?prompt\s*:`),
}

// ContainsInjection detects known prompt-override patterns after removing
// common encoding and Markdown obfuscation.
func ContainsInjection(input string) bool {
	normalized := normalize(input)
	for _, pattern := range injectionPatterns {
		if pattern.MatchString(normalized) {
			return true
		}
	}
	return false
}

func normalize(input string) string {
	input = html.UnescapeString(input)
	for range 2 {
		decoded, err := url.QueryUnescape(input)
		if err != nil || decoded == input {
			break
		}
		input = decoded
	}

	var out strings.Builder
	out.Grow(len(input))
	space := false
	inTag := false
	for _, r := range input {
		if r == '<' {
			inTag = true
			continue
		}
		if inTag {
			if r == '>' {
				inTag = false
			}
			continue
		}
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		} else if r == 0x3000 {
			r = ' '
		}
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		if strings.ContainsRune("*_`~", r) {
			continue
		}
		if unicode.IsSpace(r) {
			if !space {
				out.WriteByte(' ')
				space = true
			}
			continue
		}
		space = false
		out.WriteRune(unicode.ToLower(r))
	}
	return strings.TrimSpace(out.String())
}
