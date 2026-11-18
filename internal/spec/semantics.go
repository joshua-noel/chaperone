package spec

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// TokenGraceSeconds is the grace past budget.minutes a run token may live
// (spec section 4; checkRunTokenClaims).
const TokenGraceSeconds = 300

// ClockSkewSeconds is how far ahead of the verifier's clock iat may be.
const ClockSkewSeconds = 30

// OpAllowed reports whether op matches a profile allow pattern: exact, or a
// "prefix.*" wildcard.
func OpAllowed(op string, patterns []string) bool {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, ".*"); ok {
			if strings.HasPrefix(op, prefix+".") {
				return true
			}
		} else if p == op {
			return true
		}
	}
	return false
}

// TokenCheck is the verifier state CheckRunTokenClaims needs.
type TokenCheck struct {
	Now     time.Time
	Revoked map[string]bool // jti values in the revocation set
}

// CheckRunTokenClaims is the verifier-side check of run token claims beyond the
// schema, in the spec's order and wording (checkRunTokenClaims). profile is the
// signed generic profile the token's profile.digest names, or nil for an
// interim host token, which has no profile; its high-impact requests always
// need an approval (policy, not this function). Ops are checked against the
// generic profile only. It returns the problems; none means the claims hold.
// Match callers on the leading cause codes (TOKEN_EXPIRED, TOKEN_INVALID,
// TOKEN_REVOKED, SCOPE_BRANCH, OP_NOT_IN_TOKEN), not on prose.
func CheckRunTokenClaims(c RunTokenClaims, profile *GenericProfile, v TokenCheck) []string {
	var problems []string
	now := v.Now.Unix()
	scope := c.TaskScope
	if c.Sub != "run:"+c.RunID {
		problems = append(problems, "sub is not 'run:' + run_id")
	}
	if !(c.Exp > c.Iat) {
		problems = append(problems, "exp is not after iat")
	}
	if c.Iat > now+ClockSkewSeconds {
		problems = append(problems, "TOKEN_INVALID: iat is more than 30 seconds in the future")
	}
	if now >= c.Exp {
		problems = append(problems, "TOKEN_EXPIRED")
	}
	if v.Revoked[c.JTI] {
		problems = append(problems, "TOKEN_REVOKED")
	}
	if c.Exp-c.Iat > int64(c.Budget.Minutes)*60+TokenGraceSeconds {
		problems = append(problems, "token lifetime exceeds budget.minutes plus the 5 minute grace")
	}
	if strings.Contains(scope.Branch, "{") {
		problems = append(problems, "branch still has an unexpanded placeholder")
	}
	if scope.Branch == scope.Base {
		problems = append(problems, "SCOPE_BRANCH: the pushable branch is the base branch")
	}
	if profile != nil {
		if c.Profile.Name != profile.Profile {
			problems = append(problems, "token profile name differs from the profile")
		}
		if !strings.HasPrefix(scope.Branch, profile.BranchPrefix) {
			problems = append(problems, fmt.Sprintf("SCOPE_BRANCH: branch '%s' does not start with the profile prefix '%s'", scope.Branch, profile.BranchPrefix))
		}
		for _, op := range scope.Ops {
			if !OpAllowed(op, profile.Ops.Allow) {
				problems = append(problems, fmt.Sprintf("OP_NOT_IN_TOKEN: op '%s' is not allowed by the profile", op))
			}
		}
	} else if c.Isolation != "host" {
		problems = append(problems, "a token without a profile must have isolation 'host'")
	}
	return problems
}

// NormalizeUsage converts one provider call's raw usage to the ledger's
// model.usage attributes. The ledger follows the OTel rule: gen_ai.usage.input_tokens
// INCLUDES cache read and cache write tokens. Only providers whose raw fields
// were checked have a normalizer; any other provider is an error, so an
// unchecked adapter cannot write a total that double-counts or drops cache
// tokens. raw is the provider's usage object as decoded JSON. Values in the
// result are int64.
//
//	anthropic  input_tokens EXCLUDES cache tokens; cache_read_input_tokens and
//	           cache_creation_input_tokens are separate and are added.
//	openai     input_tokens is the total and includes input_tokens_details.cached_tokens
//	           and input_tokens_details.cache_write_tokens.
func NormalizeUsage(provider string, raw map[string]any) (map[string]any, error) {
	count := func(m map[string]any, key string, required bool) (int64, error) {
		v, ok := m[key]
		if !ok || v == nil {
			if required {
				return 0, fmt.Errorf("raw usage has no %q", key)
			}
			return 0, nil
		}
		f, ok := v.(float64)
		if !ok || f != float64(int64(f)) || f < 0 {
			return 0, fmt.Errorf("raw usage %q is not a non-negative integer", key)
		}
		return int64(f), nil
	}
	var input, read, write int64
	var err error
	in, err := count(raw, "input_tokens", true)
	if err != nil {
		return nil, err
	}
	out, err := count(raw, "output_tokens", true)
	if err != nil {
		return nil, err
	}
	switch provider {
	case "anthropic":
		if read, err = count(raw, "cache_read_input_tokens", false); err != nil {
			return nil, err
		}
		if write, err = count(raw, "cache_creation_input_tokens", false); err != nil {
			return nil, err
		}
		input = in + read + write
	case "openai":
		input = in
		details, _ := raw["input_tokens_details"].(map[string]any)
		if read, err = count(details, "cached_tokens", false); err != nil {
			return nil, err
		}
		if write, err = count(details, "cache_write_tokens", false); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("no verified usage normalizer for provider '%s'", provider)
	}
	return map[string]any{
		"gen_ai.provider.name":                  provider,
		"gen_ai.usage.input_tokens":             input,
		"gen_ai.usage.output_tokens":            out,
		"gen_ai.usage.cache_read.input_tokens":  read,
		"gen_ai.usage.cache_write.input_tokens": write,
	}, nil
}

// ContextGateGlobs name the files whose edit in a pr.open or branch.push diff
// needs approval (OP_APPROVAL_REQUIRED): they carry instructions for the next
// run, so an edit is prompt injection with persistence. Nested files count.
var ContextGateGlobs = []string{"**/AGENTS.md", "**/CLAUDE.md", "**/SKILL.md", ".agents/**"}

var contextGatePatterns = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(ContextGateGlobs))
	for i, g := range ContextGateGlobs {
		out[i] = regexp.MustCompile(globRegexp(g))
	}
	return out
}()

// globRegexp converts a glob ("**/" = any directories, "**" = anything, "*" =
// anything but "/") to an anchored regexp that ignores ASCII case only. The
// spec's reference uses a JavaScript /i regexp, whose case folding never
// equates a non-ASCII letter with an ASCII one (Go's (?i) would equate U+212A
// with "k"). "." in the reference excludes line terminators, so does the class used here.
func globRegexp(glob string) string {
	const anyChar = `[^\n\r\x{2028}\x{2029}]`
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			re.WriteString("(?:" + anyChar + `*/)?`)
			i += 2
		case strings.HasPrefix(glob[i:], "**"):
			re.WriteString(anyChar + "*")
			i++
		case glob[i] == '*':
			re.WriteString(`[^/\n\r\x{2028}\x{2029}]*`)
		default:
			c := glob[i]
			if lower := c | 0x20; lower >= 'a' && lower <= 'z' {
				re.WriteString("[" + string(lower) + string(lower&^0x20) + "]")
			} else {
				re.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
	}
	re.WriteString("$")
	return re.String()
}

// IsContextGateFile reports whether a repo path is a context gate file.
func IsContextGateFile(path string) bool {
	for _, re := range contextGatePatterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
