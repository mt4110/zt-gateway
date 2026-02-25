package main

import (
	"strconv"
	"strings"
	"unicode"
)

type versionSegment struct {
	isNum bool
	num   int
	text  string
}

func gatewayVersionAtLeast(current, minimum string) bool {
	current = strings.TrimSpace(strings.ToLower(current))
	minimum = strings.TrimSpace(strings.ToLower(minimum))
	if minimum == "" || current == "" {
		return minimum == ""
	}
	return compareGatewayVersion(current, minimum) >= 0
}

func compareGatewayVersion(a, b string) int {
	as := splitVersionSegments(a)
	bs := splitVersionSegments(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var left, right versionSegment
		leftSet := i < len(as)
		rightSet := i < len(bs)
		if leftSet {
			left = as[i]
		}
		if rightSet {
			right = bs[i]
		}
		if !leftSet && !rightSet {
			continue
		}
		if !leftSet {
			if right.isNum {
				if right.num == 0 {
					continue
				}
			} else if right.text == "" {
				continue
			}
			return -1
		}
		if !rightSet {
			if left.isNum {
				if left.num == 0 {
					continue
				}
			} else if left.text == "" {
				continue
			}
			return 1
		}
		if left.isNum && right.isNum {
			if left.num < right.num {
				return -1
			}
			if left.num > right.num {
				return 1
			}
			continue
		}
		if left.isNum != right.isNum {
			// Numeric token is treated as newer than alpha token.
			if left.isNum {
				return 1
			}
			return -1
		}
		if left.text < right.text {
			return -1
		}
		if left.text > right.text {
			return 1
		}
	}
	return 0
}

func splitVersionSegments(v string) []versionSegment {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "v")
	segments := make([]versionSegment, 0, 8)
	var b strings.Builder
	lastType := 0 // 0=none,1=num,2=alpha
	flush := func() {
		if b.Len() == 0 {
			return
		}
		token := b.String()
		if lastType == 1 {
			n, _ := strconv.Atoi(token)
			segments = append(segments, versionSegment{isNum: true, num: n})
		} else {
			segments = append(segments, versionSegment{text: token})
		}
		b.Reset()
		lastType = 0
	}
	for _, r := range v {
		if unicode.IsDigit(r) {
			if lastType != 1 {
				flush()
				lastType = 1
			}
			b.WriteRune(r)
			continue
		}
		if unicode.IsLetter(r) {
			if lastType != 2 {
				flush()
				lastType = 2
			}
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return segments
}
