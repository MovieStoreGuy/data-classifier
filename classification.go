package dataclassifier

import "strings"

type Classification int64

const (
	NoValue                        Classification = 0
	Persist                        Classification = 1 << 0
	UserGeneratedContent           Classification = 1 << 1
	PersonalIdentifableInformation Classification = 1 << 2
	Sensitive                      Classification = 1 << 3
	HighCardinality                Classification = 1 << 4
	ServiceLevelObject             Classification = 1 << 5

	// Short hand constants that are accepted industry terms
	UGC = UserGeneratedContent
	PII = PersonalIdentifableInformation
	PD  = PersonalIdentifableInformation
)

var enumstr = map[Classification]string{
	NoValue:            "no-value",
	Persist:            "persist",
	UGC:                "user-generated-content",
	PD:                 "personal-identifiable-information",
	Sensitive:          "sensitive",
	HighCardinality:    "high-cardinality",
	ServiceLevelObject: "service-level-objective",
}

func Combine(values ...Classification) (value Classification) {
	for _, v := range values {
		value |= v
	}
	return value
}

func (c Classification) Contains(value Classification) bool {
	return c == value || (c&value > 0)
}

func (c Classification) Remove(value Classification) Classification {
	return c ^ value
}

func (cf Classification) String() string {
	var sb strings.Builder
	for i, c := 0, Classification(0); i < len(enumstr); i, c = i+1, 1<<i {
		if !cf.Contains(c) {
			continue
		}
		sb.WriteString(enumstr[c])
		if i < len(enumstr)-1 {
			sb.WriteRune(',')
		}
	}
	return sb.String()
}
