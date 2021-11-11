package dataclassifier_test

import (
	"fmt"
	"math/rand"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dataclassifier "github.com/MovieStoreGuy/data-classifier"
)

const (
	UGCField             = "message.body"
	PIIField             = "user.name"
	HighCardinalityField = "timestamp"
	PreserveField        = "audit"
)

type Attribute struct {
	Name  string
	Value string
	Hint  dataclassifier.Classification
}

type Resource struct {
	Values []*Attribute
	Hint   dataclassifier.Classification
}

func (ac *Resource) AppendAttribute(attr *Attribute) {
	ac.Hint = dataclassifier.Combine(ac.Hint, attr.Hint)
	ac.Values = append(ac.Values, attr)
}

func (ac *Resource) Filter(fn func(attr *Attribute) bool) (resource Resource) {
	resource.Values = make([]*Attribute, 0, len(ac.Values))
	for i := 0; i < len(ac.Values); i++ {
		if fn(ac.Values[i]) {
			resource.AppendAttribute(ac.Values[i])
		}
	}
	return resource
}

// RandomisedCollection represents a list or set of attributes that has been generated
// by a client and has been sent to processed.
func RandomisedCollection(tb testing.TB, size int) (r Resource, filter bool) {
	tb.Helper()

	r.Values = make([]*Attribute, 0, size)
	for i := 0; i < size; i++ {
		switch rand.Intn(4) {
		case 0:
			r.AppendAttribute(&Attribute{
				Name:  UGCField,
				Value: "pineapples belong on pizza",
				Hint:  dataclassifier.UGC,
			})
			filter = true
		case 1:
			r.AppendAttribute(&Attribute{
				Name:  PIIField,
				Value: "example-email@example.com",
				Hint:  dataclassifier.PII,
			})
			filter = true
		case 2:
			r.AppendAttribute(&Attribute{
				Name:  HighCardinalityField,
				Value: time.Now().String(),
				Hint:  dataclassifier.HighCardinality,
			})
		case 3:
			r.AppendAttribute(&Attribute{
				Name:  PreserveField,
				Value: "created attribute",
				Hint:  dataclassifier.Persist,
			})
		}
	}
	return r, filter
}

func TestNoMaskOverlaps(t *testing.T) {
	t.Parallel()

	masks := [...]dataclassifier.Classification{
		dataclassifier.NoValue,
		dataclassifier.Persist,
		dataclassifier.UserGeneratedContent,
		dataclassifier.PersonalIdentifableInformation,
		dataclassifier.Sensitive,
		dataclassifier.HighCardinality,
		dataclassifier.ServiceLevelObject,
	}

	for i, expect := 0, 0; i < len(masks); i, expect = i+1, 1<<i {
		assert.Equal(t, dataclassifier.Classification(expect), masks[i], "Must be the same value")
		assert.Equal(t, dataclassifier.NoValue, masks[i].Remove(dataclassifier.Classification(expect)))
		assert.Equal(t, dataclassifier.Classification(expect).String(), masks[i].String())
	}
}

func TestMatchMasks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Scenario       string
		Value          dataclassifier.Classification
		Target         dataclassifier.Classification
		ExpectContains bool
	}{
		{
			Scenario:       "Both values are unset",
			Value:          dataclassifier.NoValue,
			Target:         dataclassifier.NoValue,
			ExpectContains: true,
		},
		{
			Scenario:       "No value is not contained within a defined value",
			Value:          dataclassifier.HighCardinality,
			Target:         dataclassifier.NoValue,
			ExpectContains: false,
		},
		{
			Scenario:       "A target defined is contained in a combined value",
			Value:          dataclassifier.Combine(dataclassifier.Sensitive, dataclassifier.HighCardinality, dataclassifier.UserGeneratedContent),
			Target:         dataclassifier.UserGeneratedContent,
			ExpectContains: true,
		},
		{
			Scenario:       "target and value are seperate values",
			Value:          dataclassifier.Sensitive,
			Target:         dataclassifier.HighCardinality,
			ExpectContains: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Scenario, func(t *testing.T) {
			assert.Equal(t, tc.ExpectContains, tc.Value.Contains(tc.Target))
		})
	}
}

var (
	// cached is used to ensure the result from the for loop
	// is not compile time optimised out
	cached  Resource
	matched bool

	sizes = []int{
		1,
		10,
		100,
		1000,
		10_000,
		100_000,
		1_000_000,
	}
)

func benchFilter(b *testing.B, method func(*Attribute) bool) {
	b.Helper()

	for _, size := range sizes {
		ac, _ := RandomisedCollection(b, size)
		b.ResetTimer()

		b.Run(fmt.Sprintf("Collection-Size-%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				cached = ac.Filter(method)
			}
			ac.Hint = ac.Hint.Remove(dataclassifier.Combine(
				dataclassifier.UGC,
				dataclassifier.PII,
			))
		})
	}
}

func BenchmarkBaselineFilter(b *testing.B) {
	benchFilter(b, func(a *Attribute) bool {
		return true
	})
}

func BenchmarkLookupFilter(b *testing.B) {
	match := map[string]struct{}{
		PIIField: {},
		UGCField: {},
	}

	benchFilter(b, func(a *Attribute) bool {
		_, matched := match[a.Name]
		return !matched
	})
}

func BenchmarkRegxFilter(b *testing.B) {
	exp, err := regexp.CompilePOSIX("[ @]+|user")
	require.NoError(b, err, "Must not error when compiling expression")

	benchFilter(b, func(a *Attribute) bool {
		return !exp.MatchString(a.Value)
	})
}

func BenchmarkAttributeClassificationFilter(b *testing.B) {
	match := dataclassifier.Combine(dataclassifier.UGC, dataclassifier.PII)

	benchFilter(b, func(a *Attribute) bool {
		return a.Hint.Contains(match)
	})
}

func BenchmarkResourceClassificationFilter(b *testing.B) {
	match := dataclassifier.Combine(dataclassifier.UGC, dataclassifier.PII)

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Collection-Size-%d", size), func(b *testing.B) {
			cached, matched = RandomisedCollection(b, size)
			b.ResetTimer()
			assert.Equal(b, matched, cached.Hint.Contains(match))
		})
	}
}
