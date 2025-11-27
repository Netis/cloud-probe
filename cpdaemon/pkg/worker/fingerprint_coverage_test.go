package worker

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// collectLeafKeys independently re-derives the set of fingerprint label keys for
// v, mirroring common.StructFingerprintLabels but implemented separately so a bug
// in the walker shows up as a divergence (differential testing). It respects json
// tags, `fingerprint:"-"`, and nil-pointer skipping. The task config has no maps
// and no FingerprintContributor implementations, so those cases are omitted.
func collectLeafKeys(v reflect.Value, prefix string) []string {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return collectLeafKeys(v.Elem(), prefix)
	case reflect.Struct:
		var keys []string
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" || f.Tag.Get("fingerprint") == "-" {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			keys = append(keys, collectLeafKeys(v.Field(i), prefix+name+".")...)
		}
		return keys
	case reflect.Slice, reflect.Array:
		var keys []string
		for i := 0; i < v.Len(); i++ {
			keys = append(keys, collectLeafKeys(v.Index(i), fmt.Sprintf("%s%d.", prefix, i))...)
		}
		return keys
	default:
		return []string{strings.TrimSuffix(prefix, ".")}
	}
}

// TestFingerprint_EveryLeafFieldContributes is the structural anti-regression
// guard for the reflection-based fingerprint. A fully-populated TaskConfig
// (touching every struct and every output variant) must produce exactly one
// label per leaf field. If a future field is added that the walker fails to
// cover — mis-tagged, an unexported reachable field, or otherwise dropped — the
// independently-derived key set and the walker's output diverge and this fails.
// This enforces the feature's guarantee ("new fields can't be silently dropped
// from reload identity") structurally rather than by convention. Unlike the
// per-field mutation suite, it does NOT need updating when a field is added.
func TestFingerprint_EveryLeafFieldContributes(t *testing.T) {
	cfg := &TaskConfig{
		ReqPattern: baseReqPattern(),
		Capturer:   CapturerConfig{Type: CapturerType_Libpcap, Libpcap: baseLibpcap()},
		Outputs: []OutputConfig{
			baseVxlanOutput(),
			baseGreOutput(),
			baseZmqOutput(),
			baseFileOutput(),
			baseRotatingFileOutput(),
		},
	}

	labels := cfg.FingerPrintLables()

	expected := collectLeafKeys(reflect.ValueOf(cfg), "")
	sort.Strings(expected)
	for _, key := range expected {
		assert.Contains(t, labels, key, "leaf field %q does not contribute to the fingerprint", key)
	}
	assert.Equal(t, len(expected), len(labels),
		"walker label count != structural leaf count — walker emitted extra or missing keys")
}
