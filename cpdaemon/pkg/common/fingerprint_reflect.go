package common

import (
	"fmt"
	"reflect"
	"strings"
)

// FingerprintContributor lets a type override how it contributes to the
// fingerprint. WARNING: implementing it REPLACES automatic field walking for
// that type — the implementer takes over the maintenance burden for its fields.
// Use only for leaf/value types that need value normalization, never for
// container structs. The method must be reachable on the value as walked: for a
// pointer struct field, implement it on the pointer type or with a value
// receiver.
type FingerprintContributor interface {
	FingerprintLabels(labels map[string]string, prefix string)
}

var fingerprintContributorType = reflect.TypeOf((*FingerprintContributor)(nil)).Elem()

// StructFingerprintLabels walks v by reflection and returns the label set that
// feeds LabelsToFingerprint. Keys are derived from json tags; nil pointers are
// skipped (so unset optional pointer fields don't contribute — note that
// zero-value non-pointer scalars are still emitted); fields tagged
// `fingerprint:"-"` are excluded. Map write order is irrelevant:
// LabelsToFingerprint sorts keys before hashing.
func StructFingerprintLabels(v any) map[string]string {
	labels := make(map[string]string)
	appendFingerprintLabels(reflect.ValueOf(v), "", labels)
	return labels
}

func appendFingerprintLabels(v reflect.Value, prefix string, labels map[string]string) {
	if !v.IsValid() {
		return
	}

	// Custom hook takes precedence over automatic walking.
	if v.CanInterface() && v.Type().Implements(fingerprintContributorType) {
		if v.Kind() == reflect.Ptr && v.IsNil() {
			return
		}
		v.Interface().(FingerprintContributor).FingerprintLabels(labels, prefix)
		return
	}

	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return
		}
		appendFingerprintLabels(v.Elem(), prefix, labels)

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" { // unexported
				continue
			}
			if f.Tag.Get("fingerprint") == "-" {
				continue
			}
			name := fingerprintFieldName(f)
			if name == "" {
				continue
			}
			appendFingerprintLabels(v.Field(i), prefix+name+".", labels)
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			appendFingerprintLabels(v.Index(i), fmt.Sprintf("%s%d.", prefix, i), labels)
		}

	case reflect.Map:
		// No sort needed: each entry's map key is embedded in its label key, so
		// entries never overwrite each other, and LabelsToFingerprint sorts all
		// keys before hashing — map iteration order cannot affect the result.
		for _, k := range v.MapKeys() {
			appendFingerprintLabels(v.MapIndex(k), fmt.Sprintf("%s%v.", prefix, k.Interface()), labels)
		}

	default: // leaf — assumes plain scalar (string/int/uint/bool); types needing custom value normalization should implement FingerprintContributor.
		labels[strings.TrimSuffix(prefix, ".")] = fmt.Sprint(v.Interface())
	}
}

// fingerprintFieldName returns the label segment for a struct field, taken from
// its json tag (falling back to the field name). Returns "" for json:"-".
func fingerprintFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	name := strings.Split(tag, ",")[0]
	if name == "-" {
		return ""
	}
	if name == "" {
		return f.Name
	}
	return name
}
