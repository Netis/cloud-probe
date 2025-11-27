package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type leafStruct struct {
	A      string `json:"a"`
	B      *int   `json:"b,omitempty"`
	C      bool   `json:"c"`
	Skip   string `json:"skip" fingerprint:"-"`
	NoJSON string `json:"-"`
}

func TestStructFingerprintLabels_LeafAndExclusion(t *testing.T) {
	x := 7
	got := StructFingerprintLabels(leafStruct{A: "hi", B: &x, C: true, Skip: "no", NoJSON: "no"})

	assert.Equal(t, "hi", got["a"])
	assert.Equal(t, "7", got["b"])
	assert.Equal(t, "true", got["c"])
	assert.NotContains(t, got, "skip") // fingerprint:"-"
	assert.NotContains(t, got, "-")    // json:"-"
	assert.NotContains(t, got, "NoJSON")
}

func TestStructFingerprintLabels_NilPointerSkipped(t *testing.T) {
	got := StructFingerprintLabels(leafStruct{A: "hi"}) // B is nil
	assert.NotContains(t, got, "b")
}

type nestedStruct struct {
	Inner *leafStruct  `json:"inner,omitempty"`
	List  []leafStruct `json:"list"`
}

func TestStructFingerprintLabels_NestedAndSlice(t *testing.T) {
	got := StructFingerprintLabels(nestedStruct{
		Inner: &leafStruct{A: "x"},
		List:  []leafStruct{{A: "y"}, {A: "z"}},
	})
	assert.Equal(t, "x", got["inner.a"])
	assert.Equal(t, "y", got["list.0.a"])
	assert.Equal(t, "z", got["list.1.a"])
}

func TestStructFingerprintLabels_PointerArgIsWalked(t *testing.T) {
	got := StructFingerprintLabels(&leafStruct{A: "hi"})
	assert.Equal(t, "hi", got["a"])
}

type customLeaf struct {
	Val string `json:"val"`
}

func (c customLeaf) FingerprintLabels(labels map[string]string, prefix string) {
	labels[prefix+"custom"] = "normalized"
}

type holdsCustom struct {
	C customLeaf `json:"c"`
}

func TestStructFingerprintLabels_CustomHookReplacesWalking(t *testing.T) {
	got := StructFingerprintLabels(holdsCustom{C: customLeaf{Val: "raw"}})
	assert.Equal(t, "normalized", got["c.custom"])
	assert.NotContains(t, got, "c.val") // hook replaced field enumeration
}

type unionStruct struct {
	Type  string      `json:"type"`
	Vxlan *leafStruct `json:"vxlan,omitempty"`
	Gre   *leafStruct `json:"gre,omitempty"`
}

func TestStructFingerprintLabels_AllNonNilMembersWalked(t *testing.T) {
	// The walker is type-agnostic: every non-nil pointer member contributes,
	// even if a Type discriminator would suggest only one is "active". This is
	// the intended divergence from the old type-discriminated FingerprintLabels.
	got := StructFingerprintLabels(unionStruct{
		Type:  "vxlan",
		Vxlan: &leafStruct{A: "v"},
		Gre:   &leafStruct{A: "g"},
	})
	assert.Equal(t, "vxlan", got["type"])
	assert.Equal(t, "v", got["vxlan.a"])
	assert.Equal(t, "g", got["gre.a"]) // walked despite Type=="vxlan"
}
