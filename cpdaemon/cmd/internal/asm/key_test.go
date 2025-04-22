package asm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVKey(t *testing.T) {
	assert.Equal(t, "cpm.base_url", VKey.Cpm.BaseUrl)
}
