package common

import (
	"sort"

	"github.com/samber/lo"
)

var emptyLabelSignature = hashNew()

const SeparatorByte byte = 255

func LabelsToFingerprint(labels map[string]string) Fingerprint {
	if len(labels) == 0 {
		return Fingerprint(emptyLabelSignature)
	}

	keys := lo.Keys(labels)
	sort.Strings(keys)

	sum := hashNew()
	for _, key := range keys {
		sum = hashAdd(sum, key)
		sum = hashAddByte(sum, SeparatorByte)
		sum = hashAdd(sum, labels[key])
		sum = hashAddByte(sum, SeparatorByte)
	}
	return Fingerprint(sum)
}
