package cpm

import (
	"fmt"
	"os"
	"sort"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/samber/lo"
)

const UUIDGenTypeEnv = "env"

type UuidGenConfig struct {
	Type string           // "env" or "random"
	Env  UuidGenEnvConfig // only used when Type is "env"
}

type UuidGenEnvConfig struct {
	Keys []string
}

func (c UuidGenConfig) Generate() (string, error) {
	switch c.Type {
	case UUIDGenTypeEnv:
		if len(c.Env.Keys) == 0 {
			return "", errors.New("uuid_gen.env.keys is required when uuid_gen.type is 'env'")
		}
		labels := map[string]string{
			"_magic": "a1b2c3d4e5", // 增加一个魔术值，让相近的值更有区分度
		}
		for _, key := range c.Env.Keys {
			val := os.Getenv(key)
			if val == "" {
				return "", errors.Errorf("environment variable %q is not set", key)
			}
			labels[key] = val
		}
		fingerprint := LabelsToFingerprint(labels)
		return fingerprint.UUID().String(), nil
	default:
		return uuid.New().String(), nil
	}
}

var emptyLabelSignature = hashNew()

const SeparatorByte byte = 255

type Fingerprint uint64

func (f Fingerprint) String() string {
	return fmt.Sprintf("%016x", uint64(f))
}

func (f Fingerprint) UUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], fmt.Sprintf("%016x", uint64(f)))
	return id
}

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
