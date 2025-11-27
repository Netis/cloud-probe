package cpm

import (
	"os"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/common"
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
		fingerprint := common.LabelsToFingerprint(labels)
		return fingerprint.UUID().String(), nil
	default:
		return uuid.New().String(), nil
	}
}
