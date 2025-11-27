package common

import (
	"fmt"

	"github.com/google/uuid"
)

type Fingerprint uint64

func (f Fingerprint) String() string {
	return fmt.Sprintf("%016x", uint64(f))
}

func (f Fingerprint) UUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], fmt.Sprintf("%016x", uint64(f)))
	return id
}
