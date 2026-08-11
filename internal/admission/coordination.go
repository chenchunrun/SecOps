package admission

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

const coordinationRetryInterval = 5 * time.Millisecond

// Coordinate serializes compound store operations across processes.
func (s *FileStore) Coordinate(ctx context.Context, action func() error) (err error) {
	s.coordinator.Lock()
	defer s.coordinator.Unlock()

	lock := flock.New(filepath.Join(s.root, ".admission.lock"))
	locked, err := lock.TryLockContext(ctx, coordinationRetryInterval)
	if err != nil {
		return fmt.Errorf("acquire admission store lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("acquire admission store lock: %w", context.Cause(ctx))
	}
	defer func() {
		if unlockErr := lock.Unlock(); unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("release admission store lock: %w", unlockErr))
		}
	}()
	return action()
}
