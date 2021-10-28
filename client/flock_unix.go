// Based on https://github.com/boltdb/bolt/blob/master/bolt_unix.go
// Copyright boltdb authors

//go:build !windows && !plan9 && !solaris
// +build !windows,!plan9,!solaris

package client

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// ErrTimeout is returned when we cannot obtain an exclusive lock
// on the key file.
var ErrTimeout = errors.New("timeout waiting on lock to become available")

type flock struct {
	fd int
}

func newFlock() *flock {
	return &flock{-1}
}

// lock acquires an advisory lock on a file descriptor.
func (f *flock) lock(k *KeysFile, mode os.FileMode, exclusive bool, timeout time.Duration) error {
	var t time.Time
	for {
		// If we're beyond our timeout then return an error.
		// This can only occur after we've attempted a lock once.
		if t.IsZero() {
			t = time.Now()
		} else if timeout > 0 && time.Since(t) > timeout {
			return ErrTimeout
		}
		flag := syscall.LOCK_SH
		if exclusive {
			flag = syscall.LOCK_EX
		}

		// Otherwise attempt to obtain an exclusive lock.
		fd, err := f.getFD(k)
		if err != nil {
			return err
		}
		err = syscall.Flock(fd, flag|syscall.LOCK_NB)
		if err == nil {
			return nil
		} else if err != syscall.EWOULDBLOCK {
			return err
		}

		// Wait for a bit and try again.
		time.Sleep(50 * time.Millisecond)
	}
}

// unlock releases an advisory lock on a file descriptor.
func (f *flock) unlock(k *KeysFile) error {
	return syscall.Flock(f.fd, syscall.LOCK_UN)
}

func (f *flock) getFD(k *KeysFile) (int, error) {
	if f.fd != -1 {
		return f.fd, nil
	}
	fd, err := syscall.Open(k.fn, syscall.O_RDWR, 0)
	if err != nil {
		return -1, err
	}
	f.fd = fd
	return f.fd, nil
}
