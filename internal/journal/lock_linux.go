package journal

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func lock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }

func replaceFile(from, to string) error { return os.Rename(from, to) }
func syncParent(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
