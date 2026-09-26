package journal

import (
	"golang.org/x/sys/windows"
	"os"
)

func lock(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

func replaceFile(from, to string) error {
	old, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	next, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(old, next, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// Windows file sync and write-through replacement provide the available durability
// primitives; directory fsync does not have a portable Windows counterpart.
func syncParent(path string) error { return nil }
