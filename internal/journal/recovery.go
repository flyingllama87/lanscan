package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"lanscan/internal/model"
)

// acquire uses a persistent sidecar: locking a byte in the journal itself prevents
// concurrent read-only export on Windows. OS locks disappear when a process exits;
// the presence of the sidecar alone never indicates a live writer.
func acquire(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(parent, filepath.Base(absolute)) + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("journal is locked by another writer: %w", err)
	}
	return f, nil
}

// OpenResume validates the entire log while holding the writer lock. accept is
// called before any repair, allowing callers to reject foreign or finished runs.
// complete malformed lines are never truncated; only a final incomplete line is
// backed up, synced, and removed. The original fragment is retained for inspection.
func OpenResume(path string, opts Options, emit func(model.Event) error, accept func(ReplayResult) error) (*Writer, ReplayResult, error) {
	var result ReplayResult
	info, err := os.Lstat(path)
	if err != nil {
		return nil, result, err
	}
	if !info.Mode().IsRegular() {
		return nil, result, errors.New("resume requires a regular journal, not a symlink or device")
	}
	guard, err := acquire(path)
	if err != nil {
		return nil, result, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		guard.Close()
		return nil, result, err
	}
	fail := func(e error) (*Writer, ReplayResult, error) { f.Close(); guard.Close(); return nil, result, e }
	opened, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(info, opened) {
		return fail(errors.New("journal changed while opening"))
	}
	result, err = Replay(f, emit)
	if err != nil {
		return fail(err)
	}
	if len(result.Runs) != 1 {
		return fail(errors.New("resume requires exactly one nonempty run"))
	}
	if accept != nil {
		if err = accept(result); err != nil {
			return fail(err)
		}
	}
	if opts.DiskBudget > 0 && result.CompleteBytes >= opts.DiskBudget {
		return fail(errors.New("journal disk budget exhausted; increase --disk-budget"))
	}
	if len(result.TornTail) > 0 {
		sum := sha256.Sum256(result.TornTail)
		backup := fmt.Sprintf("%s.torn-%d-%s", path, result.CompleteBytes, hex.EncodeToString(sum[:8]))
		b, e := os.OpenFile(backup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if errors.Is(e, os.ErrExist) {
			old, readErr := os.ReadFile(backup)
			if readErr != nil {
				return fail(readErr)
			}
			if sha256.Sum256(old) != sum {
				return fail(errors.New("existing torn-tail backup does not match"))
			}
			// An existing backup must be made durable before it can justify truncation.
			b, e = os.OpenFile(backup, os.O_RDWR, 0)
		} else if e == nil {
			n, writeErr := b.Write(result.TornTail)
			if writeErr == nil && n != len(result.TornTail) {
				writeErr = io.ErrShortWrite
			}
			if writeErr != nil {
				b.Close()
				return fail(writeErr)
			}
		}
		if e != nil {
			return fail(e)
		}
		syncErr := b.Sync()
		closeErr := b.Close()
		if syncErr != nil {
			return fail(syncErr)
		}
		if closeErr != nil {
			return fail(closeErr)
		}
		if err = syncParent(backup); err != nil {
			return fail(err)
		}
		if err = f.Truncate(result.CompleteBytes); err != nil {
			return fail(err)
		}
		if err = f.Sync(); err != nil {
			return fail(err)
		}
	}
	if _, err = f.Seek(result.CompleteBytes, io.SeekStart); err != nil {
		return fail(err)
	}
	return start(f, guard, path, opts, result.CompleteBytes), result, nil
}

// Checkpoint is a disposable hint, never a substitute for replaying evidence.
// Its byte offset and sequence refer to a synced journal prefix; recovery still
// validates the entire journal instead of trusting a potentially stale hint.
type Checkpoint struct {
	SchemaVersion int    `json:"schema_version"`
	RunID         string `json:"run_id"`
	Seq           uint64 `json:"seq"`
	CompleteBytes int64  `json:"complete_bytes"`
	ConfigHash    string `json:"config_hash"`
	Operations    int    `json:"operations"`
	ElapsedNS     int64  `json:"elapsed_ns"`
	RoutingEpoch  uint64 `json:"routing_epoch"`
}

func (w *Writer) Checkpoint(c Checkpoint) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.syncLocked(); err != nil {
		return err
	}
	c.SchemaVersion = model.SchemaVersion
	c.CompleteBytes = w.size
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	temp, err := os.CreateTemp(filepath.Dir(w.path), ".lanscan-checkpoint-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	n, err := temp.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = replaceFile(name, w.path+".checkpoint"); err != nil {
		return err
	}
	return syncParent(w.path + ".checkpoint")
}
