package state

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork/tunneler"
	"golang.org/x/sys/unix"
)

const (
	stateFileName     = "state.json"
	startLockFileName = "start.lock"
)

// ErrLocked is returned by TryLock when another process holds the sandbox lock.
var ErrLocked = errors.New("sandbox is locked by another process")

type Manager struct {
	podsDir string
}

func NewManager(podsDir string) *Manager {
	return &Manager{podsDir: podsDir}
}

func (m *Manager) statePath(sandboxID string) string {
	return filepath.Join(m.podsDir, sandboxID, stateFileName)
}

func (m *Manager) Save(st *SandboxState) error {
	path := m.statePath(st.SandboxID)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write: temp file + rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func (m *Manager) Load(sandboxID string) (*SandboxState, error) {
	data, err := os.ReadFile(m.statePath(sandboxID))
	if err != nil {
		return nil, err
	}
	var st SandboxState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (m *Manager) Delete(sandboxID string) error {
	return os.RemoveAll(filepath.Join(m.podsDir, sandboxID))
}

// TryLock takes an exclusive lock on the sandbox without blocking and returns
// ErrLocked if another process holds it. A CAA holds the lock from CreateVM
// until the sandbox is running, and the kernel drops it if that process exits,
// so a CAA recovering sandboxes can tell one that another CAA is still starting
// from one abandoned mid-start. Close the returned file to release the lock.
func (m *Manager) TryLock(sandboxID string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(m.podsDir, sandboxID, startLockFileName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return f, nil
}

func (m *Manager) List() ([]string, error) {
	entries, err := os.ReadDir(m.podsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(m.statePath(e.Name())); err == nil {
				ids = append(ids, e.Name())
			}
		}
	}
	return ids, nil
}

func (m *Manager) SetReady(sandboxID string, podNetwork *tunneler.Config) error {
	st, err := m.Load(sandboxID)
	if err != nil {
		return err
	}
	st.Running = true
	st.PodNetwork = podNetwork
	return m.Save(st)
}

// UpdateInstance updates instance info after VM creation (used in StartVM)
func (m *Manager) UpdateInstance(sandboxID, instanceID, instanceName string, ips []netip.Addr) error {
	st, err := m.Load(sandboxID)
	if err != nil {
		return err
	}
	st.InstanceID = instanceID
	st.InstanceName = instanceName

	ipStrings := make([]string, len(ips))
	for i, ip := range ips {
		ipStrings[i] = ip.String()
	}
	st.InstanceIPs = ipStrings

	now := time.Now()
	st.StartedAt = &now
	return m.Save(st)
}
