// Package audit writes the security audit trail (one JSON object per line) required by
// the last step of the proposed flow: every authentication decision, session change and
// IDS alert is recorded with who, from where and why.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	Time      time.Time `json:"time"`
	Component string    `json:"component"`
	Event     string    `json:"event"`
	Outcome   string    `json:"outcome"` // "allow", "deny", "info", "revoke", "error"
	Mode      string    `json:"mode,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Device    string    `json:"device,omitempty"`
	Username  string    `json:"username,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Service   string    `json:"service,omitempty"`
	Gateway   string    `json:"gateway,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Detail    any       `json:"detail,omitempty"`
}

// Log appends events to one or more writers.
type Log struct {
	component string
	mu        sync.Mutex
	out       []io.Writer
}

// New logs to stdout and, if path is set, to that file (created with its directory).
func New(component, path string) (*Log, error) {
	l := &Log{component: component, out: []io.Writer{os.Stdout}}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		l.out = append(l.out, f)
	}
	return l, nil
}

// NewWriter logs to w only (tests).
func NewWriter(component string, w io.Writer) *Log {
	return &Log{component: component, out: []io.Writer{w}}
}

// Record writes e, filling time and component.
func (l *Log) Record(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Component = l.component
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.out {
		_, _ = w.Write(b)
	}
}
