package audit

import (
	"sync"
	"time"
)

type Event struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Client  string    `json:"client"`
	Provider string   `json:"provider"`
	Detail  string    `json:"detail"`
}

type Log struct {
	mu     sync.RWMutex
	events []Event
	limit  int
}

func New(limit int) *Log {
	return &Log{limit: limit}
}

func (l *Log) Add(action, client, provider, detail string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, Event{
		Time:     time.Now().UTC(),
		Action:   action,
		Client:   client,
		Provider: provider,
		Detail:   detail,
	})
	if len(l.events) > l.limit {
		l.events = l.events[len(l.events)-l.limit:]
	}
}

func (l *Log) List() []Event {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}
