package resolver

import (
	"container/list"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// TraceRecord is the per-request detail stored by a TraceStore and served
// back over HTTP: the same information already logged for each completed
// request.
type TraceRecord struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	QType      string    `json:"qtype"`
	RCode      string    `json:"rcode"`
	Outcome    string    `json:"outcome"`
	ClientAddr string    `json:"client"`
	Protocol   string    `json:"protocol"`
	DurationMS int64     `json:"duration_ms"`
	CreatedAt  time.Time `json:"created_at"`
	Trace      []string  `json:"trace"`
}

// traceEntry is the value held by each list.Element - it pairs the record
// with its own ID so an evicted element (found via list.Back()) can be
// removed from the index map too.
type traceEntry struct {
	id     string
	record TraceRecord
}

// TraceStore holds a bounded number of TraceRecords, evicting the least
// recently used entry once at capacity. It's intentionally a separate type
// from Cache: that store's TTL-based expiry is a different eviction policy
// from this store's pure count-bounded LRU.
type TraceStore struct {
	capacity int

	mu    sync.Mutex
	ll    *list.List
	index map[string]*list.Element
}

// NewTraceStore returns an empty TraceStore holding at most capacity
// records. capacity must be positive; validating that is the caller's
// responsibility.
func NewTraceStore(capacity int) *TraceStore {
	return &TraceStore{
		capacity: capacity,
		ll:       list.New(),
		index:    make(map[string]*list.Element),
	}
}

// Put generates a fresh, unguessable ID for record, stores it, and returns
// the ID. If the store is at capacity, the least recently used record is
// evicted first.
//
// The ID is generated before the store's mutex is taken, so a slow
// crypto/rand call never serializes concurrent Puts against each other.
func (ts *TraceStore) Put(record TraceRecord) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate trace id: %w", err)
	}
	id := hex.EncodeToString(raw[:])

	record.ID = id
	record.CreatedAt = time.Now()

	ts.mu.Lock()
	defer ts.mu.Unlock()

	el := ts.ll.PushFront(&traceEntry{id: id, record: record})
	ts.index[id] = el

	if ts.ll.Len() > ts.capacity {
		oldest := ts.ll.Back()
		if oldest != nil {
			ts.ll.Remove(oldest)
			delete(ts.index, oldest.Value.(*traceEntry).id)
		}
	}

	return id, nil
}

// Get returns the record stored under id, if present, marking it as
// recently used.
func (ts *TraceStore) Get(id string) (TraceRecord, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	el, ok := ts.index[id]
	if !ok {
		return TraceRecord{}, false
	}
	ts.ll.MoveToFront(el)
	return el.Value.(*traceEntry).record, true
}

// ServeHTTP implements GET /trace/{id}, returning the matching TraceRecord
// as JSON, or 404 if no such trace is stored (never existed, or was
// evicted).
func (ts *TraceStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	record, ok := ts.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "trace not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(record)
}
