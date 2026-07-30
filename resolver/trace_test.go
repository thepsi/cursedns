package resolver

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTraceStore_PutGetRoundtrip(t *testing.T) {
	ts := NewTraceStore(10)

	id, err := ts.Put(TraceRecord{Name: "example.com.", QType: "A", RCode: "NOERROR"})
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if id == "" {
		t.Fatal("Put returned an empty id")
	}

	got, ok := ts.Get(id)
	if !ok {
		t.Fatalf("Get(%q) not found", id)
	}
	if got.ID != id || got.Name != "example.com." || got.QType != "A" || got.RCode != "NOERROR" {
		t.Fatalf("got %+v, want a record matching what was stored", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set by Put")
	}
}

func TestTraceStore_GetUnknownID(t *testing.T) {
	ts := NewTraceStore(10)
	if _, ok := ts.Get("does-not-exist"); ok {
		t.Fatal("Get on an unknown id should report false")
	}
}

// This is the test that actually distinguishes "real LRU" from "a bounded
// FIFO": touching an old entry via Get must protect it from eviction ahead
// of an untouched entry that was inserted more recently.
func TestTraceStore_EvictsLeastRecentlyUsedNotOldestInserted(t *testing.T) {
	ts := NewTraceStore(3)

	idA, _ := ts.Put(TraceRecord{Name: "a."})
	idB, _ := ts.Put(TraceRecord{Name: "b."})
	idC, _ := ts.Put(TraceRecord{Name: "c."})

	// Touch A, making B the least recently used of {A, B, C}.
	if _, ok := ts.Get(idA); !ok {
		t.Fatal("Get(idA) should have found the record")
	}

	// Inserting a 4th record overflows capacity (3); B, not A, should be evicted.
	idD, _ := ts.Put(TraceRecord{Name: "d."})

	if _, ok := ts.Get(idB); ok {
		t.Fatal("expected idB (least recently used) to have been evicted")
	}
	if _, ok := ts.Get(idA); !ok {
		t.Fatal("expected idA (recently touched) to have survived eviction")
	}
	if _, ok := ts.Get(idC); !ok {
		t.Fatal("expected idC to have survived eviction")
	}
	if _, ok := ts.Get(idD); !ok {
		t.Fatal("expected idD (just inserted) to have survived eviction")
	}
}

func TestTraceStore_IDsAreWellFormedAndDistinct(t *testing.T) {
	ts := NewTraceStore(100)

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		id, err := ts.Put(TraceRecord{Name: "example.com."})
		if err != nil {
			t.Fatalf("Put returned error: %v", err)
		}
		if len(id) != 32 {
			t.Fatalf("id %q has length %d, want 32 (16 bytes hex-encoded)", id, len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("id %q is not valid hex: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("id %q was generated twice", id)
		}
		seen[id] = true
	}
}

func TestTraceStore_ServeHTTP(t *testing.T) {
	ts := NewTraceStore(10)
	id, _ := ts.Put(TraceRecord{Name: "example.com.", QType: "A", RCode: "NOERROR", Trace: []string{"line one"}})

	mux := http.NewServeMux()
	mux.Handle("GET /trace/{id}", ts)

	t.Run("found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/trace/"+id, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: body=%s", rec.Code, rec.Body.String())
		}
		var got TraceRecord
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("response body is not valid JSON: %v (%s)", err, rec.Body.String())
		}
		if got.ID != id || got.Name != "example.com." || len(got.Trace) != 1 {
			t.Fatalf("got %+v, want a record matching what was stored", got)
		}
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/trace/does-not-exist", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
