package auth

import (
	"sync"
	"testing"
	"time"
)

func TestMemorySessionsExpireAndAreBounded(t *testing.T) {
	store := newMemoryStore()
	store.limit = 1
	identity := Identity{Issuer: "issuer", Subject: "subject", Provider: OIDC}
	expired, err := store.addSession(identity, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.identity(expired); ok {
		t.Fatal("expired session accepted")
	}
	id, err := store.addSession(identity, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.addSession(identity, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("session capacity exceeded")
	}
	store.deleteSession(id)
	if _, ok := store.identity(id); ok {
		t.Fatal("deleted session accepted")
	}
	flow := loginFlow{State: "state", Expires: time.Now().Add(time.Minute)}
	id, err = store.addFlow(flow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.addFlow(flow); err == nil {
		t.Fatal("login capacity exceeded")
	}
	if _, ok := store.takeFlow(id, "state"); !ok {
		t.Fatal("valid flow rejected")
	}
	if _, ok := store.takeFlow(id, "state"); ok {
		t.Fatal("flow replay accepted")
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	store := newMemoryStore()
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			flowID, err := store.addFlow(loginFlow{State: "state", Expires: time.Now().Add(time.Minute)})
			if err != nil {
				t.Error(err)
				return
			}
			if _, ok := store.takeFlow(flowID, "state"); !ok {
				t.Error("flow missing")
			}
			id, err := store.addSession(Identity{Subject: "user"}, time.Now().Add(time.Minute))
			if err != nil {
				t.Error(err)
				return
			}
			if _, ok := store.identity(id); !ok {
				t.Error("session missing")
			}
			store.deleteSession(id)
		}()
	}
	group.Wait()
}
