package sandboxcore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
)

type holdBackend struct {
	started chan struct{}
	once    sync.Once
}

func (b *holdBackend) Ready(context.Context, sandboxpolicy.Profile) error { return nil }
func (b *holdBackend) Run(ctx context.Context, _ Spec) (Result, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return Result{}, ctx.Err()
}

type doneBackend struct{}

func (doneBackend) Ready(context.Context, sandboxpolicy.Profile) error { return nil }
func (doneBackend) Run(context.Context, Spec) (Result, error) {
	return Result{ExitCode: 0, OutputDigest: "sha256:deadbeef"}, nil
}
func request() Request {
	p := sandboxpolicy.ExampleProfiles()[0]
	p.ImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return Request{Profile: p, FixtureID: "fixture-hello", FixtureDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
}
func caller() Identity { return Identity{Principal: "alice", Tenant: "team", CanRun: true} }
func wait(t *testing.T, c *Controller, who Identity, id string, target State) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		j, err := c.Get(who, id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State == target {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("job state %s not %s", j.State, target)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
func TestDisabledByDefault(t *testing.T) {
	c := New(context.Background(), nil, 2, 1)
	_, err := c.Submit(context.Background(), caller(), request())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable: %v", err)
	}
}
func TestAuthenticationScopes(t *testing.T) {
	c := New(context.Background(), doneBackend{}, 2, 1)
	_, err := c.Submit(context.Background(), Identity{Principal: "alice", Tenant: "team"}, request())
	if !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	job, err := c.Submit(context.Background(), caller(), request())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(Identity{Principal: "bob", Tenant: "team"}, job.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	_, err = c.Get(Identity{Principal: "bob", Tenant: "other", CanSeeAll: true}, job.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := c.Cancel(Identity{Principal: "bob", Tenant: "team", CanCancelAll: false}, job.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	wait(t, c, caller(), job.ID, Succeeded)
}
func TestCancelAndQuota(t *testing.T) {
	b := &holdBackend{started: make(chan struct{})}
	c := New(context.Background(), b, 1, 1)
	job, err := c.Submit(context.Background(), caller(), request())
	if err != nil {
		t.Fatal(err)
	}
	<-b.started
	_, err = c.Submit(context.Background(), caller(), request())
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("want quota denial: %v", err)
	}
	if err := c.Cancel(caller(), job.ID); err != nil {
		t.Fatal(err)
	}
	wait(t, c, caller(), job.ID, Cancelled)
	if c.Active() != 0 {
		t.Fatal("quota slot not released")
	}
}
func TestUnsafeProfileAndPlaceholders(t *testing.T) {
	c := New(context.Background(), doneBackend{}, 2, 1)
	req := request()
	req.Profile.AllowHostMounts = true
	if _, err := c.Submit(context.Background(), caller(), req); err == nil {
		t.Fatal("host mount accepted")
	}
	req = request()
	req.Profile.ImageDigest = sandboxpolicy.ExampleProfiles()[0].ImageDigest
	if _, err := c.Submit(context.Background(), caller(), req); err == nil {
		t.Fatal("placeholder image accepted")
	}
}
