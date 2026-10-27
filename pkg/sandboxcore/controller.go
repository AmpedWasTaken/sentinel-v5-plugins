// Package sandboxcore models admission and job lifecycle. It is a controller
// foundation, NOT an isolation mechanism; real backends must be separately
// reviewed and enforce all limits at the OS/runtime layer.
package sandboxcore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sandboxpolicy"
)

var (
	ErrUnavailable = errors.New("no verified isolation backend available; execution disabled")
	ErrDenied      = errors.New("sandbox operation denied")
	ErrBusy        = errors.New("sandbox concurrency quota exceeded")
	ErrNotFound    = errors.New("sandbox job not found")
)
var safeName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var immutableDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const placeholderDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type Identity struct {
	Principal    string
	Tenant       string
	CanRun       bool
	CanSeeAll    bool
	CanCancelAll bool
}

type Request struct {
	Profile       sandboxpolicy.Profile
	FixtureID     string
	FixtureDigest string
}

type Spec struct {
	ID            string
	Principal     string
	Tenant        string
	Profile       sandboxpolicy.Profile
	PolicyHash    string
	FixtureID     string
	FixtureDigest string
}

type Result struct {
	ExitCode     int    `json:"exit_code"`
	OutputDigest string `json:"output_digest"`
}

type Backend interface {
	// Ready must verify actual runtime support, pinned image and host isolation.
	// Matching a profile name or claiming readiness alone is not attestation.
	Ready(context.Context, sandboxpolicy.Profile) error
	// Run MUST enforce kernel limits, guest isolation and forced termination.
	// Returning after ctx cancellation is a mandatory backend contract.
	Run(context.Context, Spec) (Result, error)
}

type State string

const (
	Queued    State = "queued"
	Running   State = "running"
	Succeeded State = "succeeded"
	Failed    State = "failed"
	Cancelled State = "cancelled"
	TimedOut  State = "timed_out"
)

type Job struct {
	ID            string    `json:"id"`
	Principal     string    `json:"principal"`
	Tenant        string    `json:"tenant"`
	ProfileID     string    `json:"profile_id"`
	PolicyHash    string    `json:"policy_hash"`
	FixtureID     string    `json:"fixture_id"`
	FixtureDigest string    `json:"fixture_digest"`
	State         State     `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
	Result        *Result   `json:"result,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type entry struct {
	job    Job
	cancel context.CancelFunc
	active bool
}

type Controller struct {
	mu                        sync.RWMutex
	parent                    context.Context
	backend                   Backend
	maxTotal, maxPerPrincipal int
	jobs                      map[string]*entry
	activeTotal               int
	activeByOwner             map[string]int
}

// New returns a fail-closed controller when backend is nil. Identity must be
// provided by an independently authenticated Sentinel broker, NOT user JSON.
func New(parent context.Context, backend Backend, maxTotal, maxPerPrincipal int) *Controller {
	if parent == nil {
		parent = context.Background()
	}
	if maxTotal < 1 {
		maxTotal = 2
	}
	if maxPerPrincipal < 1 {
		maxPerPrincipal = 1
	}
	return &Controller{parent: parent, backend: backend, maxTotal: maxTotal, maxPerPrincipal: maxPerPrincipal, jobs: make(map[string]*entry), activeByOwner: make(map[string]int)}
}
func ownerKey(tenant, principal string) string { return tenant + "\x00" + principal }

func (c *Controller) Submit(ctx context.Context, subject Identity, req Request) (Job, error) {
	if !subject.CanRun || !safeName.MatchString(subject.Principal) || !safeName.MatchString(subject.Tenant) {
		return Job{}, ErrDenied
	}
	if !safeName.MatchString(req.FixtureID) || !immutableDigest.MatchString(req.FixtureDigest) || req.FixtureDigest == placeholderDigest {
		return Job{}, errors.New("fixture must be an approved pinned digest")
	}
	if err := req.Profile.Validate(); err != nil {
		return Job{}, err
	}
	if req.Profile.ImageDigest == placeholderDigest {
		return Job{}, errors.New("example profile has no verified runtime image")
	}
	hash, err := req.Profile.Digest()
	if err != nil {
		return Job{}, err
	}
	if c.backend == nil {
		return Job{}, ErrUnavailable
	}
	// Admission does not confer execution privileges: the backend must repeat
	// policy validation at the OS boundary, not trust the plugin's choices.
	if err := c.backend.Ready(ctx, req.Profile); err != nil {
		return Job{}, fmt.Errorf("backend unavailable: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}
	if err := c.parent.Err(); err != nil {
		return Job{}, err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return Job{}, err
	}
	id := hex.EncodeToString(raw)
	key := ownerKey(subject.Tenant, subject.Principal)
	c.mu.Lock()
	if c.activeTotal >= c.maxTotal || c.activeByOwner[key] >= c.maxPerPrincipal {
		c.mu.Unlock()
		return Job{}, ErrBusy
	}
	// Never inherit the caller's RPC request context: it may be only a few
	// seconds long while an accepted sandbox job is asynchronous.
	jobCtx, cancel := context.WithTimeout(c.parent, time.Duration(req.Profile.WallSeconds)*time.Second)
	now := time.Now().UTC()
	job := Job{ID: id, Principal: subject.Principal, Tenant: subject.Tenant, ProfileID: req.Profile.ID, PolicyHash: hash, FixtureID: req.FixtureID, FixtureDigest: req.FixtureDigest, State: Queued, CreatedAt: now}
	spec := Spec{ID: id, Principal: subject.Principal, Tenant: subject.Tenant, Profile: req.Profile, PolicyHash: hash, FixtureID: req.FixtureID, FixtureDigest: req.FixtureDigest}
	c.jobs[id] = &entry{job: job, cancel: cancel, active: true}
	c.activeTotal++
	c.activeByOwner[key]++
	c.mu.Unlock()
	go c.execute(jobCtx, spec)
	return job, nil
}
func (c *Controller) execute(ctx context.Context, spec Spec) {
	c.mu.Lock()
	item := c.jobs[spec.ID]
	if item == nil {
		c.mu.Unlock()
		return
	}
	if ctx.Err() == nil {
		item.job.State = Running
	}
	c.mu.Unlock()
	result, runErr := Result{}, ctx.Err()
	if runErr == nil {
		result, runErr = c.backend.Run(ctx, spec)
	}
	// The controller cannot forcibly contain a broken backend. Backends MUST
	// terminate the complete guest/process tree before returning.
	c.mu.Lock()
	if item = c.jobs[spec.ID]; item != nil && item.active {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			item.job.State = TimedOut
		case errors.Is(ctx.Err(), context.Canceled):
			item.job.State = Cancelled
		case runErr != nil:
			item.job.State = Failed
		default:
			item.job.State = Succeeded
			copied := result
			item.job.Result = &copied
		}
		if runErr != nil {
			item.job.Error = "sandbox backend failed"
		} // no raw host paths/secrets
		item.job.FinishedAt = time.Now().UTC()
		item.active = false
		c.activeTotal--
		c.activeByOwner[ownerKey(item.job.Tenant, item.job.Principal)]--
		item.cancel()
	}
	c.mu.Unlock()
}

func (c *Controller) Get(subject Identity, id string) (Job, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item := c.jobs[id]
	if item == nil || item.job.Tenant != subject.Tenant || (item.job.Principal != subject.Principal && !subject.CanSeeAll) {
		return Job{}, ErrNotFound
	}
	return cloneJob(item.job), nil
}
func cloneJob(job Job) Job {
	if job.Result != nil {
		r := *job.Result
		job.Result = &r
	}
	return job
}
func (c *Controller) Cancel(subject Identity, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.jobs[id]
	if item == nil || item.job.Tenant != subject.Tenant || (item.job.Principal != subject.Principal && !subject.CanCancelAll) {
		return ErrNotFound
	}
	if !item.active {
		return errors.New("sandbox job already finished")
	}
	item.cancel() // cancellation requested, not proof that backend terminated
	return nil
}
func (c *Controller) Active() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.activeTotal }
