package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

const defaultEndpoint = "http://127.0.0.1:11434/v1/chat/completions"
const maxResponseBytes = 32 * 1024
const maxHistory = 20
const maxRunDuration = 120 * time.Second
const maxRequestDuration = 35 * time.Second

var modelName = regexp.MustCompile(`^[a-zA-Z0-9_.:/-]{1,80}$`)
var runIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

type challenge struct{ name, question, answer string }

// Deterministic, versioned fixtures. This is a correctness smoke test, not SWE-bench.
var suites = map[string][]challenge{
	"sanity-v1": {
		{"instruction", "Return exactly the following word and nothing else: sentinel-ready", "sentinel-ready"},
		{"arithmetic", "Compute 17 multiplied by 19. Return only the integer.", "323"},
		{"reasoning", "A shop has 9 apples. It sells 4 and receives 2 more. How many apples remain? Reply only with the integer.", "7"},
	},
	"code-v1": {
		{"python-slice", "What is printed by this Python 3 code? x = [1, 2, 3]; print(sum(x[1:])). Reply with only the output.", "5"},
		{"go-loop", "What does this Go code print? sum := 0; for i := 1; i <= 4; i++ { sum += i }; fmt.Println(sum). Reply with only the output.", "10"},
		{"javascript-length", "What does this JavaScript print? console.log(['a','b','c'].filter(x => x !== 'b').length). Reply with only the output.", "2"},
	},
}

type sample struct {
	Name             string `json:"name"`
	Passed           bool   `json:"passed"`
	LatencyMS        int64  `json:"latency_ms"`
	CompletionTokens int    `json:"completion_tokens"`
}

type runRecord struct {
	ID               string    `json:"id"`
	Model            string    `json:"model"`
	Suite            string    `json:"suite"`
	Status           string    `json:"status"`
	Finished         int       `json:"finished"`
	Passed           int       `json:"passed"`
	Total            int       `json:"total"`
	AvgLatencyMS     int64     `json:"avg_latency_ms"`
	CompletionTokens int       `json:"completion_tokens"`
	Error            string    `json:"error,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at,omitempty"`
	Samples          []sample  `json:"samples,omitempty"`
	cancel           context.CancelFunc
}

type aiRunner struct {
	mu           sync.Mutex
	endpoint     string
	client       *http.Client
	runs         map[string]*runRecord
	active       bool
	shuttingDown bool
	wait         sync.WaitGroup
}

type chatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Stream      bool    `json:"stream"`
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func localEndpoint(input string) (string, error) {
	if input == "" {
		input = defaultEndpoint
	}
	u, err := url.Parse(input)
	if err != nil || u == nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "/v1/chat/completions" || u.EscapedPath() != "/v1/chat/completions" {
		return "", errors.New("endpoint must be literal loopback HTTP /v1/chat/completions with no query or credentials")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("only a literal loopback IP is allowed")
	}
	// Scope is deliberately stricter than arbitrary loopback interfaces.
	if host != "127.0.0.1" && host != "::1" {
		return "", errors.New("only 127.0.0.1 or ::1 allowed")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("explicit valid loopback port required")
	}
	return u.String(), nil
}

func newRunner(endpoint string, client *http.Client) (*aiRunner, error) {
	safeURL, err := localEndpoint(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: maxRequestDuration, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &aiRunner{endpoint: safeURL, client: client, runs: make(map[string]*runRecord)}, nil
}

func exactArgs(args map[string]string, allowed ...string) error {
	valid := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		valid[k] = true
	}
	for k := range args {
		if !valid[k] {
			return fmt.Errorf("unexpected argument %q", k)
		}
	}
	return nil
}

func (r *aiRunner) run(args map[string]string) (sentinelplugin.Result, error) {
	if err := exactArgs(args, "model", "suite"); err != nil {
		return sentinelplugin.Result{}, err
	}
	model := strings.TrimSpace(args["model"])
	if !modelName.MatchString(model) || strings.Contains(model, "..") {
		return sentinelplugin.Result{}, errors.New("model=<local-model-name> is required (up to 80 safe characters)")
	}
	suite := strings.TrimSpace(args["suite"])
	if suite == "" {
		suite = "sanity-v1"
	}
	tests, exists := suites[suite]
	if !exists {
		return sentinelplugin.Result{}, errors.New("unknown suite; use ai-lab suites")
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return sentinelplugin.Result{}, errors.New("failed to create run ID")
	}
	id := hex.EncodeToString(random)
	ctx, cancel := context.WithTimeout(context.Background(), maxRunDuration)
	r.mu.Lock()
	if r.shuttingDown || r.active {
		r.mu.Unlock()
		cancel()
		return sentinelplugin.Result{}, errors.New("AI Lab allows one active run; wait or cancel first")
	}
	if len(r.runs) >= maxHistory {
		// Never prune active run; all completed histories are bounded and ephemeral.
		var oldest string
		for key, record := range r.runs {
			if oldest == "" || record.StartedAt.Before(r.runs[oldest].StartedAt) {
				oldest = key
			}
		}
		delete(r.runs, oldest)
	}
	record := &runRecord{ID: id, Model: model, Suite: suite, Status: "running", Total: len(tests), StartedAt: time.Now().UTC(), cancel: cancel}
	r.runs[id] = record
	r.active = true
	r.wait.Add(1)
	r.mu.Unlock()
	initial := formatRecord(snapshot(record))
	go r.execute(ctx, record, tests)
	return initial, nil
}

func (r *aiRunner) ask(ctx context.Context, model, question string) (string, int, error) {
	reqBody := chatRequest{Model: model, Temperature: 0, MaxTokens: 64}
	reqBody.Messages = append(reqBody.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "system", Content: "You are being evaluated on fixed, deterministic questions. Answer only with the requested output. Never request or use tools."})
	reqBody.Messages = append(reqBody.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "user", Content: question})
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return "", 0, fmt.Errorf("local model request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("local model returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return "", 0, errors.New("could not read local model response")
	}
	if len(raw) > maxResponseBytes {
		return "", 0, errors.New("local model response exceeded size limit")
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", 0, errors.New("invalid local model JSON response")
	}
	if len(out.Choices) == 0 {
		return "", 0, errors.New("local model returned no choices")
	}
	if out.Usage.CompletionTokens < 0 {
		return "", 0, errors.New("invalid completion token count")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), out.Usage.CompletionTokens, nil
}

func (r *aiRunner) execute(ctx context.Context, record *runRecord, tasks []challenge) {
	defer r.wait.Done()
	defer record.cancel()
	defer func() {
		r.mu.Lock()
		if record.Status == "running" {
			record.Status = "completed"
		}
		record.FinishedAt = time.Now().UTC()
		r.active = false
		r.mu.Unlock()
	}()
	var accumulated int64
	for _, task := range tasks {
		if err := ctx.Err(); err != nil {
			r.setError(record, err)
			return
		}
		started := time.Now()
		promptCtx, cancel := context.WithTimeout(ctx, maxRequestDuration)
		answer, tokens, err := r.ask(promptCtx, record.Model, task.question)
		cancel()
		duration := time.Since(started).Milliseconds()
		if err != nil {
			r.setError(record, err)
			return
		}
		passed := strings.EqualFold(strings.TrimSpace(answer), task.answer)
		r.mu.Lock()
		record.Finished++
		if passed {
			record.Passed++
		}
		record.CompletionTokens += tokens
		accumulated += duration
		record.AvgLatencyMS = accumulated / int64(record.Finished)
		record.Samples = append(record.Samples, sample{Name: task.name, Passed: passed, LatencyMS: duration, CompletionTokens: tokens})
		r.mu.Unlock()
	}
}

func (r *aiRunner) setError(record *runRecord, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if errors.Is(err, context.Canceled) {
		record.Status = "cancelled"
	} else if errors.Is(err, context.DeadlineExceeded) {
		record.Status = "timed_out"
	} else {
		record.Status = "failed"
		record.Error = "model request failed; inspect the local AI endpoint"
	}
}

func (r *aiRunner) lookup(args map[string]string) (runRecord, error) {
	if err := exactArgs(args, "id"); err != nil {
		return runRecord{}, err
	}
	id := args["id"]
	if !runIDPattern.MatchString(id) {
		return runRecord{}, errors.New("id=<run-id> required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.runs[id]
	if !ok {
		return runRecord{}, errors.New("run not found")
	}
	return snapshot(record), nil
}

func snapshot(record *runRecord) runRecord {
	out := *record
	out.cancel = nil
	out.Samples = append([]sample(nil), record.Samples...)
	return out
}

func formatRecord(rec runRecord) sentinelplugin.Result {
	progress := fmt.Sprintf("%d/%d", rec.Finished, rec.Total)
	txt := fmt.Sprintf("AI LAB | %s\nRun: %s\nModel: %s | Suite: %s\nPassed: %d/%d | Progress: %s\nAverage latency: %dms | Completion tokens: %d", rec.Status, rec.ID, rec.Model, rec.Suite, rec.Passed, rec.Total, progress, rec.AvgLatencyMS, rec.CompletionTokens)
	if rec.Error != "" {
		txt += "\nError: " + rec.Error
	}
	return sentinelplugin.Result{Text: txt, View: "bench", Values: map[string]string{
		"id": rec.ID, "model": rec.Model, "suite": rec.Suite, "status": rec.Status,
		"passed": fmt.Sprintf("%d/%d", rec.Passed, rec.Total), "progress": progress,
		"latency": fmt.Sprintf("%d ms", rec.AvgLatencyMS), "tokens": strconv.Itoa(rec.CompletionTokens),
	}}
}

func (r *aiRunner) status(args map[string]string) (sentinelplugin.Result, error) {
	rec, err := r.lookup(args)
	if err != nil {
		return sentinelplugin.Result{}, err
	}
	return formatRecord(rec), nil
}
func (r *aiRunner) cancel(args map[string]string) (sentinelplugin.Result, error) {
	if err := exactArgs(args, "id"); err != nil {
		return sentinelplugin.Result{}, err
	}
	id := args["id"]
	if !runIDPattern.MatchString(id) {
		return sentinelplugin.Result{}, errors.New("id=<run-id> required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.runs[id]
	if !ok {
		return sentinelplugin.Result{}, errors.New("run not found")
	}
	if rec.Status != "running" {
		return sentinelplugin.Result{}, errors.New("run is no longer active")
	}
	rec.cancel()
	rec.Status = "cancelled"
	return sentinelplugin.Result{Text: "Cancellation requested for run " + id}, nil
}
func (r *aiRunner) results(args map[string]string) (sentinelplugin.Result, error) {
	if err := exactArgs(args); err != nil {
		return sentinelplugin.Result{}, err
	}
	r.mu.Lock()
	copyRecords := make([]runRecord, 0, len(r.runs))
	for _, rec := range r.runs {
		copyRecords = append(copyRecords, snapshot(rec))
	}
	r.mu.Unlock()
	sort.Slice(copyRecords, func(i, j int) bool { return copyRecords[i].StartedAt.After(copyRecords[j].StartedAt) })
	if len(copyRecords) == 0 {
		return sentinelplugin.Result{Text: "AI Lab: no runs yet. Use ai-lab run model=<installed-model> suite=sanity-v1"}, nil
	}
	var b strings.Builder
	b.WriteString("AI LAB / RECENT RUNS (volatile)\n")
	for _, record := range copyRecords {
		fmt.Fprintf(&b, "%s %s %s %s %d/%d\n", record.ID, record.Status, record.Model, record.Suite, record.Passed, record.Total)
	}
	return sentinelplugin.Result{Text: b.String()}, nil
}
func (r *aiRunner) suites(args map[string]string) (sentinelplugin.Result, error) {
	if err := exactArgs(args); err != nil {
		return sentinelplugin.Result{}, err
	}
	return sentinelplugin.Result{Text: "Built-in suites:\n  sanity-v1  3 deterministic instruction/arithmetic questions\n  code-v1    3 code comprehension questions\n\nNo model-generated code is executed. These are smoke tests, not comprehensive benchmarks."}, nil
}
func (r *aiRunner) shutdown() {
	r.mu.Lock()
	r.shuttingDown = true
	for _, rec := range r.runs {
		if rec.Status == "running" {
			rec.cancel()
		}
	}
	r.mu.Unlock()
	r.wait.Wait()
}
