package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fakeServer(t *testing.T, fn func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fn))
	t.Cleanup(srv.Close)
	return srv
}

func testRunner(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *aiRunner {
	t.Helper()
	srv := fakeServer(t, handler)
	r, err := newRunner(srv.URL+"/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.shutdown)
	return r
}

func TestEndpointValidation(t *testing.T) {
	accepted := []string{"", "http://127.0.0.1:11434/v1/chat/completions", "http://[::1]:11434/v1/chat/completions"}
	for _, in := range accepted {
		if _, err := localEndpoint(in); err != nil {
			t.Errorf("accepted %q: %v", in, err)
		}
	}
	rejected := []string{"https://127.0.0.1:11434/v1/chat/completions", "http://localhost:11434/v1/chat/completions", "http://0.0.0.0:11434/v1/chat/completions", "http://127.0.0.2:11434/v1/chat/completions", "http://127.0.0.1:11434/admin", "http://127.0.0.1:11434/v1/chat/completions?x=1", "http://user@127.0.0.1:11434/v1/chat/completions", "http://127.0.0.1/v1/chat/completions", "http://127.0.0.1:0/v1/chat/completions", "http://127.0.0.1:11434/v1/%63hat/completions"}
	for _, in := range rejected {
		if _, err := localEndpoint(in); err == nil {
			t.Errorf("rejected endpoint accepted: %q", in)
		}
	}
}

func TestRunCompletesAndScores(t *testing.T) {
	r := testRunner(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/chat/completions" {
			t.Errorf("wrong request %s %s", req.Method, req.URL.Path)
		}
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != "qwen-test" {
			t.Errorf("unexpected model: %s", body.Model)
		}
		answer := "7"
		last := body.Messages[len(body.Messages)-1].Content
		if strings.Contains(last, "sentinel-ready") {
			answer = "sentinel-ready"
		} else if strings.Contains(last, "17 multiplied by 19") {
			answer = "323"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": answer}}}, "usage": map[string]int{"completion_tokens": 4}})
	})
	result, err := r.run(map[string]string{"model": "qwen-test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Values["status"] != "running" {
		t.Fatalf("not running: %+v", result)
	}
	id := result.Values["id"]
	var values map[string]string
	for i := 0; i < 200; i++ {
		out, e := r.status(map[string]string{"id": id})
		if e != nil {
			t.Fatal(e)
		}
		values = out.Values
		if values["status"] != "running" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if values["status"] != "completed" || values["passed"] != "3/3" || values["tokens"] != "12" {
		t.Fatalf("incorrect result: %+v", values)
	}
	list, err := r.results(nil)
	if err != nil || !strings.Contains(list.Text, id) {
		t.Fatalf("missing result: %+v %v", list, err)
	}
}

func TestCancellationAndConcurrency(t *testing.T) {
	entered := make(chan struct{}, 1)
	r := testRunner(t, func(w http.ResponseWriter, req *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-req.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	})
	start, err := r.run(map[string]string{"model": "qwen-test", "suite": "code-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.run(map[string]string{"model": "qwen-test"}); err == nil {
		t.Fatal("allowed concurrent benchmark")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("runner never contacted model")
	}
	if _, err := r.cancel(map[string]string{"id": start.Values["id"]}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		r.mu.Lock()
		active := r.active
		r.mu.Unlock()
		if !active {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	result, err := r.status(map[string]string{"id": start.Values["id"]})
	if err != nil {
		t.Fatal(err)
	}
	if result.Values["status"] != "cancelled" {
		t.Fatalf("expected cancellation: %+v", result.Values)
	}
}

func TestBadArgsAndResponses(t *testing.T) {
	r := testRunner(t, func(w http.ResponseWriter, req *http.Request) { http.Error(w, "secret diagnostic", 502) })
	invalid := []map[string]string{{"model": ""}, {"model": "../../secret"}, {"model": "valid", "suite": "missing"}, {"model": "valid", "command": "exec"}}
	for _, a := range invalid {
		if _, err := r.run(a); err == nil {
			t.Errorf("accepted invalid args: %v", a)
		}
	}
	if _, err := r.status(map[string]string{"id": "../../../secret"}); err == nil {
		t.Error("unsafe ID accepted")
	}
	started, err := r.run(map[string]string{"model": "local-test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		out, err := r.status(map[string]string{"id": started.Values["id"]})
		if err != nil {
			t.Fatal(err)
		}
		if out.Values["status"] != "running" {
			if out.Values["status"] != "failed" {
				t.Errorf("bad failure status: %v", out.Values)
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.mu.Lock()
	rec := snapshot(r.runs[started.Values["id"]])
	r.mu.Unlock()
	if strings.Contains(rec.Error, "secret diagnostic") {
		t.Fatal("leaked provider error content")
	}
	if _, err := r.cancel(map[string]string{"id": started.Values["id"]}); err == nil {
		t.Fatal("cancelled completed job")
	}
}

func TestRequestTimeout(t *testing.T) {
	r := testRunner(t, func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := r.ask(ctx, "test", "test question")
	if err == nil {
		t.Fatal("cancelled request returned no error")
	}
}
