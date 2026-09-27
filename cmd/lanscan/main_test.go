package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestGraceReturnsNormallyWithoutInterrupt(t *testing.T) {
	var stderr bytes.Buffer
	code := runWithGrace(context.Background(), time.Millisecond, &stderr, func(int) { t.Error("exit called") }, func() int { return 3 })
	if code != 3 || stderr.Len() != 0 {
		t.Fatalf("code %d stderr %q", code, stderr.String())
	}
}

func TestGraceAllowsPromptDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	code := runWithGrace(ctx, time.Second, &stderr, func(int) { t.Error("exit called during drain") }, func() int {
		cancel()
		time.Sleep(10 * time.Millisecond)
		return 130
	})
	if code != 130 || stderr.Len() != 0 {
		t.Fatalf("code %d stderr %q", code, stderr.String())
	}
}

func TestGraceExpiresWhenSinkBlocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	exited := make(chan int, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWithGrace(ctx, 20*time.Millisecond, &stderr, func(code int) { exited <- code; close(release) }, func() int {
			cancel()
			<-release // a blocked output sink
			return 0
		})
	}()
	select {
	case code := <-exited:
		if code != 130 {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("grace period never expired")
	}
	<-done
	if !strings.Contains(stderr.String(), "grace period expired") {
		t.Fatalf("stderr %q", stderr.String())
	}
}
