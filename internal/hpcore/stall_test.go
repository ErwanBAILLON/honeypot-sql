package hpcore

import (
	"context"
	"testing"
	"time"
)

func TestStallOffReturnsImmediately(t *testing.T) {
	s := &Session{ctx: context.Background()} // Tarpit zero value = off
	start := time.Now()
	s.Stall()
	if d := time.Since(start); d > 5*time.Millisecond {
		t.Fatalf("stall with tarpit off took %s", d)
	}
}

func TestStallWakesWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // session already over (SessionMax hit, shutdown)
	s := &Session{ctx: ctx}
	s.Limits.Tarpit = time.Hour
	start := time.Now()
	s.Stall()
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("stall ignored a cancelled context: waited %s", d)
	}
}

func TestStallWaitsRoughlyTheDelay(t *testing.T) {
	s := &Session{ctx: context.Background()}
	s.Limits.Tarpit = 20 * time.Millisecond
	start := time.Now()
	s.Stall()
	if d := time.Since(start); d < 20*time.Millisecond {
		t.Fatalf("stall returned too early: %s", d)
	}
}
