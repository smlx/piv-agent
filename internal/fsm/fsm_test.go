package fsm_test

import (
	"testing"

	"github.com/smlx/piv-agent/internal/fsm"
)

const (
	invalidEvent fsm.Event = iota
	pushOpen
	pullShut
)
const (
	invalidState fsm.State = iota
	opened
	closed
)

func TestFSM(t *testing.T) {
	var openCount uint
	var closeCount uint
	door := fsm.Machine{
		State: opened,
		Transitions: []fsm.Transition{
			{
				Src:   opened,
				Dst:   closed,
				Event: pullShut,
			},
			{
				Src:   closed,
				Dst:   opened,
				Event: pushOpen,
			},
		},
		OnEntry: map[fsm.State][]func(fsm.Event, ...[]byte) error{
			opened: []func(fsm.Event, ...[]byte) error{
				func(_ fsm.Event, _ ...[]byte) error {
					openCount++
					return nil
				},
			},
			closed: []func(fsm.Event, ...[]byte) error{
				func(_ fsm.Event, _ ...[]byte) error {
					closeCount++
					return nil
				},
			},
		},
	}
	// e is a collection of expected state
	type e struct {
		state      fsm.State
		openCount  uint
		closeCount uint
	}
	var steps = map[string]struct {
		event  fsm.Event
		expect e
	}{
		"step 1": {event: pushOpen, expect: e{state: opened, openCount: 0, closeCount: 0}},
		"step 2": {event: pullShut, expect: e{state: closed, openCount: 0, closeCount: 1}},
		"step 3": {event: pullShut, expect: e{state: closed, openCount: 0, closeCount: 1}},
		"step 4": {event: pushOpen, expect: e{state: opened, openCount: 1, closeCount: 1}},
		"step 5": {event: pushOpen, expect: e{state: opened, openCount: 1, closeCount: 1}},
	}
	for name, step := range steps {
		if err := door.Occur(step.event); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if door.State != step.expect.state {
			t.Fatalf("%s: expected %v, got %v", name, step.expect.state, door.State)
		}
		if openCount != step.expect.openCount {
			t.Fatalf("%s: expected %v, got %v", name, step.expect.openCount, openCount)
		}
		if closeCount != step.expect.closeCount {
			t.Fatalf("%s: expected %v, got %v", name, step.expect.closeCount, closeCount)
		}
	}
}
