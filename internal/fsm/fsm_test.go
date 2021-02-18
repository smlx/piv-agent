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
		OnEntry: map[fsm.State][]func(fsm.Event){
			opened: []func(fsm.Event){
				func(_ fsm.Event) {
					openCount++
				},
			},
			closed: []func(fsm.Event){
				func(_ fsm.Event) {
					closeCount++
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
	var testCases = map[string]struct {
		event  fsm.Event
		expect e
	}{
		"step 1": {event: pushOpen, expect: e{state: opened, openCount: 0, closeCount: 0}},
		"step 2": {event: pullShut, expect: e{state: closed, openCount: 0, closeCount: 1}},
		"step 3": {event: pullShut, expect: e{state: closed, openCount: 0, closeCount: 1}},
		"step 4": {event: pushOpen, expect: e{state: opened, openCount: 1, closeCount: 1}},
		"step 5": {event: pushOpen, expect: e{state: opened, openCount: 1, closeCount: 1}},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			door.Occur(tc.event)
			if door.State != tc.expect.state {
				t.Fatalf("expected %v, got %v", tc.expect.state, door.State)
			}
			if openCount != tc.expect.openCount {
				t.Fatalf("expected %v, got %v", tc.expect.openCount, openCount)
			}
			if closeCount != tc.expect.closeCount {
				t.Fatalf("expected %v, got %v", tc.expect.closeCount, closeCount)
			}
		})
	}
}
