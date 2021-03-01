// Package fsm implements a simple finite state machine. Events cause
// Transitions between States, and entry/exit to a state may be hooked by
// defining one or more functions to be called. That's it!
package fsm

import (
	"sync"
)

// Event represents an event that can occur which may cause a state transition.
type Event int

// State represents a state that the FSM can be in.
type State int

// Transition represents a transition that the FSM can make between states.
type Transition struct {
	Src   State
	Dst   State
	Event Event
}

// Machine represents a finite state machine (FSM).
type Machine struct {
	mu sync.Mutex
	// State is the current Machine state.
	State State
	// Transition is a slice of possible transitions from state to state.
	Transitions []Transition
	// OnEntry is a way of hooking transitions between functions. Each
	// func(Event) will be called just before the Machine enters the associated
	// State.
	OnEntry map[State][]func(Event, ...[]byte) error
	// OnExit works similarly to OnEntry. Each func(Event) will be called just
	// before the Machine leaves the associated State.
	OnExit map[State][]func(Event, ...[]byte) error
	// ErrorOnUnexpectedEvent, if set tot true, causes Occur to return an error
	// on an unexpected event.
	ErrorOnUnexpectedEvent bool
}

// Occur handles events which may cause a transition in the machine's state. It
// handles synchronisation via an internal mutex, so is safe to call from
// multiple goroutines.
// The data argument is additional data which is passed alongside the event.
func (m *Machine) Occur(e Event, data ...[]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.Transitions {
		if t.Event == e && t.Src == m.State {
			for _, f := range m.OnExit[m.State] {
				if err := f(e, data...); err != nil {
					return err
				}
			}
			for _, f := range m.OnEntry[t.Dst] {
				if err := f(e, data...); err != nil {
					return err
				}
			}
			m.State = t.Dst
			return nil
		}
	}
	if m.ErrorOnUnexpectedEvent {
		return UnexpectedEventError{
			Event: e,
			State: m.State,
		}
	}
	return nil
}
