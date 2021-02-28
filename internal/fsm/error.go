package fsm

import "fmt"

// UnexpectedEventError is an error type that exposes the event/state that
// caused the error.
type UnexpectedEventError struct {
	Event Event
	State State
}

func (e UnexpectedEventError) Error() string {
	return fmt.Sprintf("unexpected event %v for state %v", e.Event, e.State)
}
