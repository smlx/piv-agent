package assuan

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

// Run the event machine loop
func (a *Assuan) Run(conn io.Reader) error {
	// register connection
	if err := a.Occur(connect); err != nil {
		return fmt.Errorf("error handling connect: %w", err)
	}
	// parse incoming messages to events
	r := bufio.NewReader(conn)
	var e Event
	for {
		line, err := r.ReadBytes(byte('\n'))
		if err != nil {
			if err == io.EOF {
				return nil // connection closed
			}
			return fmt.Errorf("socket read error: %w", err)
		}
		// parse the event
		msg := bytes.Split(bytes.TrimRight(line, "\n"), []byte(" "))
		if err := e.UnmarshalText(msg[0]); err != nil {
			return fmt.Errorf(`couldn't unmarshal line %q: %w`, line, err)
		}
		// send the event and additional arguments to the state machine
		if err := a.Occur(e, msg[1:]...); err != nil {
			return fmt.Errorf("couldn't handle event %v in state %v: %w",
				e, State(a.State), err)
		}
	}
}
