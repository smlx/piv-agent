package assuan

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

// Run the event machine loop
func (a *Assuan) Run(ctx context.Context) error {
	// register connection
	if err := a.Occur(connect); err != nil {
		return fmt.Errorf("error handling connect: %w", err)
	}
	var e Event
	for {
		// check for cancellation
		if err := ctx.Err(); err != nil {
			return err
		}
		// get the next command. returns at latest after conn deadline expiry.
		line, err := a.reader.ReadBytes(byte('\n'))
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
