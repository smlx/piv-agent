package assuan

import (
	"bufio"
	"bytes"
	"fmt"
	"io"

	"github.com/smlx/piv-agent/internal/fsm"
)

// Run the event machine loop
func (a *Assuan) Run(conn io.Reader) error {
	// register connection
	if err := a.fsm.Occur(fsm.Event(connect)); err != nil {
		return fmt.Errorf("error handling connect: %w", err)
	}
	// parse incoming messages to events
	r := bufio.NewReader(conn)
	var e event
	for {
		line, err := r.ReadBytes(byte('\n'))
		if err != nil {
			if err == io.EOF {
				return nil // connection closed
			}
			return fmt.Errorf("socket read error: %w", err)
		}
		if err := e.UnmarshalText(
			bytes.SplitN(line, []byte(" "), 2)[0]); err != nil {
			return fmt.Errorf("couldn't unmarshal line `%v`: %w", line, err)
		}
		if err := a.fsm.Occur(fsm.Event(e)); err != nil {
			return fmt.Errorf("error handling event %v: %w", e, err)
		}
	}
}
