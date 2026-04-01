package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

type ServeCmd struct{}

func (c *ServeCmd) Run(cli *CLI) error {
	stateMachine := cli.AgePlugin
	if stateMachine == "" {
		return fmt.Errorf(`--age-plugin=STATE_MACHINE requires "recipient-v1" or "identity-v1"`)
	}

	var socketPath string
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" {
		return fmt.Errorf("XDG_RUNTIME_DIR is not set")
	}
	socketPath = filepath.Join(xdg, "piv-agent", "age.socket")

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("couldn't connect to socket %s: %v", socketPath, err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "%s\n", stateMachine)
	if err != nil {
		return fmt.Errorf("couldn't write state machine to socket: %v", err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		defer wg.Done()
		// close the socket conn to cleanly exit the other goroutine
		defer conn.Close()
		if _, err = io.Copy(conn, os.Stdin); err != nil {
			fmt.Fprintf(os.Stderr, "error copying stdin to socket: %v\n", err)
			// unexpected non-EOF error indicates stdin didn't close first, cleanly
			os.Exit(1)
		}
	})
	wg.Go(func() {
		defer wg.Done()
		defer os.Stdin.Close()
		if _, err = io.Copy(os.Stdout, conn); err != nil {
			fmt.Fprintf(os.Stderr, "error copying socket to stdout: %v\n", err)
		}
	})
	wg.Wait()
	return nil
}
