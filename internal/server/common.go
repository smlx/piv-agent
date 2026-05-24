package server

import (
	"log/slog"
	"net"
)

// accept connections in a goroutine and return them on a channel
func accept(log *slog.Logger, l net.Listener) <-chan net.Conn {
	conns := make(chan net.Conn)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Error("accept error", slog.Any("error", err))
				close(conns)
				return
			}
			conns <- c
		}
	}()
	return conns
}
