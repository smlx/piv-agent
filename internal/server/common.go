package server

import (
	"net"

	"go.uber.org/zap"
)

// accept connections in a goroutine and return them on a channel
func accept(log *zap.Logger, l net.Listener) <-chan net.Conn {
	conns := make(chan net.Conn)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Error("accept error", zap.Error(err))
				close(conns)
				return
			}
			conns <- c
		}
	}()
	return conns
}
