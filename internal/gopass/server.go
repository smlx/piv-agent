package gopass

import (
	"github.com/smlx/piv-agent/internal/gopass/pb"
	"google.golang.org/grpc"
)

var opts []grpc.ServerOption

func test() {
	grpcServer := grpc.NewServer(opts...)
	gpc := &GPCrypto{}
	pb.RegisterCryptoServer(grpcServer, gpc)
	grpcServer.Serve(lis)
}
