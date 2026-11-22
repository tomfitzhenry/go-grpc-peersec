package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tomfitzhenry/go-grpc-peersec"
	"github.com/tomfitzhenry/go-grpc-peersec/examples/greeter/greeterpb"
	"github.com/tomfitzhenry/go-peersec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type server struct {
	greeterpb.UnimplementedGreeterServer
}

func (s *server) SayHello(ctx context.Context, req *greeterpb.HelloRequest) (*greeterpb.HelloReply, error) {
	info, ok := grpcpeersec.PeerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing SO_PEERSEC")
	}
	return &greeterpb.HelloReply{
		Message: fmt.Sprintf("hello %s", req.GetName()),
		PeerSec: info.Raw,
	}, nil
}

func main() {
	mode := flag.String("mode", "server", "server or client")
	network := flag.String("network", "tcp4", "tcp4 or unix")
	addr := flag.String("addr", "127.0.0.1:9001", "listen or dial address")
	name := flag.String("name", "world", "greeting name (client mode)")
	allowType := flag.String("allow-type", "", "optional SELinux domain type required by server")
	flag.Parse()

	switch *mode {
	case "server":
		if *network == "unix" {
			_ = os.Remove(*addr)
		}
		ln, err := net.Listen(*network, *addr)
		if err != nil {
			log.Fatalf("listen: %v", err)
		}

		opts := []grpcpeersec.Option{
			grpcpeersec.WithSecurityLevel(credentials.PrivacyAndIntegrity),
		}
		if *allowType != "" {
			want := strings.TrimSpace(*allowType)
			opts = append(opts, grpcpeersec.WithAuthorize(func(info grpcpeersec.AuthInfo) error {
				ctx, err := peersec.ParseSELinuxContext(info.Raw)
				if err != nil {
					return err
				}
				if ctx.IsUnlabeled() || ctx.Type != want {
					return fmt.Errorf("domain %q not allowed (want %q)", ctx.Type, want)
				}
				return nil
			}))
		}

		srv := grpc.NewServer(grpc.Creds(grpcpeersec.ServerCredentials(opts...)))
		greeterpb.RegisterGreeterServer(srv, &server{})
		log.Printf("greeter listening on %s (%s)", ln.Addr(), *network)
		log.Fatal(srv.Serve(ln))

	case "client":
		target := *addr
		if *network == "unix" {
			target = "unix://" + *addr
		}
		conn, err := grpc.NewClient(target,
			grpc.WithTransportCredentials(grpcpeersec.ClientCredentials(
				grpcpeersec.WithSecurityLevel(credentials.PrivacyAndIntegrity),
			)),
		)
		if err != nil {
			log.Fatalf("NewClient: %v", err)
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		resp, err := greeterpb.NewGreeterClient(conn).SayHello(ctx, &greeterpb.HelloRequest{Name: *name})
		if err != nil {
			log.Fatalf("SayHello: %v", err)
		}
		fmt.Printf("%s (peer_sec=%s)\n", resp.GetMessage(), resp.GetPeerSec())

	default:
		log.Fatalf("unknown -mode %q", *mode)
	}
}
