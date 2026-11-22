package grpcpeersec

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/peer"
)

func TestCredentialsMisuse(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	srvCreds := ServerCredentials()
	if _, _, err := srvCreds.ClientHandshake(t.Context(), "example", c1); err == nil {
		t.Fatal("expected error calling ClientHandshake on ServerCredentials")
	}

	cliCreds := ClientCredentials()
	if _, _, err := cliCreds.ServerHandshake(c2); err == nil {
		t.Fatal("expected error calling ServerHandshake on ClientCredentials")
	}
}

func TestSecurityLevelAndClone(t *testing.T) {
	c := ServerCredentials(WithSecurityLevel(credentials.PrivacyAndIntegrity)).(*transportCreds)
	if c.cfg.securityLevel != credentials.PrivacyAndIntegrity {
		t.Fatalf("securityLevel = %v, want PrivacyAndIntegrity", c.cfg.securityLevel)
	}
	if c.Info().SecurityProtocol != authType {
		t.Fatalf("SecurityProtocol = %q, want %q", c.Info().SecurityProtocol, authType)
	}

	cloned := c.Clone()
	if err := cloned.OverrideServerName("override.internal"); err != nil {
		t.Fatalf("OverrideServerName: %v", err)
	}
	if c.Info().ServerName != "" {
		t.Fatalf("Clone mutated original ServerName: %q", c.Info().ServerName)
	}
	if cloned.Info().ServerName != "override.internal" {
		t.Fatalf("cloned ServerName = %q, want override.internal", cloned.Info().ServerName)
	}
}

func TestPeerFromContext(t *testing.T) {
	if _, ok := PeerFromContext(t.Context()); ok {
		t.Fatal("expected false for empty context")
	}

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: AuthInfo{
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.IntegrityOnly},
			Raw:            "system_u:system_r:svc_alice_t",
		},
	})
	info, ok := PeerFromContext(ctx)
	if !ok {
		t.Fatal("expected true for valid AuthInfo")
	}
	if info.Raw != "system_u:system_r:svc_alice_t" || info.SecurityLevel != credentials.IntegrityOnly {
		t.Fatalf("unexpected AuthInfo: %+v", info)
	}
}

type testService struct {
	grpc_testing.UnimplementedTestServiceServer
}

func (s *testService) EmptyCall(ctx context.Context, _ *grpc_testing.Empty) (*grpc_testing.Empty, error) {
	if _, ok := PeerFromContext(ctx); !ok {
		return nil, errors.New("missing SO_PEERSEC AuthInfo in context")
	}
	return &grpc_testing.Empty{}, nil
}

func TestGRPCUnixSocketEndToEnd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "grpc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := grpc.NewServer(grpc.Creds(ServerCredentials(
		WithSecurityLevel(credentials.IntegrityOnly),
		WithAuthorize(func(info AuthInfo) error {
			if info.Raw == "" {
				return errors.New("empty label")
			}
			return nil
		}),
	)))
	grpc_testing.RegisterTestServiceServer(srv, &testService{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(ClientCredentials(WithSecurityLevel(credentials.IntegrityOnly))),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()

	client := grpc_testing.NewTestServiceClient(conn)
	_, err = client.EmptyCall(t.Context(), &grpc_testing.Empty{})
	if err != nil {
		// On kernels without an active LSM supporting SO_PEERSEC, ServerHandshake fails with ENOPROTOOPT.
		if errors.Is(err, syscall.ENOPROTOOPT) || strings.Contains(err.Error(), "protocol not available") {
			t.Skipf("kernel does not support SO_PEERSEC on unix sockets: %v", err)
		}
		t.Fatalf("EmptyCall: %v", err)
	}
}
