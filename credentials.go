package grpcpeersec

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/tomfitzhenry/go-peersec"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const authType = "so_peersec"

// AuthInfo carries the peer's raw SO_PEERSEC security context.
type AuthInfo struct {
	credentials.CommonAuthInfo
	Raw string
}

// AuthType implements credentials.AuthInfo.
func (AuthInfo) AuthType() string { return authType }

// PeerFromContext extracts the peer's AuthInfo from a gRPC handler context.
func PeerFromContext(ctx context.Context) (AuthInfo, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return AuthInfo{}, false
	}
	info, ok := p.AuthInfo.(AuthInfo)
	if !ok || info.Raw == "" {
		return AuthInfo{}, false
	}
	return info, true
}

// Option configures ServerCredentials or ClientCredentials.
type Option func(*config)

type config struct {
	securityLevel  credentials.SecurityLevel
	authorize      func(AuthInfo) error
	requirePeerSec bool
}

// WithSecurityLevel sets CommonAuthInfo.SecurityLevel on the returned AuthInfo.
// It defaults to credentials.NoSecurity because SO_PEERSEC alone does not
// describe the underlying transport's encryption or integrity guarantees.
func WithSecurityLevel(level credentials.SecurityLevel) Option {
	return func(c *config) {
		c.securityLevel = level
	}
}

// WithAuthorize registers an optional handshake-time authorization check.
func WithAuthorize(fn func(AuthInfo) error) Option {
	return func(c *config) {
		c.authorize = fn
	}
}

// WithRequirePeerSec controls whether ClientCredentials fails the handshake if
// SO_PEERSEC cannot be read from the client socket (default false).
// ServerCredentials always requires SO_PEERSEC.
func WithRequirePeerSec(require bool) Option {
	return func(c *config) {
		c.requirePeerSec = require
	}
}

// ServerCredentials returns gRPC TransportCredentials that require and extract
// SO_PEERSEC from each accepted connection.
func ServerCredentials(opts ...Option) credentials.TransportCredentials {
	cfg := config{
		securityLevel:  credentials.NoSecurity,
		requirePeerSec: true,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return &transportCreds{server: true, cfg: cfg}
}

// ClientCredentials returns gRPC TransportCredentials for a client connecting
// over a kernel-labeled transport (such as Labeled IPsec or Unix domain sockets).
func ClientCredentials(opts ...Option) credentials.TransportCredentials {
	cfg := config{
		securityLevel: credentials.NoSecurity,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return &transportCreds{server: false, cfg: cfg}
}

type transportCreds struct {
	server     bool
	serverName string
	cfg        config
}

func (c *transportCreds) ClientHandshake(_ context.Context, _ string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.server {
		return nil, nil, errors.New("grpcpeersec: ServerCredentials cannot be used for ClientHandshake")
	}
	info := AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: c.cfg.securityLevel},
	}
	raw, err := peersec.FromConn(rawConn)
	if err != nil {
		if c.cfg.requirePeerSec {
			return nil, nil, fmt.Errorf("grpcpeersec: read SO_PEERSEC: %w", err)
		}
		return rawConn, info, nil
	}
	info.Raw = raw
	if c.cfg.authorize != nil {
		if err := c.cfg.authorize(info); err != nil {
			return nil, nil, err
		}
	}
	return rawConn, info, nil
}

func (c *transportCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if !c.server {
		return nil, nil, errors.New("grpcpeersec: ClientCredentials cannot be used for ServerHandshake")
	}
	raw, err := peersec.FromConn(rawConn)
	if err != nil {
		return nil, nil, fmt.Errorf("grpcpeersec: read SO_PEERSEC: %w", err)
	}
	info := AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: c.cfg.securityLevel},
		Raw:            raw,
	}
	if c.cfg.authorize != nil {
		if err := c.cfg.authorize(info); err != nil {
			return nil, nil, err
		}
	}
	return rawConn, info, nil
}

func (c *transportCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: authType,
		SecurityVersion:  "1.0",
		ServerName:       c.serverName,
	}
}

func (c *transportCreds) Clone() credentials.TransportCredentials {
	cp := *c
	return &cp
}

func (c *transportCreds) OverrideServerName(name string) error {
	c.serverName = name
	return nil
}
