# go-grpc-peersec

`google.golang.org/grpc/credentials.TransportCredentials` implementation backed by Linux `SO_PEERSEC` (via [`go-peersec`](https://github.com/tomfitzhenry/go-peersec)), for authenticating gRPC peers over Labeled IPsec (`ESP-NULL`) or Unix domain sockets.

## Usage

```go
srv := grpc.NewServer(
    grpc.Creds(grpcpeersec.ServerCredentials(
        grpcpeersec.WithSecurityLevel(credentials.PrivacyAndIntegrity),
        grpcpeersec.WithAuthorize(func(info grpcpeersec.AuthInfo) error {
            ctx, err := peersec.ParseSELinuxContext(info.Raw)
            if err != nil || ctx.IsUnlabeled() {
                return errors.New("unlabeled peer")
            }
            return nil
        }),
    )),
)
```

Inside an RPC handler or interceptor:

```go
info, ok := grpcpeersec.PeerFromContext(ctx)
```

## Example & tests

```console
$ nix flake check -L   # runs Go tests, cross-compilation, and a 2-VM NixOS WireGuard + ESP-NULL gRPC test
```
