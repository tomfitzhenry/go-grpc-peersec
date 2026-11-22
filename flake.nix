{
  description = "gRPC TransportCredentials backed by Linux SO_PEERSEC";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-26.05";
  };

  outputs =
    {
      nixpkgs,
      ...
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      greeterPkg = pkgs.buildGoModule {
        pname = "go-grpc-peersec-greeter";
        version = "0.1.0";
        src = pkgs.lib.cleanSource ./.;
        vendorHash = "sha256-MC1Ozh+V2FQ+XH58tm4VYBXSXwG/pFzhZnsxlESOt+k=";
        subPackages = [ "examples/greeter" ];

        nativeBuildInputs = [
          pkgs.protobuf
          pkgs.protoc-gen-go
          pkgs.protoc-gen-go-grpc
        ];

        preBuild = ''
          protoc \
            --go_out=. \
            --go_opt=module=github.com/tomfitzhenry/go-grpc-peersec \
            --go-grpc_out=. \
            --go-grpc_opt=module=github.com/tomfitzhenry/go-grpc-peersec \
            examples/greeter/proto/greeter.proto
        '';

        checkPhase = ''
          runHook preCheck
          go test -v ./...
          go vet ./...
          GOOS=darwin go build ./...
          runHook postCheck
        '';

        env.CGO_ENABLED = "0";
      };
    in
    {
      packages.${system} = {
        default = greeterPkg;
        greeter = greeterPkg;
      };

      checks.${system} = {
        vm-test = import ./nix/test.nix {
          inherit pkgs greeterPkg;
        };
      };
    };
}
