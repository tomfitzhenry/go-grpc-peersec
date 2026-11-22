{
  pkgs,
  greeterPkg,
}:

let
  inherit (pkgs) lib;
  secilc = pkgs.callPackage ./secilc.nix { };
  xfrm = import ./xfrm.nix { inherit lib; };

  hosts = {
    app = {
      overlayIP = "10.99.0.1";
      underlayIP = "192.168.1.1";
      wgPublicKey = "PudJ9oCMLHQ0vnYufhEdOgQmzA7/kY6CG654SspOCxQ=";
    };
    server = {
      overlayIP = "10.99.0.2";
      underlayIP = "192.168.1.2";
      wgPublicKey = "s4x2MypWuqJE6Giart2fUEfdffjVKbICIsW0T7n9rEE=";
    };
  };

  wgKeys = {
    app.privateKey = "MBtLnGNGGDzkWAKGdgbcJPZQ8BP9kRq7JGaNIqV17HA=";
    server.privateKey = "2Azjw1V2bmAHbNAABD0PHt8qRILZr5567x4jczjy8ns=";
  };

  services = {
    greeter = {
      host = "server";
      listenPort = 9001;
    };
    alice = {
      host = "app";
      connectTo = [ "greeter" ];
    };
    bob = {
      host = "app";
      connectTo = [ "greeter" ];
    };
    web = {
      host = "app";
      connectTo = [ ];
    };
  };

  policy = pkgs.callPackage ./policy {
    inherit secilc services;
  };

  allSAs = xfrm.mkTable { inherit hosts services; };

  runInCtx = pkgs.writeShellScriptBin "run-in-ctx" ''
    set -eu
    ctx="$1"
    shift
    printf '%s' "$ctx" > /proc/self/attr/exec
    exec "$@"
  '';

  mkNode =
    hostName:
    let
      localHost = hosts.${hostName};
      peerHosts = lib.removeAttrs hosts [ hostName ];
      localSAs = lib.filter (sa: sa.src == localHost.overlayIP || sa.dst == localHost.overlayIP) allSAs;
      wgKeyFile = "/run/go-grpc-peersec/wg0.key";
    in
    {
      boot.kernelPatches = [
        {
          name = "enable-security-network-xfrm";
          patch = null;
          structuredExtraConfig = {
            SECURITY_NETWORK_XFRM = lib.kernel.yes;
          };
        }
      ];
      boot.kernelModules = [
        "esp4"
        "xfrm_user"
        "crypto_null"
        "wireguard"
      ];
      security.lsm = lib.mkForce [ ];
      boot.kernelParams = [
        "security=selinux"
        "selinux=1"
        "enforcing=1"
        "lsm=selinux,landlock,yama,bpf"
        "audit=1"
      ];
      security.auditd.enable = true;

      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = localHost.underlayIP;
          prefixLength = 24;
        }
      ];
      networking.firewall.allowedUDPPorts = [ 51820 ];
      networking.firewall.trustedInterfaces = [ "wg0" ];

      environment.systemPackages = [
        greeterPkg
        runInCtx
        pkgs.iproute2
        pkgs.wireguard-tools
      ];

      system.activationScripts.go-grpc-peersec-selinux = {
        deps = [ "specialfs" ];
        text = ''
          if [ ! -e /sys/fs/selinux/load ]; then
            mount -t selinuxfs selinuxfs /sys/fs/selinux || true
          fi
          cat ${policy}/policy.${toString policy.policyVersion} > /sys/fs/selinux/load
        '';
      };

      systemd.services = {
        wg-key = {
          wantedBy = [ "wireguard-wg0.service" ];
          before = [ "wireguard-wg0.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            install -d -m 0700 /run/go-grpc-peersec
            install -m 0600 /dev/null ${wgKeyFile}
            printf '%s\n' ${lib.escapeShellArg wgKeys.${hostName}.privateKey} > ${wgKeyFile}
          '';
        };

        peersec-xfrm = {
          wantedBy = [ "multi-user.target" ];
          after = [ "wireguard-wg0.service" ];
          requires = [ "wireguard-wg0.service" ];
          path = [
            pkgs.coreutils
            pkgs.iproute2
          ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            grep -qx 1 /sys/fs/selinux/enforce
            ip xfrm state flush
            ip xfrm policy flush

            ${lib.concatMapStringsSep "\n" (sa: ''
              ip xfrm state add \
                src ${sa.src} dst ${sa.dst} proto esp spi ${sa.spi} \
                mode transport \
                enc "ecb(cipher_null)" "" \
                auth "digest_null" "" \
                ctx ${lib.escapeShellArg sa.ctx}
            '') localSAs}

            ${lib.concatStringsSep "\n" (
              lib.mapAttrsToList (_: peer: ''
                ip xfrm policy add \
                  src ${localHost.overlayIP}/32 dst ${peer.overlayIP}/32 dir out \
                  priority 100 ctx "system_u:object_r:ipsec_spd_t" \
                  tmpl proto esp mode transport level required
                ip xfrm policy add \
                  src ${peer.overlayIP}/32 dst ${localHost.overlayIP}/32 dir in \
                  priority 100 ctx "system_u:object_r:ipsec_spd_t" \
                  tmpl proto esp mode transport level required
                ip xfrm policy add \
                  src ${localHost.overlayIP}/32 dst ${peer.overlayIP}/32 dir out \
                  priority 2000 action block
                ip xfrm policy add \
                  src ${peer.overlayIP}/32 dst ${localHost.overlayIP}/32 dir in \
                  priority 2000 action block
              '') peerHosts
            )}
          '';
        };
      }
      // lib.optionalAttrs (hostName == "server") {
        greeter-server = {
          wantedBy = [ "multi-user.target" ];
          after = [ "peersec-xfrm.service" ];
          requires = [ "peersec-xfrm.service" ];
          serviceConfig = {
            Type = "simple";
            ExecStart = "${runInCtx}/bin/run-in-ctx system_u:system_r:svc_greeter_t ${greeterPkg}/bin/greeter -mode server -network tcp4 -addr ${hosts.server.overlayIP}:9001 -allow-type svc_alice_t";
          };
        };
      };

      networking.wireguard.interfaces.wg0 = {
        ips = [ "${localHost.overlayIP}/24" ];
        listenPort = 51820;
        privateKeyFile = wgKeyFile;
        peers = lib.mapAttrsToList (_: peer: {
          publicKey = peer.wgPublicKey;
          allowedIPs = [ "${peer.overlayIP}/32" ];
          endpoint = "${peer.underlayIP}:51820";
          persistentKeepalive = 5;
        }) peerHosts;
      };
    };
in
pkgs.testers.runNixOSTest {
  name = "go-grpc-peersec-vm-test";

  nodes = {
    app = mkNode "app";
    server = mkNode "server";
  };

  testScript = ''
    start_all()
    for node in (app, server):
        node.wait_for_unit("multi-user.target")
        node.wait_for_unit("peersec-xfrm.service")
        assert node.succeed("cat /sys/fs/selinux/enforce").strip() == "1"

    server.wait_for_unit("greeter-server.service")
    server.wait_until_succeeds("ss -tln | grep -q '${hosts.server.overlayIP}:9001'")

    out = app.succeed(
        "run-in-ctx system_u:system_r:svc_alice_t "
        "greeter -mode client -network tcp4 -addr ${hosts.server.overlayIP}:9001 -name alice"
    ).strip()
    print("alice greeter:", out)
    assert out == "hello alice (peer_sec=system_u:system_r:svc_alice_t)", f"unexpected output: {out}"

    # svc_bob_t is allowed by SELinux peer { recv } to connect to svc_greeter_t,
    # but rejected at ServerHandshake by WithAuthorize (-allow-type svc_alice_t).
    app.fail(
        "run-in-ctx system_u:system_r:svc_bob_t "
        "greeter -mode client -network tcp4 -addr ${hosts.server.overlayIP}:9001 -name bob"
    )

    # svc_web_t is dropped in kernel by SELinux peer { recv }.
    app.fail(
        "run-in-ctx system_u:system_r:svc_web_t "
        "greeter -mode client -network tcp4 -addr ${hosts.server.overlayIP}:9001 -name web"
    )

    server.succeed("sleep 1")
    audit = server.succeed("cat /var/log/audit/audit.log")
    assert any(
        "avc:  denied" in line and "svc_greeter_t" in line and "svc_web_t" in line
        for line in audit.splitlines()
    ), f"expected AVC denial for svc_web_t -> svc_greeter_t: {audit}"
  '';
}
