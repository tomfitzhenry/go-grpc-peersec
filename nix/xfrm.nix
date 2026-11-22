{ lib }:

# Deterministically derives the Transport-Mode ESP-NULL SA table from a
# declarative fleet graph ({ hosts, services }).
#
# Because WireGuard already handles encryption, authentication, PFS, rekeying,
# and anti-replay, ESP-NULL SAs carry no cryptographic keys — each SPI is just
# a 32-bit label identifier mapping (src, dst, SPI) -> XFRMA_SEC_CTX.
#
# Without MLS, each service has exactly one SELinux context
# (system_u:system_r:svc_<name>_t), so each service simply needs one SA per
# peer host.
let
  # Derive a deterministic non-zero 32-bit hex SPI from (src, dst, ctx).
  # Prefix with 0x1.. so SPIs are always >= 0x10000000 (well above RFC 4303
  # reserved range 0..255).
  spiFor =
    src: dst: ctx:
    let
      h = builtins.hashString "sha256" "${src}->${dst}:${ctx}";
      hex = builtins.substring 0 7 h;
    in
    "0x1${hex}";

  contextOf = name: "system_u:system_r:svc_${name}_t";

  mkTable =
    {
      hosts,
      services,
    }:
    let
      hostNames = lib.attrNames hosts;
      svcList = lib.mapAttrsToList (name: svc: svc // { inherit name; }) services;
      spdSvcs = lib.filter (s: s.useSpd or true) svcList;

      allSAs = lib.concatMap (
        svc:
        let
          srcHost = hosts.${svc.host};
          ctx = contextOf svc.name;
        in
        lib.concatMap (
          peerName:
          lib.optional (peerName != svc.host) {
            src = srcHost.overlayIP;
            dst = hosts.${peerName}.overlayIP;
            inherit ctx;
            spi = spiFor srcHost.overlayIP hosts.${peerName}.overlayIP ctx;
            label = "${svc.name} (${svc.host} -> ${peerName})";
          }
        ) hostNames
      ) spdSvcs;

      spiKeys = map (sa: "${sa.src}|${sa.dst}|${sa.spi}") allSAs;
    in
    assert lib.assertMsg (
      lib.unique spiKeys == spiKeys
    ) "esp-null: SPI hash collision detected";
    allSAs;
in
{
  inherit spiFor contextOf mkTable;
}
