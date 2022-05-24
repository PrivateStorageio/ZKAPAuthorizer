{ pkgs, zkapauthorizer, issuer }:
let
  lib = pkgs.callPackage ./lib.nix { };

  # Generated using PaymentServer-generate-key
  signingKeyPath = ./signing-key.ristretto;
in
pkgs.nixosTest {
  # https://nixos.org/nixos/manual/index.html#sec-nixos-tests
  nodes = {
    # Run a client node which will replicate its state and then fail.
    replication = lib.client { inherit zkapauthorizer; };

    # Run a client node which will recover the replicated state after the
    # first client fails.
    recovery = lib.client { inherit zkapauthorizer; };

    # Run a storage node which can hold the replicated state.  It will also
    # run an introducer because that's the simplest way to actually get the
    # clients to talk to the storage node.
    storage = lib.server { inherit zkapauthorizer signingKeyPath; };

    # Run a ZKAP issuer that we can use to get some ZKAPs for storing data and
    # which themselves should be replicated and recovered.
    issuer = lib.issuer { inherit issuer signingKeyPath; };
  };

  testScript = lib.makeTestScript {
    testpath = ./test_replication_recovery.py;
    kwargs = {
    };
  };
}
