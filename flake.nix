{
  description = "A `Tahoe-LAFS`_ storage-system plugin which authorizes storage operations based on privacy-respecting tokens.";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system: let

      pkgs = nixpkgs.legacyPackages.${system};

      utils = import ./nix/lib.nix {
        inherit system pkgs;
      };

    in {

      packages = {
        zkapauthorizer = (import ./default.nix { }).zkapauthorizer;
      };

      bundlers = {
        toWheel = utils.toWheel;
      };
    });
}
