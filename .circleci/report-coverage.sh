#! /usr/bin/env nix-shell
#! nix-shell -i bash -p "curl" -p "python3.withPackages (ps: [ ps.coveralls ps.pyyaml ])"
set -x
find ./result*/
cp ./result*/coverage/.coverage ./.coverage
coveralls
