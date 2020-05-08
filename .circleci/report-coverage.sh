#! /usr/bin/env nix-shell
#! nix-shell -i bash -p "python.withPackages (ps: [ ps.codecov ])"
find ./result-doc/share/doc
cp ./result-doc/share/doc/*/.coverage ./
python -m coverage report
python -m coverage xml
codecov --file coverage.xml
