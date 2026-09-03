#!/bin/sh
set -eu

specs_root=${AEP_SPECS_DIR:-../aep-specs}
reports_root=.conformance/reports
manifest=.conformance/capability-manifest.json
repository_root=$(pwd -P)

mkdir -p "$reports_root"

for role in agent platform service; do
  (cd "$specs_root/ietf" && bundle exec ruby scripts/run_conformance.rb \
    --manifest "$repository_root/$manifest" \
    --role "$role" \
    --output "$repository_root/$reports_root/$role.json" \
    -- "$repository_root/.venv/bin/python" "$repository_root/scripts/conformance_adapter.py" "$role")
done
