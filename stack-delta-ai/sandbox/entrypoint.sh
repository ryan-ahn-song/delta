#!/bin/sh
set -eu

window="${1:-30}"
case "$window" in
  *[!0-9]*|'') echo "invalid observation window" >&2; exit 64 ;;
esac

mkdir -p /work/package "$HOME/.ssh" "$HOME/.aws"
cp -a /input/. /work/package/
printf '%s\n' 'STACK_DELTA_FAKE_SSH_KEY' > "$HOME/.ssh/id_rsa"
printf '%s\n' '[default]' 'aws_access_key_id=STACK_DELTA_FAKE' > "$HOME/.aws/credentials"
: > "$HOME/.bashrc"
chmod 600 "$HOME/.ssh/id_rsa" "$HOME/.aws/credentials"

export NODE_OPTIONS="--require=/opt/stack-delta/env-sensor.cjs"
cd /work/package

set +e
timeout --signal=KILL "${window}s" \
  strace -ff -ttt -s 4096 -yy -e trace=%file,%process,%network -o /output/trace \
  npm install --offline --ignore-scripts=false --no-audit --no-fund --package-lock=false
status=$?
set -e
exit "$status"

