#!/usr/bin/env bash
set -o errexit

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT/go-controller"

echo "Regenerating mockery mocks"
make mocksgen

CHANGES=$(git -C "$ROOT" status --porcelain -- go-controller/pkg)
test -z "$CHANGES"
