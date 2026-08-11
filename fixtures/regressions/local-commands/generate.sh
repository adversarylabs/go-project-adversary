#!/bin/sh
set -eu

mkdir -p generated
sed 's/example/generated/' input.txt > generated/output.txt
./tools/formatter generated/output.txt
