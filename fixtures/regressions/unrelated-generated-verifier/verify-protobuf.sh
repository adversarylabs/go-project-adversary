#!/usr/bin/env bash
set -o errexit

make protobuf
git diff --exit-code -- '*.pb.go'
