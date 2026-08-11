#!/usr/bin/env bash
set -o errexit

go install github.com/vektra/mockery/v2@v2.53.4
mockery --version
git status --short
