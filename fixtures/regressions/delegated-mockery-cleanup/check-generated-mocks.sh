#!/usr/bin/env bash
set -o errexit

make clean-generated-mocks mocksgen
git status --porcelain -- pkg
