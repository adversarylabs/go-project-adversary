#!/bin/sh
set -eu

version="$(jq -r '.version' package.json)"
printf '%s\n' "$version"
