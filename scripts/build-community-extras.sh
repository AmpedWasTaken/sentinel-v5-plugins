#!/bin/sh
set -eu
mkdir -p build-local
for name in httpxray whoiz jwtpeek gitty servectl termfiles authguard jsonfix hashkit uptimez; do
  echo "building $name"
  go build -o "build-local/$name" "./plugins/$name"
done
