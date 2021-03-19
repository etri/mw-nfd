#!/usr/bin/env bash
set -ex

git submodule sync
git submodule update --init

# Build in debug mode
./waf --color=yes configure --debug
./waf --color=yes build -j$WAF_JOBS

# Cleanup
./waf --color=yes distclean

# Build in release mode
./waf --color=yes configure
./waf --color=yes build -j$WAF_JOBS

# Install
sudo_preserve_env PATH -- ./waf --color=yes install
