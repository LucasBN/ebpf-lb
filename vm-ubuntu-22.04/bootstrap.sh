#!/bin/bash

set -e

sudo apt-get update -y
sudo apt-get install -y python3 unzip net-tools \
    arping bridge-utils make meson gcc g++ python3-pyelftools \
    pkg-config libconfig-dev libnuma-dev libelf-dev clang gcc-multilib
