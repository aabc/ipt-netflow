#!/bin/bash -efu
# SPDX-License-Identifier: GPL-2.0-only
#
# Update default .config for values required to run tests
#

set -x
cp -f .config .config-pkt-netflow.bak

if type virtme-configkernel >/dev/null 2>&1; then
  virtme-configkernel --update
fi

scripts/config \
  -e CONFIG_VETH \
  -e CONFIG_PACKET \

make olddefconfig

scripts/diffconfig .config-pkt-netflow.bak .config
