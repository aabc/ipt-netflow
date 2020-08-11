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
  -e CONFIG_NETFILTER \
  -e CONFIG_NETFILTER_XTABLES \
  -e NETFILTER_ADVANCED \
  -e CONFIG_IP_NF_FILTER \
  -e CONFIG_IP_NF_IPTABLES \
  -e CONFIG_IP6_NF_FILTER \

if [ "${1-}" = debug ]; then
scripts/config \
  -e CONFIG_LOCK_DEBUGGING_SUPPORT \
  -e CONFIG_PROVE_LOCKING \
  -e CONFIG_DEBUG_SPINLOCK \
  -e CONFIG_FRAME_POINTER \
  -d CONFIG_RANDOMIZE_BASE \

fi

make olddefconfig

scripts/diffconfig .config-pkt-netflow.bak .config

# export XTABLES_LIBDIR=
