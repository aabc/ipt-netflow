#!/bin/bash -efu
# SPDX-License-Identifier: GPL-2.0-only
#
# Update default .config for values required to run tests
#

COLOR=11
V() {
	[ -t 1 ] && tput setaf "$COLOR"
	printf '+'
	printf ' %q' "$@"
	printf '\n'
	[ -t 1 ] && tput op
	"$@"
}

for opt; do
	case $opt in
		--kdir=*) KDIR=${opt#*=} ;;
		--checkout=*) BRANCH=${opt#*=} ;&
		--defconfig) DEFCONFIG=defconfig ;;
		--debug) ADD_DEBUG=y ;;
		--force) FORCE=--force ;;
		--prepare) TARGETS="prepare modules_prepare" ;&
		--clean) CLEAN=clean ;;
		--cmd=*) KBUILD_PREPARE_CMD=${opt#*=} ;;
		--build) DO_BUILD=y ;;
		--configure) DO_CONFIGURE=y ;;
		--pick=*) PICKS+=("${opt#*=}") ;;
		--*) echo >&2 "$0: Unknown option $opt"; exit 1 ;;
		gcc-*) OPTS+=(CC=$opt HOSTCC=$opt) ;;
		-no-* | -[fDWO]*) KBUILD_CFLAGS+=("$opt") ;;
		*=*) OPTS+=("${opt%%=*}=${opt#*=}") ;;
		*) echo >&2 "$0: Unknown argument $opt"; exit 1 ;;
	esac
done

# Patch applying command assuming --force checkout.
[ -n "$KBUILD_PREPARE_CMD" ] && [ -n "$TARGETS" ] && FORCE=-f

[ -n "${KDIR-}" ] && V cd "$KDIR"
[ -n "${BRANCH-}" ] && V git switch ${FORCE-} --detach "$BRANCH"
[ -n "${DEFCONFIG-}" ] && V make $DEFCONFIG

V cp -f .config .config-pkt-netflow.bak

if type virtme-configkernel >/dev/null 2>&1; then
  V virtme-configkernel --update
fi

V scripts/config \
  -e CONFIG_VETH \
  -e CONFIG_PACKET \
  -e CONFIG_NETFILTER \
  -e CONFIG_NETFILTER_XTABLES \
  -e NETFILTER_ADVANCED \
  -e CONFIG_IP_NF_FILTER \
  -e CONFIG_IP_NF_IPTABLES \
  -e CONFIG_IP6_NF_FILTER \
  -e CONFIG_NF_CONNTRACK_EVENTS \
  -e CONFIG_VLAN_8021Q \

if [ -n "${ADD_DEBUG-}" ]; then
V scripts/config \
  -e CONFIG_LOCK_DEBUGGING_SUPPORT \
  -e CONFIG_PROVE_LOCKING \
  -e CONFIG_DEBUG_SPINLOCK \
  -e CONFIG_FRAME_POINTER \
  -d CONFIG_RANDOMIZE_BASE \

fi

V make olddefconfig

V scripts/diffconfig .config-pkt-netflow.bak .config || :

[ -n "${CLEAN-}" ] && V make $CLEAN
[ -n "${KBUILD_PREPARE_CMD-}" ] && V eval "$KBUILD_PREPARE_CMD" || :
for commit in "${PICKS[@]}"; do
	V git cherry-pick --no-commit "$commit" || :
done
[ -n "${KBUILD_CFLAGS-}" ] && OPTS+=("KBUILD_CFLAGS=${KBUILD_CFLAGS[*]}")
[ -n "${TARGETS-}" ] && V make $TARGETS "${OPTS[@]}"

echo
V cd "$OLDPWD"
COLOR=14

if [ -n "${DO_CONFIGURE-}" ]; then
	readarray -t confs <<-EOF
	  --disable-snmp-agent
	  --enable-aggregation
	  --enable-natevents
	  --enable-snmp-rules
	  --enable-macaddress
	  --enable-vlan
	  --promisc-mpls
	  --enable-direction
	  --enable-sampler
	  --enable-sampler=hash
	  --enable-promisc --promisc-mpls
	  --enable-physdev
	  --enable-physdev-override
	EOF
	mv -f Makefile Makefile- || :
	V ./configure ${confs[@]}
fi

if [ -n "${DO_BUILD-}" ]; then
	V make "${OPTS[@]}" $CLEAN ipt_NETFLOW.ko
	size ipt_NETFLOW.ko
fi

# export XTABLES_LIBDIR=
