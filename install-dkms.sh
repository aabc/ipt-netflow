#!/bin/bash
# This script cleanly re-install module into DKMS tree.

PATH=$PATH:/bin:/usr/bin:/usr/sbin:/sbin:/usr/local/sbin

if [ "$1" = --uninstall ]; then
  echo "Uninstalling from DKMS..."
elif [ "$1" = --install ]; then
  echo "Installing into DKMS..."
else
  exit 1
fi

if ! which dkms >/dev/null 2>&1; then
  echo "! You don't have DKMS accessible in system."
  exit 1
fi

if [ ! -e dkms.conf ]; then
  echo "! You don't have DKMS configured for this module."
  exit 1
fi

MVERSION=`./version.sh`

contains() { for e in "${@:2}"; do [[ "$e" = "$1" ]] && return 0; done; return 1; }

D=() # to be list of installed versions
OLDIFS="$IFS"
IFS=$'\n' A=(`dkms status | grep ^ipt-netflow`)
IFS="$OLDIFS"

for i in "${A[@]}"; do
  z=($i)
  v=${z[1]}
  v=${v%,}
  v=${v%:}
  if ! contains "$v" "${D[@]}"; then
    D+=($v)
  fi
done

if [ ${#D[@]} -eq 1 ]; then
  # single version is already installed.
  if [ $D = "$MVERSION" ]; then
    echo "! You have same version of module already installed into DKMS."
  else
    echo "! You have different version of module installed into DKMS."
  fi
  if [ ! -d /usr/src/ipt-netflow-$D ]; then
    echo "! Can not find DKMS dir for it, that's plain weird."
  elif [ -e /usr/src/ipt-netflow-$D/.automatic ]; then
    echo "! That version was automatically installed by this script,"
    echo "! thus, is safe to remove. No worries."
  else
    echo "! That version was manually installed by you."
  fi

  nodepmod=
  if grep -qs no-depmod `which dkms`; then
    nodepmod=--no-depmod
  fi
  echo "! Removing from dkms..."
  dkms $nodepmod remove ipt-netflow/$D --all

  if [ -d "/usr/src/ipt-netflow-$D" ]; then
    echo "! Removing source tree from /usr/src/ipt-netflow-$D"
    rm -rf "/usr/src/ipt-netflow-$D"
  fi

elif [ ${#D[@]} -gt 1 ]; then
  # multiple versions are installed.
  echo "! You have multiple versions of module already installed in DKMS."
  echo "! Please remove them manually to avoid conflict."
  echo "! 'dkms status' output:"
  dkms status
  echo "! Suggested commands to remove them:"
  for i in ${D[@]}; do
    echo "!   root# dkms remove ipt-netflow/$i --all"
  done
  exit 1
fi

if [ "$1" = --uninstall ]; then
  exit 0
fi

if [ "$PWD" = "/usr/src/ipt-netflow-$MVERSION" ]; then
  echo "! You are already in DKMS dir."
  dkms add -m ipt-netflow -v $MVERSION
  exit $?
fi

echo "! Installing $MVERSION into DKMS..."
rm -rf /usr/src/ipt-netflow-$MVERSION

mkdir -p /usr/src/ipt-netflow-$MVERSION
cp -p *.[ch] Make* READ* conf* irq* *.sh *.conf /usr/src/ipt-netflow-$MVERSION/
if [ -d .git ]; then
  cp -pr .git /usr/src/ipt-netflow-$MVERSION/
fi
touch /usr/src/ipt-netflow-$MVERSION/.automatic

dkms add -m ipt-netflow -v $MVERSION
exit $?

