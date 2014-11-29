#!/bin/bash
# This script determines actual module version.

# From the source.
MVERSION=`sed -n 's/^#define.*IPT_NETFLOW_VERSION.*"\(.*\)".*/\1/p' ipt_NETFLOW.c`

# Git overrides version from the source.
if [ -d .git ] && type git >/dev/null 2>&1; then \
  GVERSION=`git describe --dirty`
  MVERSION=${GVERSION#v}
else
  GVERSION=
fi

if [ "$1" = --define ]; then
  if [ "$GVERSION" ]; then
    echo "#define GITVERSION \"$MVERSION\""
  else
    echo "/* kernel doesn't like empty files */"
  fi
else
  echo $MVERSION
fi
