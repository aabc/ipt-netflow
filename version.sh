#!/bin/sh
# This script determines actual module version.

PATH=$PATH:/usr/local/bin:/usr/bin:/bin

# Base version from the source.
MVERSION=`sed -n 's/^#define.*IPT_NETFLOW_VERSION.*"\(.*\)".*/\1/p' ipt_NETFLOW.c`

# GITVERSION overrides base version.
if [ -e version.h ]; then
  GITVERSION=`sed -n 's/#define GITVERSION "\(.*\)".*/\1/p' version.h`
fi
if [ "$GITVERSION" != "" ]; then
  MVERSION="$GITVERSION"
fi

# git describe overrides version from the source.
if [ -d .git ] && which git >/dev/null 2>&1; then \
  GVERSION=`git describe --dirty`
  GITDESCVERSION=${GVERSION#v}
else
  GVERSION=
fi
if [ "$GITDESCVERSION" != "" ]; then
  MVERSION="$GITDESCVERSION"
fi

if [ "$1" = --define ]; then
  # output version.h which is GITVERSION or empty.
  if [ "$GVERSION" ]; then
    echo "#define GITVERSION \"$MVERSION\""
  else
    echo "/* kernel doesn't like empty files */"
  fi
else
  echo $MVERSION
fi
