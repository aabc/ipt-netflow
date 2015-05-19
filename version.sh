#!/bin/sh
# This script determines actual module version.

PATH=$PATH:/usr/local/bin:/usr/bin:/bin

# Base version from the source.
MVERSION=`sed -n 's/^#define.*IPT_NETFLOW_VERSION.*"\(.*\)".*/\1/p' ipt_NETFLOW.c`

# GITVERSION overrides base version.
if [ -e version.h ] && grep -q GITVERSION version.h; then
  MVERSION=`sed -n 's/#define GITVERSION "\(.*\)".*/\1/p' version.h`
fi

# git describe overrides version from the source.
if [ -d .git ] && which git >/dev/null 2>&1; then \
  GVERSION=`git describe --dirty 2>/dev/null`
  if [ "$GVERSION" ]; then
    MVERSION=${GVERSION#v}
  fi
else
  GVERSION=
fi

if [ "$1" = --define ]; then
  # called from Makefile to create version.h
  # which should contain GITVERSION or be empty.
  if [ "$GVERSION" ]; then
    echo "#define GITVERSION \"$MVERSION\""
  else
    echo "/* placeholder, because kernel doesn't like empty files */"
  fi
else
  # normal run
  echo $MVERSION
fi
