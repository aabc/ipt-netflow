#!/bin/bash

set -e

if [ "$1" = "" ]; then
  echo Maintainer only tool.
  exit 1
elif [ "$1" = all ]; then
  exec bash $0 linux-2.6.18 centos5 linux-3.11.2 centos6 linux-3.4.66 linux-3.9.11 centos7 linux-3.14 linux-3.16
  exit 1
fi

cfg=()
echo -n Testing for:
for k in "$@"; do
  if [ ! -d /usr/src/$k ]; then continue; fi
  echo -n " $k"
  cfg+=("./configure --kdir=/usr/src/$k")
done
echo

readarray -t opts <<EOF

  --enable-natevents    
  --enable-connmark     
  --enable-snmp-rules   
  --enable-macaddress   
  --enable-vlan         
  --enable-direction    
  --disable-aggregation 
EOF

colorecho() {
  echo -e "\033[1;32m$@\033[m"
}
for i in "${cfg[@]}"; do
  for j in "${opts[@]}"; do
    echo
    colorecho == $i $j
    echo
    $i $j -Werror
    make
  done
done

