#!/bin/bash
# virtme-run --kdir=$K --mem=1G --qemu-opts -netdev user,id=n1 -device e1000,netdev=n1

set -eu
cd $(dirname $0)

   RED=$'\e[1;31m'
 GREEN=$'\e[1;32m'
YELLOW=$'\e[1;33m'
  BLUE=$'\e[1;34m'
  CYAN=$'\e[1;36m'
  NORM=$'\e[m'

if [ "${1-}" = restart ]; then
  rmmod pkt_netflow || :
  ip link del ve0 || :
fi
set -x
if ! ip link show ve0 2>/dev/null; then
  ip link add ve0 type veth peer name ve1
  ifconfig ve0 10.0.0.1/16 up
  ifconfig ve1 10.0.0.2/16 up
fi

rmmod pkt_netflow >/dev/null 2>&1 || :

test_flow() {
  local HEAD='^\d+ \S+ '
  local TAIL=' \d+,\d+$'
  local MATCH=$1; shift
  if ! grep -P -q "$HEAD$MATCH$TAIL" /tmp/pkt_flows; then
    echo $RED"ERROR no $* flow detected"$NORM
    echo "Expected: $MATCH"
    return 1
  else
    echo $GREEN"OK $* (active)"$NORM
  fi
}

test_cflow() {
  cflows+=1
  local MATCH=$1; shift
  if ! grep -P -q "^$MATCH\$" /tmp/pkt_cflows; then
    echo $RED"ERROR no $* cflow detected"$NORM
    echo "Expected: $MATCH"
    return 1
  else
    echo $GREEN"OK $* (cflow)"$NORM
  fi
}

set +x
# Test internal accounting

test_ping() {
  local PROTO=$1
  local PKT=$2 # packets
  local PSZ=$3 # payload size

  echo "Test ping $PKT packets of $PSZ+28 bytes"
  echo

  # Will catch some packets
  rm -f /tmp/pkt_flows.pkt
  tcpdump -U -s56535 -np -i lo -w /tmp/pkt_flows.pkt udp and port 2055 &
  TCPDUMP=$!
  sleep 0.1

  # On the fresh module run
  insmod ./pkt_netflow.ko protocol=$PROTO debug=3

  # Generate test flows accorgingly
  ping -f -c$PKT -s$PSZ -I 10.0.0.1 10.0.0.2

  # Verify active flows
  cat /proc/net/stat/pkt_netflow_flows > /tmp/pkt_flows
  echo -n $BLUE
  cat /tmp/pkt_flows
  echo -n $NORM

  if ! grep -q '# hash' /tmp/pkt_flows; then
    echo $RED"ERROR no header in pkt_netflow_flows"$NORM
    return 1
  else
    echo $GREEN"OK header present"$NORM
  fi

  # What flows stat should be
  SZ=$((PKT * (PSZ + 28)))

  test_flow "0 4 -1,1 1 10.0.0.1,0 10.0.0.2,2048 10.0.0.2 0,0,0,0 $PKT $SZ" ping egress
  test_flow "0 0 1,1 1 10.0.0.1,0 10.0.0.2,2048 10.0.0.2 0,0,0,0 $PKT $SZ"  ping ingress
  test_flow "0 4 -1,1 1 10.0.0.2,0 10.0.0.1,0 10.0.0.1 0,0,0,0 $PKT $SZ"    reply egress
  test_flow "0 0 1,1 1 10.0.0.2,0 10.0.0.1,0 10.0.0.1 0,0,0,0 $PKT $SZ"     reply ingress
  if [ `wc -l < /tmp/pkt_flows` != 5 ]; then
    echo $RED"ERROR wrong number of flows seen"$NORM
    return 1
  else
    echo $GREEN"OK no extra flows seen"$NORM
  fi

  # Flush and stop packet recording
  sysctl net.netflow.flush=1
  sleep 1
  kill -INT $TCPDUMP
  wait $TCPDUMP
  rmmod pkt_netflow

  # Verify exported flows
  tcpdump -nr /tmp/pkt_flows.pkt
  tshark -nr /tmp/pkt_flows.pkt -T json > /tmp/pkt_flows.json
  ls -l /tmp/pkt_flows.pkt /tmp/pkt_flows.json

  ./extract_flows.rb /tmp/pkt_flows.json > /tmp/pkt_cflows
  if [ ! -s /tmp/pkt_cflows ]; then
    echo $RED"ERROR now cflow data extracted"$NORM
    return 1
  fi
  echo -n $BLUE
  sort /tmp/pkt_cflows
  echo -n $NORM

  declare -i cflows=0
  # Same flows as (active flows) above
  test_cflow "(1|N) N,1 1 10.0.0.1,(80)?0 10.0.0.2(,2048)? 10.0.0.2 0(,0)? $PKT $SZ" ping egress
  test_cflow "(0|N) 1,1 1 10.0.0.1,(80)?0 10.0.0.2(,2048)? 10.0.0.2 0(,0)? $PKT $SZ" ping ingress
  test_cflow "(1|N) N,1 1 10.0.0.2,0 10.0.0.1(,0)? 10.0.0.1 0(,0)? $PKT $SZ"   reply egress
  test_cflow "(0|N) 1,1 1 10.0.0.2,0 10.0.0.1(,0)? 10.0.0.1 0(,0)? $PKT $SZ"   reply ingress

  # NetFlow v5 does not have metadata packets sent before we stop measuring
  if [ $PROTO != 5 ]; then
    # Netflow traffic and connection refused
    test_cflow '1 N,1 17 127.0.0.1,\d+ 127.0.0.1,2055 0.0.0.0 0,0 \d+ \d+' netflow egress
    test_cflow '0 1,1 17 127.0.0.1,\d+ 127.0.0.1,2055 0.0.0.0 0,0 \d+ \d+' netflow ingress
    test_cflow '1 N,1 1 127.0.0.1,(303|0) 127.0.0.1(,771)? 0.0.0.0 c0 \d+ \d+' icmp-refused egress
    test_cflow '0 1,1 1 127.0.0.1,(303|0) 127.0.0.1(,771)? 0.0.0.0 c0 \d+ \d+' icmp-refused ingress
  fi
  
  if [ `wc -l < /tmp/pkt_cflows` != $cflows ]; then
    echo $RED"ERROR wrong number of flows exported"$NORM
    return 1
  else
    echo $GREEN"OK no extra flows exported"$NORM
  fi
}

for proto in 5 9 10; do
  echo
  echo "Test procotol=$proto"
  echo
  test_ping $proto  1   54
  test_ping $proto  1 1000
  test_ping $proto  2   55
  test_ping $proto  9   56
  test_ping $proto 99   99
done

