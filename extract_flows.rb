#!/usr/bin/ruby -Ku

require 'pp'
require 'json'

## hash a d dev:i,o proto src:ip,port dst:ip,port nexthop tos,tcpflags,options,tcpoptions packets bytes ts:first,last
#1 0f828 0 4 -1,1 1 127.0.0.1,0 127.0.0.1,771 0.0.0.0 c0,0,0,0 1 498 1870,1870

def ifc(port)
  (port == "65535")? 'N' : port
end

def print_flow(f)
  print f["cflow.direction"] ? f["cflow.direction"] : "N"
  print ' ' + ifc(f["cflow.inputint"])
  print ',' + ifc(f["cflow.outputint"])
  print ' ' + f["cflow.protocol"]
  print ' ' + f["cflow.srcaddr"]
  print ',' + f["cflow.srcport"] if f["cflow.srcport"]
  print ',' + f["cflow.icmp_type_code_ipv4"].to_i(16).to_s(16) if f["cflow.icmp_type_code_ipv4"]
  print ' ' + f["cflow.dstaddr"]
  print ',' + f["cflow.dstport"] if f["cflow.dstport"]
  print ' ' + f["cflow.nexthop"]
  print ' ' + f["cflow.tos"].to_i(16).to_s(16)
  print ',' + f["cflow.tcpflags"].to_i(16).to_s(16) if f["cflow.tcpflags"]
  print ' ' + f["cflow.packets"]
  print ' ' + f["cflow.octets"]
  puts
end

def seek_flow(k, v)
  if k =~ /^(pdu|Flow) / and v['cflow.srcaddr']
    print_flow v
  elsif v.kind_of? Hash
    v.each do |k,v|
      seek_flow(k, v)
    end
  end
end

def json_extract_flows(jtext)
  jtext.each do |jpkt|
    jpkt["_source"]["layers"]["cflow"].each do |k,v|
      seek_flow k, v
    end
  end
end

ARGV.each do |fn|
  json_extract_flows JSON.parse IO.read fn
end
