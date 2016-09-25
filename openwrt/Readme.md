Cross-compiling and packages for openwrt
===

Place Makefile in `packages/network/ipt-netflow` directory in OpenWRT bouldroot.
Run `make menuconfig` and select package in Network/Netflow menu. Configure args partially supported.

Run `make` to build full firmware or `make package/network/ipt-netflow/{clean,prepare,configure,compile,install}` to rebuild packages.

To make git version uncomment two lines in Makefile.

Tested to work on Chaos Calmer and Designated Driver with Atheros AR7xxx/AR9xxx target.
