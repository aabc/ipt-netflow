include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ipt-netflow
PKG_RELEASE:=2

PKG_SOURCE_URL:=https://github.com/aabc/$(PKG_NAME).git
PKG_VERSION:=2.5.1
PKG_SOURCE_VERSION:=v$(PKG_VERSION)

#TO BUILD development version uncomment 2 rows below and remove patches
#PKG_VERSION:=$(shell (git ls-remote $(PKG_SOURCE_URL) | grep refs/heads/master | cut -f 1 | head -c 7))
#PKG_SOURCE_VERSION:=HEAD

PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_BUILD_DIR := $(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_DEPENDS:=iptables

include $(INCLUDE_DIR)/package.mk


define KernelPackage/ipt-netflow
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Netflow
	TITLE:=Netflow iptables module for Linux kernel
	URL:=http://ipt-netflow.sourceforge.net/
	FILES:=$(PKG_BUILD_DIR)/ipt_NETFLOW.ko
	DEPENDS:=+iptables +iptables-mod-netflow
endef


define Package/iptables-mod-netflow
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Netflow
	TITLE:=Netflow iptables module for Linux kernel
	URL:=http://ipt-netflow.sourceforge.net/
	#DEPENDS:=+kmod-ipt-netflow
	DEPENDS:=+iptables
endef

CONFIGURE_ARGS:= \
	--kdir="$(LINUX_DIR)" 

define Package/iptables-mod-netflow/config
	menu "Configuration"
		depends on PACKAGE_iptables-mod-netflow
	config PACKAGE_iptables-mod-netflow_natevents
		bool "enables natevents support"
		default n
	config PACKAGE_iptables-mod-netflow_snmp-rules
		bool "enables SNMP-index conversion rules"
		default n
	config PACKAGE_iptables-mod-netflow_macaddress
		bool "enables MAC address for v9/IPFIX"
		default n
	config PACKAGE_iptables-mod-netflow_vlan
		bool "enables VLAN Ids for v9/IPFIX"
		default n
	config PACKAGE_iptables-mod-netflow_direction
		bool "enables flowDirection(61) Element"
		default n
	config PACKAGE_iptables-mod-netflow_sampler
		bool "enables Flow Sampling"
		default n
	config PACKAGE_iptables-mod-netflow_aggregation
		bool "enables aggregation rules"
		default n
	config PACKAGE_iptables-mod-netflow_promisc
		bool "enables promisc hack mode"
		default n
	config PACKAGE_iptables-mod-netflow_promisc-mpls
		bool "decapsulate MPLS in promisc mode"
		default n
	config PACKAGE_iptables-mod-netflow_physdev
		bool "enables physdev reporting"
		default n
	config PACKAGE_iptables-mod-netflow_physdev-override
		bool "to override interfaces"
		default n
	config PACKAGE_iptables-mod-netflow_snmp-agent
		bool "disables net-snmp agent"
		default y
	config PACKAGE_iptables-mod-netflow_dkms
		bool "disables DKMS support completely"
		default y
	config PACKAGE_iptables-mod-netflow_dkms-install
		bool "no DKMS install but still create dkms.conf"
		default n
	endmenu
endef

CONFIGURE_ARGS += \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_natevents),--enable-natevents) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_snmp-rules),--enable-snmp-rules) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_macaddress),--enable-macaddress) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_vlan),--enable-vlan) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_direction),--enable-direction) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_sampler),--enable-sampler) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_aggregation),--enable-aggregation) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_promisc),--enable-promisc) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_promisc-mpls),--promisc-mpls) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_physdev),--enable-physdev) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_physdev-override),--enable-physdev-override) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_snmp-agent),--disable-snmp-agent) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_dkms),--disable-dkms) \
	$(if $(CONFIG_PACKAGE_iptables-mod-netflow_dkms-install),--disable-dkms-install) 

#TODO: --enable-sampler=hash --promisc-mpls=N


$(eval $(call KernelPackage,ipt-netflow))

$(eval $(call Package,kmod-ipt-netflow))

define Package/iptables-mod-netflow/install
	$(MAKE) -C $(PKG_BUILD_DIR) DESTDIR=$(1) linstall
	#TODO: snmp install, dkms install
endef

$(eval $(call BuildPackage,iptables-mod-netflow))
