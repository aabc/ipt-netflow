include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ipt-netflow
PKG_VERSION:=2.2
PKG_RELEASE:=1
PKG_MD5SUM:=5952f05d6a067400d0225b7524cde590

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tgz
PKG_SOURCE_URL:=@SF/ipt-netflow

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
	DEPENDS:=+iptables
endef

define Package/iptables-mod-netflow
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Netflow
	TITLE:=Netflow iptables module for Linux kernel
	URL:=http://ipt-netflow.sourceforge.net/
	DEPENDS:=+kmod-ipt-netflow libc
endef

CONFIGURE_ARGS:= \
	--kdir="$(LINUX_DIR)" \
	--ipt-ver=1.4.21 \
	--disable-dkms \
	--disable-snmp-agent

$(eval $(call KernelPackage,ipt-netflow))

$(eval $(call Package,kmod-ipt-netflow))

define Package/iptables-mod-netflow/install
	$(MAKE) -C $(PKG_BUILD_DIR) DESTDIR=$(1) linstall
endef

$(eval $(call BuildPackage,iptables-mod-netflow))
