#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=czmq
PKG_VERSION:=3.0.2

PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/zeromq/$(PKG_NAME)/archive/
PKG_LICENSE:=MPL-2.0

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/czmq
    TITLE:=High-level C Binding for ZeroMQ
    SECTION:=libs
    CATEGORY:=Libraries
    URL:=http://czmq.zeromq.org/
    DEPENDS:=+libzmq
endef

define Package/czmq/description
	High-level C Binding for ZeroMQ
endef

TARGET_CFLAGS = -std=c99

define Build/Configure
	cd $(PKG_BUILD_DIR); \
		./autogen.sh
	$(call Build/Configure/Default)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/* $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/* $(1)/usr/lib/pkgconfig/
	$(INSTALL_DIR) $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(1)/usr/include/
endef

define Package/czmq/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libczmq.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,czmq))
