#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libzmq
PKG_VERSION:=a9bad3bc13887c07759318751738d5a2d14ee9d0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/zeromq/libzmq.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_VERSION)

PKG_LICENSE:=LGPL-3.0
PKG_INSTALL:=1
PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/libzmq
	TITLE:=Native (core) API of Zeromq project.
	SECTION:=libs
	CATEGORY:=Libraries
	URL:=https://github.com/zeromq/libzmq.git
	DEPENDS:=+libstdcpp +libpthread +librt
endef

define Package/libzmq/description
 The ZeroMQ is a high-performance asynchronous messaging library
endef

CONFIGURE_ARGS+= --without-libsodium \
				 --without-documentation \
				 --enable-SO_KEEPALIVE \
				 --enable-TCP_KEEPALIVE \
				 --enable-TCP_KEEPCNT \
				 --enable-TCP_KEEPIDLE \
				 --enable-TCP_KEEPINTVL

define Build/Configure
	cd $(PKG_BUILD_DIR); \
		./autogen.sh
	$(call Build/Configure/Default)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libzmq.so* $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/* $(1)/usr/lib/pkgconfig/
endef

define Package/libzmq/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libzmq.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libzmq))
