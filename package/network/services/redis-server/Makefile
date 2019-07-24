#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=redis-server
PKG_VERSION:=3.0

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/antirez/redis.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=49f2f691cbf62aa77ebeed1edd8b008cac622e5c

include $(INCLUDE_DIR)/package.mk

define Package/redis-server
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Redis server $(PKG_VERSION)
	URL:=http://redis.io/
	DEPENDS:=+libpthread
	PKGARCH:=all
endef

define Package/redis-server/description
	Redis server package
endef

INST_PFX:=$(PKG_BUILD_DIR)/install_pfx
# TOOLCHAIN PATH + CROSSCOMPILATION TARGET PREFIX
TCH_P:=$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)

define Build/Compile
	mkdir -p $(INST_PFX)
	CFLAGS="$(TARGET_CFLAGS)" \
	CC="$(TCH_P)gcc" \
	AR="$(TCH_P)ar" \
	RANLIB="$(TCH_P)ranlib" \
	PREFIX="$(INST_PFX)" \
	$(MAKE) install -C $(PKG_BUILD_DIR) \
	$(TARGET_CONFIGURE_OPTS)
endef

PY_TMP=tmp_py_pkg

define Package/redis-server/install
	$(INSTALL_DIR) $(1)/usr
	cp -r $(INST_PFX)/* $(1)/usr/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/redis.init $(1)/etc/init.d/redis
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) ./files/redis.conf $(1)/etc
endef

$(eval $(call BuildPackage,redis-server))
