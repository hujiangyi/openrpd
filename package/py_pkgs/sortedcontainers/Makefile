#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sortedcontainers
PKG_VERSION:=1.4.4

PY_PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/sortedcontainers
	CATEGORY:=Python packages
	TITLE:=Python package - sortedcontainers
	URL:=https://github.com/grantjenks/sorted_containers
	DEPENDS:=+python +distribute
	PKGARCH:=all
endef

define Package/sortedcontainers/description
	SortedContainers provides sorted container types
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call PY_PKG_DEBUG)
endef


define Package/sortedcontainers/install
	$(INSTALL_DIR) $(1)/usr
	setlock -N /tmp/lock-pip-openrpd pip install \
	   --proxy "$(PIP_PROXY)" \
	   --install-option="--install-base=./" \
	   --install-option="--install-purelib=./lib/python2.7/site-packages" \
	   --install-option="--install-platlib=./lib" \
	   --install-option="--install-headers=./include" \
	   --install-option="--install-scripts=./bin" \
	   --install-option="--install-data=./data" \
	   --root $(1)/usr \
	   --force-reinstall -U -I \
	   $(PKG_NAME)==$(PKG_VERSION)
endef

$(eval $(call BuildPackage,sortedcontainers))
