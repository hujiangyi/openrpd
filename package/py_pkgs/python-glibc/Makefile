#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-glibc
PKG_VERSION:=0.6.1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/zyga/python-glibc.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=1097a1e5d1e243f08a4872fdb0f088c3c019bc12

include $(INCLUDE_DIR)/package.mk

define Package/python-glibc
	CATEGORY:=Python packages
	TITLE:=Python package - python-glibc
	URL:=https://github.com/zyga/python-glibc
	DEPENDS:=+python +distribute
	PKGARCH:=all
endef

define Package/python-glibc/description
	Just python python-glibc package
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call PY_PKG_DEBUG)
	cd $(PKG_BUILD_DIR); \
	python setup.py build
endef

PY_TMP=tmp_py_pkg

define Package/python-glibc/install
	$(INSTALL_DIR) $(1)/usr
	$(INSTALL_DIR) $(1)/$(PY_TMP)
	cd $(PKG_BUILD_DIR); \
		python setup.py install --force --root $(1)/$(PY_TMP)
	mv $(1)/$(PY_TMP)/$(STAGING_DIR_HOST)/* $(1)/usr/
	rm -r $(1)/$(PY_TMP)
endef

$(eval $(call BuildPackage,python-glibc))
