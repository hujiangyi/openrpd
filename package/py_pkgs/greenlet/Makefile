#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=greenlet
PKG_VERSION:=0.4.7

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/python-greenlet/greenlet.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=641794f49a15007e0a9981cbe9423f6a01143e97

include $(INCLUDE_DIR)/package.mk

define Package/greenlet
	CATEGORY:=Python packages
	TITLE:=Python package - $(PKG_NAME)
	URL:=https://pypi.python.org/pypi/greenlet
	DEPENDS:=+python +distribute
	PKGARCH:=all
endef

define Package/greenlet/description
	Just python greenlet package
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call PY_PKG_DEBUG)
	cd $(PKG_BUILD_DIR); \
	python setup.py build
endef

PY_TMP=tmp_py_pkg

define Package/greenlet/install
	$(INSTALL_DIR) $(1)/usr
	$(INSTALL_DIR) $(1)/$(PY_TMP)
	cd $(PKG_BUILD_DIR); \
		python setup.py install --force --root $(1)/$(PY_TMP)
	mv $(1)/$(PY_TMP)/$(STAGING_DIR_HOST)/* $(1)/usr/
	rm -r $(1)/$(PY_TMP)
endef

$(eval $(call BuildPackage,greenlet))
