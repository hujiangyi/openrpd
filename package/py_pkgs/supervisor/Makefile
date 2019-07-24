#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=supervisor
PKG_VERSION:=3.1.3

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/Supervisor/supervisor
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=f067ed44b726b754d23f97fd1277a23292382f82

include $(INCLUDE_DIR)/package.mk

define Package/supervisor
	CATEGORY:=Python packages
	TITLE:=Python package - $(PKG_NAME)
	URL:=https://pypi.python.org/pypi/supervisor
	DEPENDS:=+python +distribute
	PKGARCH:=all
endef

define Package/supervisor/description
	Just python $(PKG_NAME) package
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call PY_PKG_DEBUG)
	cd $(PKG_BUILD_DIR); \
	python setup.py build
endef

PY_TMP=tmp_py_pkg

define Package/supervisor/install
	$(INSTALL_DIR) $(1)/usr
	$(INSTALL_DIR) $(1)/$(PY_TMP)
	cd $(PKG_BUILD_DIR); \
		python setup.py install --force --root $(1)/$(PY_TMP)
	mv $(1)/$(PY_TMP)/$(STAGING_DIR_HOST)/* $(1)/usr/
	rm -r $(1)/$(PY_TMP)
endef

$(eval $(call BuildPackage,supervisor))
