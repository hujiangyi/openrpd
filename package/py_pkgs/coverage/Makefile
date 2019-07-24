#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=coverage
PKG_VERSION:=3.7.1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/nedbat/coveragepy.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=8da39d5389c602bb838363563bd2e31ecbb53754

include $(INCLUDE_DIR)/package.mk

define Package/coverage
	CATEGORY:=Python packages
	TITLE:=Python package - coverage
	URL:=https://pypi.python.org/pypi/coverage/3.7.1
	DEPENDS:=+python +distribute
	PKGARCH:=all
endef

define Package/coverage/description
	Just python coverage package
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call PY_PKG_DEBUG)
	cd $(PKG_BUILD_DIR); \
	python setup.py build
endef

PY_TMP=tmp_py_pkg

define Package/coverage/install
	$(INSTALL_DIR) $(1)/usr
	$(INSTALL_DIR) $(1)/$(PY_TMP)
	cd $(PKG_BUILD_DIR); \
		python setup.py install --force --root $(1)/$(PY_TMP)
	mv $(1)/$(PY_TMP)/$(STAGING_DIR_HOST)/* $(1)/usr/
	rm -r $(1)/$(PY_TMP)
endef

$(eval $(call BuildPackage,coverage))
