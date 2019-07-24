#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=memory_profiler
PKG_VERSION:=0.31

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/fabianp/memory_profiler.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=3fa7aafb0ac9c05c83fd9726ba1ffd6a7c27ec82

include $(INCLUDE_DIR)/package.mk

define Package/memory_profiler
	CATEGORY:=Python packages
	TITLE:=Python package - memory profiler
	URL:=https://pypi.python.org/pypi/memory_profiler
	DEPENDS:=+python +distribute
	PKGARCH:=all
endef

define Package/memory_profiler/description
	A module for monitoring memory usage of a python program
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call PY_PKG_DEBUG)
	cd $(PKG_BUILD_DIR); \
	python setup.py build
endef

PY_TMP=tmp_py_pkg

define Package/memory_profiler/install
	$(INSTALL_DIR) $(1)/usr
	$(INSTALL_DIR) $(1)/$(PY_TMP)
	cd $(PKG_BUILD_DIR); \
		python setup.py install --force --root $(1)/$(PY_TMP)
	mv $(1)/$(PY_TMP)/$(STAGING_DIR_HOST)/* $(1)/usr/
	rm -r $(1)/$(PY_TMP)
endef

$(eval $(call BuildPackage,memory_profiler))
