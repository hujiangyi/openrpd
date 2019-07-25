#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=memory_profiler
PKG_VERSION:=0.52

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/pythonprofilers/memory_profiler.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=0b6e2bf0264bb845c65c8e8238760df8876a570d

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
