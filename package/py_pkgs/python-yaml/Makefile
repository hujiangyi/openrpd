#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=PyYAML
PKG_VERSION:=3.12

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=http://pyyaml.org/download/pyyaml/

PKG_SOURCE_VERSION:=3.12

include $(INCLUDE_DIR)/package.mk

define Package/yaml
	CATEGORY:=Python packages
	TITLE:=Python package - $(PKG_NAME)
	URL:=http://pyyaml.org/download/pyyaml/
	DEPENDS:=+python +distribute
	PKGARCH:=all
endef

define Package/yaml/description
	Just python $(PKG_NAME) package
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call PY_PKG_DEBUG)
	cd $(PKG_BUILD_DIR); \
	python setup.py build
endef

PY_TMP=tmp_py_pkg

define Package/yaml/install
	$(INSTALL_DIR) $(1)/usr
	$(INSTALL_DIR) $(1)/$(PY_TMP)
	cd $(PKG_BUILD_DIR); \
		python setup.py install --force --root $(1)/$(PY_TMP)
	mv $(1)/$(PY_TMP)/$(STAGING_DIR_HOST)/* $(1)/usr/
	rm -r $(1)/$(PY_TMP)
endef

$(eval $(call BuildPackage,yaml))
