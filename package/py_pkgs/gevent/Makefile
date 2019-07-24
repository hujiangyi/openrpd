#
# Copyright (C) 2015 Cisco
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gevent
PKG_VERSION:=1.0.2

PY_PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/gevent
	CATEGORY:=Python packages
	TITLE:=Python package - $(PKG_NAME)
	URL:=https://pypi.python.org/pypi/gevent/1.0.2
	DEPENDS:=+python +distribute +librt +greenlet +python-openssl
	PKGARCH:=all
endef

define Package/gevent/description
	Just python $(PKG_NAME) package
endef

include $(INCLUDE_DIR)/py_pkgs.mk

# download PKG
# unpack the PKG
# execute 001-configure-patch.sh script
#   which generates patch according target architecture
# copy generated patch and use it to patch setup.py file
# execute build of the PKG
define Build/Compile
	    $(call PY_PKG_DEBUG)
	    setlock -N /tmp/lock-pip-openrpd pip install --download $(DL_DIR)/ $(PKG_NAME)==$(PKG_VERSION); \
		cd $(BUILD_DIR); \
	    tar -zxvf $(DL_DIR)/$(PY_PKG_SOURCE);
		cd py_patches; \
		./001-configure-patch.sh \
			$(REAL_GNU_TARGET_NAME) > ./001-configure.patch; \
		cp ./* $(PKG_BUILD_DIR)/; \
		rm ./001-configure.patch; \
	    cd $(PKG_BUILD_DIR)/; \
	    patch setup.py 001-configure.patch; \
	    python setup.py build
endef

PY_TMP=tmp_py_pkg

define Package/gevent/install
	    $(INSTALL_DIR) $(1)/usr
	    $(INSTALL_DIR) $(1)/$(PY_TMP)
	    cd $(PKG_BUILD_DIR); \
			python setup.py install --force --root $(1)/$(PY_TMP)
	    mv $(1)/$(PY_TMP)/$(STAGING_DIR_HOST)/* $(1)/usr/
	    rm -r $(1)/$(PY_TMP)
endef

$(eval $(call BuildPackage,gevent))
