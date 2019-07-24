include $(TOPDIR)/rules.mk

PKG_NAME:=tftpy
PKG_VERSION:=0.6.2
PKG_RELEASE:=1

PKG_SOURCE:=tftpy-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/7d/a5/e246b93d0996264f80c54af706bda111b1547cef6def52ecb05183263af7/

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-tftpy
  CATEGORY:=Python packages
  TITLE:=python-tftpy
  URL:=http://code.google.com/p/tftpy/
  DEPENDS:=+python
  PKGARCH:=all
endef

define Package/python-tftpy/description
  Python TFTP Lib
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call Build/Compile/PyMod,., \
		install --prefix="/usr" --root="$(PKG_INSTALL_DIR)" \
	)
endef

define Package/python-tftpy/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,python-tftpy))
