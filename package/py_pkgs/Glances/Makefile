include $(TOPDIR)/rules.mk

PKG_NAME:=Glances
PKG_VERSION:=2.7.1
PKG_RELEASE:=1

PKG_SOURCE:=Glances-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/1f/10/ba2025883d595499a7bba5392a548a8fddd934af630a981d7bf8cbd1ec6e/
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/Glances
  CATEGORY:=Python packages
  TITLE:=Glances
  URL:=https://nicolargo.github.io/glances/
  DEPENDS:=+python
  PKGARCH:=all
endef

define Package/Glances/description
  Glances is a module providing an interface for retrieving information on all running processes and system utilization (CPU, memory, disks, network, users) in a portable way by using Python.
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call Build/Compile/PyMod,., \
		install --prefix="/usr" --root="$(PKG_INSTALL_DIR)" \
	)
endef

define Package/Glances/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) $(PKG_INSTALL_DIR)/usr/* $(1)/usr/
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) ./files/glances.conf $(1)/etc
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/glances.init $(1)/etc/init.d/glances
endef

$(eval $(call BuildPackage,Glances))
