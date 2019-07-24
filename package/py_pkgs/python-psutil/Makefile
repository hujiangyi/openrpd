include $(TOPDIR)/rules.mk

PKG_NAME:=psutil
PKG_VERSION:=4.3.0
PKG_RELEASE:=1

PKG_SOURCE:=psutil-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/22/a8/6ab3f0b3b74a36104785808ec874d24203c6a511ffd2732dd215cf32d689/

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-psutil
  CATEGORY:=Python packages
  TITLE:=python-psutil
  URL:=http://code.google.com/p/psutil/
  DEPENDS:=+python
  PKGARCH:=all
endef

define Package/python-psutil/description
  psutil is a module providing an interface for retrieving information on all running processes and system utilization (CPU, memory, disks, network, users) in a portable way by using Python.
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	$(call Build/Compile/PyMod,., \
		install --prefix="/usr" --root="$(PKG_INSTALL_DIR)" \
	)
endef

define Package/python-psutil/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,python-psutil))
