include $(TOPDIR)/rules.mk

PKG_NAME:=gnureadline
PKG_VERSION:=6.3.3
PKG_RELEASE:=1

PKG_SOURCE:=gnureadline-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/3a/ee/2c3f568b0a74974791ac590ec742ef6133e2fbd287a074ba72a53fa5e97c/

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-gnureadline
  CATEGORY:=Python packages
  TITLE:=python-readline
  URL:=http://code.google.com/p/gnureadline/
  DEPENDS:=+python +libreadline
  PKGARCH:=all
endef

define Package/python-gnureadline/description
  readline is a module providing an interface for retrieving information on all running processes and system utilization (CPU, memory, disks, network, users) in a portable way by using Python.
endef

include $(INCLUDE_DIR)/py_pkgs.mk

define Build/Compile
	@echo "Appy set_customer patch for rpdCli framework,only support readline-6.3"
	ls $(PKG_BUILD_DIR)/Modules/2.x/
	patch -p0 $(PKG_BUILD_DIR)/Modules/2.x/readline.c < 160-readline-add-customer.patch || @echo "already patched"
	mkdir $(PKG_BUILD_DIR)/readline/ 
	cp $(PKG_BUILD_DIR)/../readline-6.3/lib* $(PKG_BUILD_DIR)/readline/
	@echo "Apply set_customer patch for rpdCli framework ok"
	$(call Build/Compile/PyMod,., \
		install --prefix="/usr" --root="$(PKG_INSTALL_DIR)" \
	)
endef

define Package/python-gnureadline/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,python-gnureadline))
