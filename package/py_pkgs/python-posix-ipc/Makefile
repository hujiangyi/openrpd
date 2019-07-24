#
# Copyright (C) 2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-posix-ipc
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE:=posix_ipc-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://semanchuk.com/philip/posix_ipc/
PKG_MD5SUM:=85607a392087715ac3a3c7ded2492d06

PKG_BUILD_DIR:=$(BUILD_DIR)/posix_ipc-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-posix-ipc
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Python Posix IPC
  URL:=https://pypi.python.org/pypi/posix_ipc
  DEPENDS:=+python +librt 
endef

define Package/python-posix-ipc/description
  The Python extension module posix_ipc gives Python access to POSIX
  inter-process semaphores, shared memory and message queues on systems
  that support the POSIX Realtime Extensions a.k.a. POSIX 1003.1b-1993.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-posix-ipc/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	    $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-posix-ipc))
