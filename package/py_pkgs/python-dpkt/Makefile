#
# Copyright (C) 2007-2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-dpkt
PKG_VERSION:=1.8.6.2
PKG_RELEASE:=1

PKG_SOURCE:=dpkt-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/source/d/dpkt
PKG_MD5SUM:=ada8a7477f67ffa0cf4042e6138a6fed

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DIR:=$(BUILD_DIR)/dpkt-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-dpkt
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Python DPKT
  URL:=https://dpkt.readthedocs.org
  DEPENDS:=+python +librt
endef

define Package/python-dpkt/description
  dpkt is a python module for fast, simple packet creation / parsing, with
  definitions for the basic TCP/IP protocols
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-dpkt/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	    $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-dpkt))