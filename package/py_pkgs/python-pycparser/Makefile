#
# Copyright (C) 2015-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pycparser
PKG_VERSION:=2.14
PKG_RELEASE:=3

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/source/p/pycparser
PKG_MD5SUM:=a2bc8d28c923b4fe2b2c3b4b51a4f935

PKG_BUILD_DEPENDS:=python python-setuptools
HOST_BUILD_DEPENDS:=python/host python-setuptools/host python-ply/host

HOST_BUILD_DIR:=$(BUILD_DIR_HOST)/$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Jeffery To <jeffery.to@gmail.com>

include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)
#$(call include_mk, python-host.mk)

define Package/python-pycparser
	SECTION:=lang
	CATEGORY:=Languages
	SUBMENU:=Python
	TITLE:=python-pycparser
	URL:=https://github.com/eliben/pycparser
	DEPENDS:=+python-light +python-ply
endef

define Package/python-pycparser/description
pycparser is a parser for the C language, written in pure Python. It is a
module designed to be easily integrated into applications that need to parse
C source code.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="/usr" --root="$(PKG_INSTALL_DIR)")
endef

define Host/Compile/PyMod
        $(call HostPython, \
                cd $(HOST_BUILD_DIR)/$(strip $(1)); \
                CFLAGS="$(HOST_CFLAGS)" \
                CPPFLAGS="$(HOST_CPPFLAGS)" \
                LDFLAGS="$(HOST_LDFLAGS)" \
                $(3) \
                , \
                ./setup.py $(2) \
        )
endef

define Host/Compile
	$(call Host/Compile/PyMod,,install --prefix="/usr" --root="$(STAGING_DIR_HOST)")
endef

define Host/Install
endef

$(eval $(call HostBuild))

$(eval $(call PyPackage,python-pycparser))
$(eval $(call BuildPackage,python-pycparser))
