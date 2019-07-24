#
# Copyright (C) 2006-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=rsyslog
PKG_VERSION:=8.21.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.rsyslog.com/files/download/rsyslog/

PKG_MAINTAINER:=Dov Murik <dmurik@us.ibm.com>
PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=COPYING

PKG_INSTALL:=1
PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/rsyslog
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Enhanced system logging and kernel message trapping daemons
  URL:=http://www.rsyslog.com/
  DEPENDS:=+libestr +libfastjson +libuuid +zlib +libpthread +librt
endef

define Package/rsyslog/conffiles
/etc/rsyslog.conf
endef

CONFIGURE_ARGS+= \
	--disable-libgcrypt \
	--enable-omuxsock \
	--enable-omprog \
	--disable-liblogging-stdlog

TARGET_CFLAGS += \
	-std=c99

define Package/rsyslog/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/rsyslogd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/lib/rsyslog
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/rsyslog/* $(1)/usr/lib/rsyslog/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) ./files/rsyslog.conf $(1)/etc
	$(CP) ./files/log_rotate.sh $(1)/usr/sbin/
	$(CP) ./files/log_rotate_archive.sh $(1)/usr/sbin/
	$(CP) ./files/log_rotate_clean.sh $(1)/usr/sbin/
	$(CP) ./files/log_rotate_before_reboot.sh $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/crontabs
	$(INSTALL_BIN) ./files/rsyslog.init $(1)/etc/init.d/rsyslog
	$(INSTALL_BIN) ./files/root $(1)/etc/crontabs
endef

$(eval $(call BuildPackage,rsyslog))
