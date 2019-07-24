#
#
# Copyright (c) 2016 Cisco and/or its affiliates, and 
#                    Cable Television Laboratories, Inc. ("CableLabs")
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=core-emulator
PKG_VERSION:=0

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/core-emulator
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=IP Addresses and Names
	TITLE:=core-emulator extention for ISC's DHCP IPv4/IPv6 (dhcp.conf, dhcp6.conf) and rsyslog
	PKGARCH:=all
	DEPENDS:=+isc-dhcp-server-ipv6 +rsyslog +rpd
endef

define Package/description
Package providing services for integration testing
endef

define Build/Compile
	@echo "===> COMPILE: PKG_BUILD_DIR='$(PKG_BUILD_DIR)' INSTALL_BIN='$(INSTALL_BIN)' 1='$(STAGING_DIR)'"
endef

PY_DST_DIR:=/usr/lib/python2.7/site-packages/rpd_service_suite
SERVICE_DIR:=/etc/init.d

define Package/core-emulator/install
	mkdir $(1)/etc
	mkdir $(1)/etc/config
	$(INSTALL_CONF) ./files/{dhcpd,dhcpd6}.conf $(1)/etc
	$(INSTALL_CONF) ./files/network $(1)/etc/config/
	$(INSTALL_CONF) ./files/system $(1)/etc/config/
	$(INSTALL_DATA) ./files/dhcp.conf $(1)/etc/config/dhcp
	$(INSTALL_DIR) $(1)$(PY_DST_DIR) $(1)$(SERVICE_DIR)
	$(INSTALL_BIN) ./{service_suite_mgr,__init__,service_suite_controller}.py $(1)$(PY_DST_DIR)/
	$(INSTALL_BIN) ./service-manager.init $(1)$(SERVICE_DIR)/service-manager
	$(INSTALL_BIN) ./tps.init $(1)$(SERVICE_DIR)/tps

endef

$(eval $(call BuildPackage,core-emulator))
