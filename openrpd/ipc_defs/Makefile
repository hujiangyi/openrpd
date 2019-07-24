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

include $(TOPDIR)/rules.mk

PKG_NAME:=ipc_defs
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/ipc_defs
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OpenRPD IPC message format definitions
  PKGARCH:=all
  DEPENDS:=+protobuf-c
endef

define Package/ipc_defs/description
OpenRPD Interprocess communication message format definitions
endef

PROTO_PATH:=$(STAGING_DIR)/usr/share/rpd/

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PROTO_PATH)
	$(CP) ./src/Makefile $(PKG_BUILD_DIR)/
endef

C_PROTO_COMPILER:=protoc-c
PY_PROTO_COMPILER:=protoc
C_GPB_COMPILE:=$(C_PROTO_COMPILER) --c_out=$(PKG_BUILD_DIR)/. --proto_path=.
PY_GPB_COMPILE:=$(PY_PROTO_COMPILER) --python_out=$(PKG_BUILD_DIR)/. --proto_path=.

define Build/Compile
	$(C_PROTO_COMPILER) --version
	$(PY_PROTO_COMPILER) --version
	$(C_GPB_COMPILE) ./dhcp.proto
	$(PY_GPB_COMPILE) ./dhcp.proto
	$(call Build/Compile/Default)
endef

# Python classes will be generated and copied as part of DB proto in RPD package

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/ $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/*.[h] $(STAGING_DIR)/usr/include/
	$(CP) ./*.proto $(PROTO_PATH)
	$(CP) $(PKG_BUILD_DIR)/*.so $(1)/usr/lib/
endef

RPD_DIR:=/usr/lib/python2.7/site-packages/rpd

define Package/ipc_defs/install
	$(INSTALL_DIR) $(1)$(RPD_DIR) $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/*.so $(1)/usr/lib/
endef

$(eval $(call RequireCommand,protoc, \
		Please install protobuf-compiler))

$(eval $(call RequireCommand,protoc-c, \
		Please install protobuf-c-compiler))

$(eval $(call BuildPackage,ipc_defs))
