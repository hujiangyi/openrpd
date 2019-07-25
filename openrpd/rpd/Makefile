#
# Copyright (c) 2016 Cisco and/or its affiliates, and 
#                    Teleste Corporation,
#                    MaxLinear, Inc. ("MaxLinear"), and
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

PKG_NAME:=rpd
PKG_RELEASE:=0

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/rpd/config
	source "$(SOURCE)/Config.in"
endef

define Package/rpd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Remote Physical Layer Device Implementation
  URL:=http://www.cablelabs.com/wp-content/uploads/specdocs/CM-SP-GCP-I01-150615.pdf
  PKGARCH:=all
  DEPENDS:=+libc \
  		   +libpthread \
  		   +librt \
  		   +libstdcpp \
  		   +libncurses \
  		   +protobuf-to-dict \
  		   +python-glibc \
  		   +fysom \
  		   +pyzmq \
  		   +protobuf-c \
  		   +ipc_defs \
  		   +busybox \
  		   +odhcp6c \
  		   +base-files \
		   +klish \
		   +klish-xml-files
endef

#
# There are next dependencies when CONFIG_RPD_UNITTEST is selected:
# 	+pylint
#

define Package/rpd/description
Implementation of Generic Control Plane	
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PROTO_PATH)
endef

PROTO_PATH:=$(STAGING_DIR)/usr/share/rpd/
export PYTHONPATH:=$(PKG_BUILD_DIR)

PROTO_COMPILER:=protoc
GPB_COMPILE:=$(PROTO_COMPILER) --python_out=./gpb/ --proto_path=$(PROTO_PATH)

define Build/Compile
	cd common/ && $(MAKE)
	cd l2tp/ && $(MAKE)
endef

RPD_DIR:=/usr/lib/python2.7/site-packages/rpd
CLI_DIR:=/usr/lib/python2.7/site-packages
define CopyPy
	mkdir -p $(1)$(RPD_DIR)/$(2)
	$(INSTALL_BIN) ./$(2)/*.py $(1)$(RPD_DIR)/$(2)/
endef

define CopyCliDir
	mkdir -p $(1)$(CLI_DIR)/$(2)
	$(INSTALL_BIN) ./$(2)/*.py $(1)$(CLI_DIR)/$(2)/
endef

define CopyCli
        @echo Copying all Open RPD Cli
	$(call CopyCliDir,$(1),cli)
	$(call CopyCliDir,$(1),cli/provision_cli)
	$(call CopyCliDir,$(1),cli/gcp_cli)
	$(call CopyCliDir,$(1),cli/ikev2_cli)
	$(call CopyCliDir,$(1),cli/l2tp_cli)
	$(call CopyCliDir,$(1),cli/macsec_cli)
	$(call CopyCliDir,$(1),cli/ssd_cli)
	$(call CopyCliDir,$(1),cli/basic_cfg)
	$(call CopyCliDir,$(1),cli/cmd_rpd)
endef

define CopyUnitTests
	@echo Copying all RPD unittests
	$(INSTALL_BIN) ./rpd_unit_tests.py $(1)$(RPD_DIR)

	$(call CopyPy,$(1),confdb/testing)
	$(call CopyPy,$(1),dispatcher/testing)
	$(call CopyPy,$(1),common/testing)
	$(call CopyPy,$(1),rcp/testing)
	$(call CopyPy,$(1),rcp/rcp_lib/testing)
	$(call CopyPy,$(1),rcp/gcp/testing)
	$(call CopyPy,$(1),rcp/gcp/gcp_lib/testing)
	$(call CopyPy,$(1),rcp/vendorTLVs/testing)
	$(call CopyPy,$(1),testing)
	$(call CopyPy,$(1),it_api/testing)
	$(call CopyPy,$(1),hal/src/testing)
	$(call CopyPy,$(1),hal/src/db/testing)
	$(call CopyPy,$(1),hal/src/msg/testing)
	$(call CopyPy,$(1),hal/src/transport/testing)
	$(call CopyPy,$(1),l2tp/docsisAVPs/testing)
	$(call CopyPy,$(1),l2tp/vendorAVPs/testing)
	$(call CopyPy,$(1),l2tp/l2tpv3/testing)
	$(call CopyPy,$(1),resource/testing)
	$(call CopyPy,$(1),ssd/testing)

endef

define CopyNodeInitFiles
	@echo "Starting install vici, wpa supplicant init files"
	$(INSTALL_BIN) ./vici.init $(1)/etc/init.d/vici
	$(INSTALL_BIN) ./wpa_supplicant.init $(1)/etc/init.d/wpa_supplicant
endef

define Package/rpd/install
	$(INSTALL_DIR) $(1)$(RPD_DIR) $(1)/etc/init.d/ $(1)/etc/config/
	$(INSTALL_BIN) ./__init__.py $(1)$(RPD_DIR)
	$(call CopyPy,$(1),confdb)
	$(call CopyPy,$(1),dispatcher)
	$(call CopyPy,$(1),common)
	$(call CopyPy,$(1),rcp)
	$(call CopyPy,$(1),rcp/rcp_lib)
	$(call CopyPy,$(1),rcp/gcp)
	$(call CopyPy,$(1),rcp/gcp/gcp_lib)
	$(call CopyPy,$(1),rcp/vendorTLVs)
	$(call CopyPy,$(1),rcp/vendorTLVs/src)
	$(call CopyPy,$(1),gpb)
	$(call CopyPy,$(1),hal)
	$(call CopyPy,$(1),ssd)
	$(call CopyPy,$(1),it_api)
	$(call CopyPy,$(1),hal/lib)
	$(call CopyPy,$(1),hal/lib/clients)
	$(call CopyPy,$(1),hal/lib/drivers)
	$(call CopyPy,$(1),hal/src)
	$(call CopyPy,$(1),hal/src/db)
	$(call CopyPy,$(1),hal/src/msg)
	$(call CopyPy,$(1),hal/src/transport)
	$(call CopyPy,$(1),l2tp)
	$(call CopyPy,$(1),l2tp/client)
	$(call CopyPy,$(1),l2tp/docsisAVPs)
	$(call CopyPy,$(1),l2tp/docsisAVPs/src)
	$(call CopyPy,$(1),l2tp/vendorAVPs)
	$(call CopyPy,$(1),l2tp/vendorAVPs/src)
	$(call CopyPy,$(1),l2tp/l2tpv3)
	$(call CopyPy,$(1),l2tp/l2tpv3/simulator)
	$(call CopyPy,$(1),l2tp/l2tpv3/src)
	$(call CopyPy,$(1),mcast)
	$(call CopyPy,$(1),mcast/src)
	$(call CopyPy,$(1),provision)
	$(call CopyPy,$(1),provision/manager)
	$(call CopyPy,$(1),provision/manager/src)
	$(call CopyPy,$(1),provision/process_agent)
	$(call CopyPy,$(1),provision/process_agent/agent)
	$(call CopyPy,$(1),provision/process_agent/dhcp)
	$(call CopyPy,$(1),provision/process_agent/interface_status)
	$(call CopyPy,$(1),provision/process_agent/ipsec)
	$(call CopyPy,$(1),provision/process_agent/l2tp)
	$(call CopyPy,$(1),provision/process_agent/macsec)
	$(call CopyPy,$(1),provision/process_agent/ptp1588)
	$(call CopyPy,$(1),provision/process_agent/rcp)
	$(call CopyPy,$(1),provision/process_agent/tod)
	$(call CopyPy,$(1),provision/transport)
	$(call CopyPy,$(1),provision/simulator)
	$(call CopyPy,$(1),provision/proto)
	$(call CopyPy,$(1),provision/testing)
	$(call CopyPy,$(1),resource)
	$(call CopyPy,$(1),resource/src)
	$(call CopyPy,$(1),statistics)
	$(call CopyCli,$(1))

ifeq ($(CONFIG_PACKAGE_core-emulator),)	
	$$(call CopyNodeInitFiles,$(1))
ifeq ($(CONFIG_TARGET_x86),y)
	@echo "Copying IT client manager to support IT test cases"
	$(INSTALL_BIN) ./it_api/manager_it_api.init $(1)/etc/init.d/it_manager
endif
endif

ifeq ($(CONFIG_PACKAGE_core-emulator),y)	
	@echo CONFIG_RPD_UNITTEST: $$(CONFIG_RPD_UNITTEST)
	$(if $(CONFIG_RPD_UNITTEST), $$(call CopyUnitTests,$(1)))
endif
	$(INSTALL_CONF) ./confdb/*.conf $(1)/etc/config/
	$(INSTALL_CONF) ./hal/conf/*.conf $(1)/etc/config/
	$(INSTALL_CONF) ./rcp/conf/*.conf $(1)/etc/config/
	$(INSTALL_CONF) ./files/network $(1)/etc/config/
	$(INSTALL_CONF) ./files/system $(1)/etc/config/
	$(INSTALL_CONF) ./files/firewall.config $(1)/etc/config/firewall
	$(INSTALL_CONF) ./files/rpd_logging.conf $(1)/etc/config/
	$(INSTALL_CONF) ./files/rpd_debug.json $(1)/etc/config/
	$(INSTALL_CONF) ./files/banner $(1)/etc/
	$(INSTALL_CONF) ./files/profile $(1)/etc/
ifeq ($(CONFIG_PACKAGE_core-emulator),y)
	$(INSTALL_BIN) ./files/rpd-core.init $(1)/etc/init.d/rpd-core
else
	$(INSTALL_BIN) ./files/rpd.init $(1)/etc/init.d/rpd
	$(INSTALL_BIN) ./files/rpd_start.sh $(1)/etc/config/
endif
	$(INSTALL_CONF) ./files/shadow $(1)/etc/
	$(INSTALL_DIR)  $(1)/bin/
	$(INSTALL_BIN) ./files/sshshell $(1)/bin/
	$(INSTALL_BIN) ./{manager.py,tps.py,tpc.py,example.py,python_path_resolver.py} $(1)$(RPD_DIR)


endef

$(eval $(call BuildPackage,rpd))
