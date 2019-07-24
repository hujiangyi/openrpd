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

RPD_TOP_DIR_PATH?=../../
PROTO_COMPILER?=protoc
PROTO_PATH?=$(RPD_TOP_DIR_PATH)/rpd/l2tp/l2tpv3/proto

export PYTHONPATH:=$(RPD_TOP_DIR_PATH)
GPB_COMPILE:=$(PROTO_COMPILER) --python_out=$(RPD_TOP_DIR_PATH)rpd/l2tp/l2tpv3/src --proto_path=$(PROTO_PATH)

all:
	$(GPB_COMPILE) $(PROTO_PATH)/*.proto

clean:
	rm -rf $(RPD_TOP_DIR_PATH)rpd/l2tp/l2tpv3/src/*pb2.py
