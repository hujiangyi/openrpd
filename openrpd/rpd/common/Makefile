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
PROTO_PATH?=$(RPD_TOP_DIR_PATH)/rpd/common/proto_dir/

export PYTHONPATH:=$(RPD_TOP_DIR_PATH)
GPB_COMPILE:=$(PROTO_COMPILER) --python_out=$(RPD_TOP_DIR_PATH)rpd/gpb/ --proto_path=$(PROTO_PATH)

all:
	mkdir -p $(PROTO_PATH)
	python ./proto_generator.py $(RPD_TOP_DIR_PATH)/rpd/rcp/rcp_lib/cfg.proto
	cp ../rcp/rcp_lib/*.proto $(PROTO_PATH)
	cp ../confdb/db.proto $(PROTO_PATH)
	cp ../../ipc_defs/*.proto $(PROTO_PATH)
	cp ../it_api/*.proto $(PROTO_PATH)
	cp ../ssd/proto/*.proto $(PROTO_PATH)
	$(GPB_COMPILE) $(PROTO_PATH)/*.proto
	
	# Generate the cfg proto
	python ./proto_generator.py --test ../rcp/gcp/gcp_lib/cfg.proto
	python ./proto_generator.py --ucd ../rcp/gcp/gcp_lib/ucd.proto
	python ./proto_generator.py --ocd ../rcp/gcp/gcp_lib/ocd.proto
	python ./proto_generator.py --dpd ../rcp/gcp/gcp_lib/dpd.proto
	python ./proto_generator.py --ucdBurst ../rcp/gcp/gcp_lib/ucdBurstProfile.proto
	cp $(PROTO_PATH)/CcapCoreIdentification.proto ../provision/proto/
	$(PROTO_COMPILER) --python_out=../rcp/gcp/gcp_lib/ --proto_path=../rcp/gcp/gcp_lib ../rcp/gcp/gcp_lib/*.proto

	# make the Hal proto messages
	python ../hal/tool/compileGPB.py --home_path=$(RPD_TOP_DIR_PATH)/rpd/hal/
	
	# make the provision proto messages
	$(PROTO_COMPILER) --python_out=../provision/proto/ --proto_path=../provision/proto/ ../provision/proto/*.proto
	$(PROTO_COMPILER) --python_out=../gpb/ --proto_path=../provision/proto/ ../provision/proto/*.proto
	
	# Generate the simulator proto
	cp ../rcp/simulator/proto/master_sim.proto $(PROTO_PATH)
	$(GPB_COMPILE) $(PROTO_PATH)/master_sim.proto

        # Generate cli related proto
	$(PROTO_COMPILER) --python_out=$(RPD_TOP_DIR_PATH)rpd/gpb/ --proto_path=../cli/proto_def ../cli/proto_def/*.proto
	cp ../cli/msg_type_def/*.py $(RPD_TOP_DIR_PATH)rpd/gpb/

clean:
	rm -rf $(PROTO_PATH)
	rm ../gpb/*pb2.py
	# clean the Hal proto messages
	rm ../hal/src/msg/*pb2.py
