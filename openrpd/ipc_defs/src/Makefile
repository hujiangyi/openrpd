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

LDFLAGS+=-lprotobuf-c
CFLAGS?=-fPIC
INCLUDE_DIR=.

LIBNAME=libipc_defs.so
GEN_C_FILE = dhcp.pb-c.c
OBJ_FILE = dhcp_ipc.o

C_PROTO_COMPILER:=protoc-c
C_GPB_COMPILE:=$(C_PROTO_COMPILER) --c_out=. --proto_path=../

all: $(LIBNAME)

$(GEN_C_FILE):
	$(C_GPB_COMPILE) ../dhcp.proto

$(OBJ_FILE): $(GEN_C_FILE)
	$(CC) $(LDFLAGS) -c -o $@ -fPIC -I $(INCLUDE_DIR) $(CFLAGS) $<

$(LIBNAME): $(OBJ_FILE)
#$(AR) rcs $(LIBNAME) $(OBJ_FILE)
	$(CC) -fPIC -shared -o $@ $^

clean:
	rm *.[cho] *.so
