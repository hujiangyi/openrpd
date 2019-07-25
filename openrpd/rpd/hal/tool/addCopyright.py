#!/usr/bin/python

import os.path
import os

whitelist = ["../../ssd/testing/codefile"]

rootDir = "../../"

for d, _, fl in os.walk(rootDir):
    if d.find("/tool") >= 0:
        continue
    for fn in fl:
        ext = os.path.splitext(d + "/" + fn)
        if ext[1] in (".py"):
            # we don't want to process the _pb2 file
            if ext[0].endswith("_pb2"):
                continue
            if fn == "__init__.py":
                continue
            if ext[0] in whitelist:
                print "{} skipt since in whitelist".format(d + '/' + fn)
                continue
# print "The file name is ", fn
#            print "Processing the file", fn
            content = None
            with open(d + "/" + fn) as f:
                content = f.read()
                # content = re.sub("HAL", "Hal", conetent)

            # delete the first line
            contentLines = content.split("\n")
            if contentLines[0] == "":
                contentLines.pop(0)

            # delete
            for i in xrange(len(contentLines)):
                if contentLines[i].find("We should add the copyright here") >= 0:
                    contentLines.pop(i)
                    break

            content = "\n".join(contentLines)

            if content.find("Copyright") >= 0 and \
                    content.find("Cisco and/or its affiliates") >= 0 and \
                    content.find("CableLabs") >= 0 and \
                    content.find("http://www.apache.org/licenses/LICENSE-2.0") >= 0:
                continue
            elif content.find("http://www.apache.org/licenses/LICENSE-2.0") >= 0:
                print "{} only has appache license".format(d + '/' + fn)
            elif content.find("Copyright") >= 0:
                print "{} has Copyright, do not override!".format(d + '/' + fn)
                continue
            else:
                print "{} Copyright incomplete!".format(d + '/' + fn)

            # judge if we have copywrite?
            if content.find("Copyright") < 0:
                content = """#
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
#""" + '\n' + content
            if not content is None:
                with open(d + "/" + fn, "w") as f:
                    f.write(content)
