#!/usr/bin/python

import os.path
import re
import os


rootDir = "../"

for d, _, fl in os.walk(rootDir):
    for fn in fl:
        ext = os.path.splitext(d + "/" + fn)
        if ext[1] in (".py", ".proto"):
            if ext[0] == "convertHAL2Hal":
                continue
            # we don't want to process the _pb2 file
            if ext[0].endswith("_pb2"):
                continue
            print "The file name is ", fn
            print "Processing the file", fn
            content = None
            with open(d + "/" + fn) as f:
                conetent = f.read()
                content = re.sub("HAL", "Hal", conetent)

            if not content is None:
                with open(d + "/" + fn, "w") as f:
                    f.write(content)
