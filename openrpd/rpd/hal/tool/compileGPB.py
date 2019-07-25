#!/usr/bin/python

import subprocess
import argparse

# Global variables
protocCmd = "protoc"
homeDir = "../"
idlDir = "proto/"
outputDir = "src/msg/"
fileList = (
    "HalCommon.proto",
    "ClientProvision.proto",
    "HalControl.proto",
    "HalOperation.proto",
    "HalStats.proto"
)


def checkIfPtotocInstalled():
    global protocCmd
    output = subprocess.check_output((protocCmd + " --version").split(" "))

    if output.find("libprotoc") >= 0:
        return True
    else:
        return False


"""
    protoc -I ./idl/ --python_out ./src/msg/ ./idl/HalCommon.proto
"""


def compileProto(fileName):
    global homeDir
    includeDir = homeDir + idlDir
    msgOutputDir = homeDir + outputDir
    msgDir = includeDir

    protocPythonCmd = protocCmd + " -I " + includeDir + \
        " --python_out " + msgOutputDir + " " + msgDir + fileName
    print protocPythonCmd

    subprocess.call(protocPythonCmd.split(" "))


def compileAllProtocFiles():

    for fn in fileList:
        compileProto(fn)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--home_path", type=str, help="The Hal directory path")
    args = parser.parse_args()
    homeDir = args.home_path
    compileAllProtocFiles()
