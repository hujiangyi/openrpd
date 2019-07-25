#!/usr/bin/env bash

FEED_SRC_DIR=$1
CONFIG_FILE=$2
FILE_SUFFIX=$3
DEBUG=$4

# TODO: add logic around parsing parameters for manual execution

echo "$0 pwd = `pwd`"
echo "src-link openrpd ${FEED_SRC_DIR}" > feeds.conf
scripts/feeds update -a
scripts/feeds install -a
cp ${CONFIG_FILE} .config
echo "CONFIG_TARGET_x86=y" >> .config
echo "CONFIG_TARGET_x86_generic=y" >> .config
echo "CONFIG_TARGET_x86_generic_Generic=y" >> .config
make defconfig

