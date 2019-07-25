#!/usr/bin/env bash

if [ $# -ne 3 ]; then
    echo "Usage: $0 <prefix> <git dir> <file>"
    exit 1
fi

PREFIX=$1
GIT_DIR=$2
RPD_IMAG_INFO_F=$3

pushd ${GIT_DIR} > /dev/null

TAG_DESC=`git describe --tags --match 'rel-[0-9]*.[0-9]*.[0-9]*' --exact-match 2>/dev/null`
if [ $? -eq 0 ]; then
    # This is an exact match of an official release
    TAG_DESC+=-0-g`git rev-parse --short HEAD`
    REL_TYPE="rel"
    # Example: rel-1.0.0-0-gf5ac66c
else
    TAG_DESC=`git describe --tags --match 'dev-[0-9]*.[0-9]*.[0-9]*' --exact-match 2>/dev/null`
    if [ $? -eq 0 ]; then
        # This is an exact match of a development release, so the DEV_ID and hash must be added
        TAG_DESC+=-0-g`git rev-parse --short HEAD`
        REL_TYPE="dev"
        # Example: dev-1.1.0-1-g87d2480
    else
        TAG_DESC=`git describe --tags --match 'dev-[0-9]*.[0-9]*.[0-9]*' 2>/dev/null`
        if [ $? -eq 0 ]; then
            # This is a development release (change number is greater than 0)
            REL_TYPE="dev"
            # Example: dev-1.1.0-1-g87d2480
        else
            TAG_DESC=`git describe --tags --match 'rel-[0-9]*.[0-9]*.[0-9]*' 2>/dev/null`
            if [ $? -eq 0 ]; then
                # This commit is after an official release, but no development tag is present
                REL_TYPE="post"
                # Example: rel-1.1.0-1-g87d2480
            else
                # No tags are present; create a default version number
                REL_TYPE="dev"
                TAG_DESC=dev-0.0.0-0-g`git rev-parse --short HEAD`
                # Example: dev-0.0.0-0-g87d2480
            fi
        fi
    fi
fi

VER_NUM=`echo ${TAG_DESC} | cut -f2 -d-`
MAJOR_REV=`echo ${VER_NUM} | cut -f1 -d.`
MINOR_REV=`echo ${VER_NUM} | cut -f2 -d.`
PATCH_REV=`echo ${VER_NUM} | cut -f3 -d.`
DEV_ID=`echo ${TAG_DESC} | cut -f3 -d-`
HASH=`echo ${TAG_DESC} | cut -f4 -d-`

REV_SUFFIX=""
if [ ${REL_TYPE} = "dev" ]; then
    REV_SUFFIX="-dev.${DEV_ID}"
elif [ ${REL_TYPE} = "post" ]; then
    REV_SUFFIX="-post.${DEV_ID}"
fi

REV_SUFFIX+="+${HASH}"
VERSION_STRING="${VER_NUM}${REV_SUFFIX}"

echo ${TAG_DESC}
echo "REL_TYPE=${REL_TYPE}"
echo "TAG_DESC=${TAG_DESC}"
echo "VER_NUM=${VER_NUM}"
echo "MAJOR_REV=${MAJOR_REV}"
echo "MINOR_REV=${MINOR_REV}"
echo "PATCH_REV=${PATCH_REV}"
echo "DEV_ID=${DEV_ID}"
echo "HASH=${HASH}"
echo "REV_SUFFIX=${REV_SUFFIX}"
echo "VERSION_STRING=${VERSION_STRING}"

popd > /dev/null

echo "${PREFIX}_MAJOR_REV=${MAJOR_REV}" >> $RPD_IMAG_INFO_F
echo "${PREFIX}_MINOR_REV=${MINOR_REV}" >> $RPD_IMAG_INFO_F
echo "${PREFIX}_PATCH_REV=${PATCH_REV}" >> $RPD_IMAG_INFO_F
echo "${PREFIX}_REV_SUFFIX=${REV_SUFFIX}" >> $RPD_IMAG_INFO_F

exit 0
