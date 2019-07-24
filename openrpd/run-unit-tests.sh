#!/usr/bin/env bash

#
# Script for executing unit tests
# NOTE: If this script changes, please update relevant part
#       in Jenkinsfile also (and vice-versa), if applicable.
#

RETCODE=0
OPENRPD_ROOT=$( cd "$(dirname ${BASH_SOURCE[0]} )" && pwd)
PY_BUILD_COMPLETE_MARKER=$OPENRPD_ROOT/.openrpd_py_venv_built

RELEASE_DESCRIPTION=`lsb_release -s -d`
echo "Release description: ${RELEASE_DESCRIPTION}"
echo ""

echo "# Pre-build"

echo "## Build dependencies"

if [[ -f $PY_BUILD_COMPLETE_MARKER ]]; then
	echo "Python already built, skipping..."
	source venv/bin/activate
elif [[ ${RELEASE_DESCRIPTION} == "Ubuntu 14.04.4 LTS" ]] || 
     [[ ${RELEASE_DESCRIPTION} == "Ubuntu 14.04.5 LTS" ]]; then
	sudo apt-get install -y git-core build-essential libssl-dev \
		libncurses5-dev unzip gawk subversion mercurial
	sudo apt-get install -y protobuf-compiler protobuf-c-compiler \
		python-protobuf
	sudo apt-get install -y python-dev python-pip pylint
	sudo apt-get install -y redis-server
	sudo apt-get install -y psmisc
	sudo apt-get install -y libffi-dev

	ps -A | grep syslog
	if [[ $? != "0" ]]; then
		echo "### Starting rsyslog..."
		sudo service rsyslog start
	fi

	sudo pip install virtualenv

	wget https://www.python.org/ftp/python/2.7.9/Python-2.7.9.tar.xz
	tar xvJf Python-2.7.9.tar.xz
	cd Python-2.7.9
	cd Modules
	patch -p2 <../../package/lang/python/patches/012-l2tp-socket-support.patch
	cd ..
	./configure --prefix=`pwd`
	make
	make install
	cd ..
	virtualenv -p `pwd`/Python-2.7.9/bin/python venv
	source venv/bin/activate

	pip install fysom protobuf-to-dict glibc
	pip install pyzmq --install-option="--zmq=bundled"
	pip install sortedcontainers
	pip install python-daemon
	pip install protobuf
	pip install redis
	pip install psutil
	pip install pyasn1
	pip install pyasn1-modules
	pip install pyopenssl
	pip install tftpy
	pip install urllib

	touch $PY_BUILD_COMPLETE_MARKER
else
	echo "Sorry, only Ubuntu 14.04.4 or .5 LTS is supported at this time."
	exit 1
fi

echo "# Build"

echo "## Make the project"
cd $OPENRPD_ROOT
make

echo "# Test"

echo "## Generate coverage XML report"
export PYTHONPATH=$OPENRPD_ROOT:$OPENRPD_ROOT/rpd/l2tp
python rpd/rpd_unit_tests.py -v || RETCODE=1

exit $RETCODE
