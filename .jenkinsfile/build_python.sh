#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TMPDIR=/tmp/openrpd

ps -A | grep syslog
if [[ $? != "0" ]]; then
	echo "### Starting rsyslog..."
	sudo service rsyslog start
fi

if [ ! -f /tmp/openrpd/python-venv-complete ]; then
	sudo pip install virtualenv

	mkdir -p $TMPDIR

	cp $THIS_DIR/../package/lang/python/patches/012-l2tp-socket-support.patch $TMPDIR
        cp $THIS_DIR/../package/lang/python/patches/013-unittest-sorted-visit.patch $TMPDIR

	cd $TMPDIR
	wget https://www.python.org/ftp/python/2.7.9/Python-2.7.9.tar.xz
	tar xvJf Python-2.7.9.tar.xz
	cd $TMPDIR/Python-2.7.9/Modules
	patch -p2 <$TMPDIR/012-l2tp-socket-support.patch
        cd $TMPDIR/Python-2.7.9/Lib/unittest
        patch -p3 <$TMPDIR/013-unittest-sorted-visit.patch
	cd $TMPDIR/Python-2.7.9
	./configure --prefix=`pwd`
	make
	make install
	cd $TMPDIR
	virtualenv -p $TMPDIR/Python-2.7.9/bin/python venv

	source venv/bin/activate

	pip install -r $THIS_DIR/../requirements.txt
	pip install pyzmq --install-option="--zmq=bundled"

	touch /tmp/openrpd/python-venv-complete
fi

