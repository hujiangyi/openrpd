#!/bin/bash
RETCODE=0
source /tmp/openrpd/venv/bin/activate

## Run unit tests
ulimit -n 4096
cd openrpd
coverage run --rcfile=.coverage.rc rpd/rpd_unit_tests.py -v || RETCODE=1
coverage xml

exit $RETCODE
