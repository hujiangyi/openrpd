README
======

Please see the [project wiki](https://community.cablelabs.com/wiki/display/C3/Building+and+Using+OpenRPD+Software)
for more information.


Jenkins CI
----------

Currently the project is built using two separate jobs on the C3 Jenkins
server.

1. The _reports_ job runs the unit tests on the code strictly from the
   Ubuntu 14.04.4 build machine and generates code reports.
2. The _pipeline_ job builds the RPD and CCAP core emulator VMs and runs the
   integration tests. The "reports" job will be absorbed by this job once
   the code coverage and violations reports plugins are compatible with the
   pipeline plugin.

The Jenkinsfile that controls the _pipeline_ job is included in the repo.
