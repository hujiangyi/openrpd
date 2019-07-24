######################
Continuous Integration
######################

Continuous Integration (CI) in the OpenRPD project consists of running unit and
integration tests upon each code submission and merge into the master (or
primary) branch. It is the responsibility of the project developers to maintain
adequate unit test code coverage and appropriate integration test functionality.
While CI tools can automatically build, test, and deploy code, it is only as
useful as the tests the code contains.

Jenkins
=======

The `C3 Jenkins CI Server`_ is the server that runs CI for the OpenRPD project.
It contains various scripts and plugins to performs its duties, including
building and testing the code and generating reports on unit test coverage and
various formatting violations. As Python is a highly formatted language, it is
of the best interest of project participants to maintain a coding style
consistent with Python best practices.

.. _C3 Jenkins CI Server: https://c3jenkins.cablelabs.com/

.. _jenkins-jobs:

Jobs
----

Jobs are how Jenkins configures work to perform based on certain actions and/or
inputs. The OpenRPD project currently utilizes the following jobs:

Pipeline
^^^^^^^^

The Pipeline job runs the ``Jenkinsfile`` contained in the root of the
`openrpd` project repo. This job:

* builds custom Python environment for unit tests
* runs PEP-8 violations report
* builds this documentation in HTML form
* runs the unit tests & generates code coverage report
* builds both VMs
* performs the integration tests

This job takes longer to execute and typically takes between 45 minutes and 1
hour to complete.

.. note::

   Due to the requirement of running the OpenRPD VMs using KVM, the integration
   test stage of this job cannot scale in cloud VM providers (i.e. Amazon AWS
   EC2 or Docker) and must be run on a single VM instance contained in
   CableLabs' IT core server farm.

OpenWRT
^^^^^^^

The OpenWRT job runs when there are changes to the `openwrt_15.05` project repo
and simply builds both VMs. It does not perform any testing.


Build Nodes
-----------

Jenkins talks to build nodes, typically VMs, that perform the contents of the
``.jenkins.sh`` and ``Jenkinsfile`` build scripts.

1. **cllv-lvslav01** performs specialized builds for OpenRPD and is dedicated
   solely to this project.

2. **cllv-lvslav02** is a Docker host and can spin up build nodes on demand for
   various projects, including OpenRPD. OpenRPD uses a specific Docker image to
   run the `Reports`_ job. This is how the `Reports`_ job is able to auto scale
   to accomodate spikes in workload.

3. **Amazon AWS EC2 cloud** will spin up build nodes as needed and auto-destroy
   them when they are no longer in use. This cloud is currently used to build
   the VM .vmdk image files, by far the most time-consuming and
   processor-intensive aspect of the OpenRPD build process.

