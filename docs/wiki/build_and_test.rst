######################
OpenRPD Build and Test
######################

.. note:: These instructions are intended to be used for setting up a
   Debian-based build machine (Ubuntu).

***********************************
Software Prerequisites for Building
***********************************

OpenWRT
=======

(required to build the base OpenWRT)

.. code-block:: bash

  sudo apt-get install git-core build-essential libssl-dev libncurses5-dev unzip gawk subversion mercurial daemontools

OpenRPD
=======

(required to build the OpenRPD component)

.. code-block:: bash

  sudo apt-get install python-dev

The build now requires at least version 2.6.1 of protobuf-compiler and version
1.2.1 of protobuf-c-compiler, which must be compiled from source for Ubuntu 14.04.

.. code-block:: bash

  wget https://github.com/protobuf-c/protobuf-c/releases/download/v1.2.1/protobuf-c-1.2.1.tar.gz
  wget https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.tar.gz
  
  tar -xzf protobuf-c-1.2.1.tar.gz
  tar -xzf protobuf-2.6.1.tar.gz
  
  cd protobuf-2.6.1/
  ./configure
  make
  sudo make install
  sudo ldconfig
  
  cd python
  python setup.py build
  sudo python setup.py install --cpp_implementation
  
  cd ../..
  cd protobuf-c-1.2.1/
  
  ./configure
  make
  sudo make install
  sudo ldconfig

To verify the correct versions, run:

.. code-block:: bash

  protoc-c --version

You should see::

  protobuf-c 1.2.1
  libprotoc 2.6.1

OpenRPD Unit Tests
==================

(required to run the OpenRPD unit tests on the development environment)

.. code-block:: bash

  sudo apt-get install python-pip pylint libffi-dev
  sudo pip install fysom protobuf-to-dict glibc
  sudo pip install pyzmq --install-option="--zmq=bundled"

OpenRPD CCAP Core Emulator
==========================

(required to build the CCAP Core Emulator project)

.. code-block:: bash

  sudo apt-get install gettext

***********************
RPD Check Out and Build
***********************

The RPD and the CCAP Core Emulator now build from the same branch.
The essence of the build scripts is to add the openrpd project repo as a feed_
in the OpenWRT package management system, and to configure and install the
RPD-specific packages from that feed_.

.. _feed: https://wiki.openwrt.org/doc/devel/feeds

1. Clone the OpenWRT repository using either the SSH or HTTP method:

  a. **HTTP**:
     
     .. code-block:: bash

        git clone -b chaos_calmer_openrpd https://gerrit.cablelabs.com/openwrt

  b. **SSH**:

     .. code-block:: bash

        git clone -b chaos_calmer_openrpd ssh://gerrit.cablelabs.com:29418/openwrt

2. Navigate into the cloned repository directory:

   ``cd openwrt``

3. Execute the ``build.sh`` script with the ``vRPD`` parameter:

   .. note:: Running this script will clone the OpenRPD repository into the
      correct filesystem location.

   .. note:: The build script is currently pre-configured to clone
      over SSH, so if you want to clone over HTTP, you must manually modify the
      ``build/x86/OpenRPD.feeds`` file (editing the URL to use
      ``https://gerrit.cablelabs.com/openrpd;master``), set up your HTTP
      password and enter your username and generated HTTP password (not the
      password that you use to log into CableLabs Community/InfoZone and
      Gerrit) during the clone step. During the script execution, you may have
      to enter this information more than once.

   .. code-block:: bash

      ./build.sh vRPD

   .. warning:: The VM image is saved in the ``bin/x86`` directory. Subsequent
      builds (e.g., for the core emulator) will overwrite the file, so be sure
      to rename the .vmdk file before proceeding to build the core emulator.

   .. tip:: For informational purposes, here is a :download:`successful build log <files/RPD_15.05_build_log.txt>`.

   .. _successful build log: ./files/RPD_15.05_build_log.txt

RPD Unit Testing on the Build Machine
=====================================

.. attention:: As the build process is currently rapidly changing, please see
   the :download:`run-unit-tests.sh <../../openrpd/run-unit-tests.sh>` script in the root
   of the openrpd project directory for
   the latest build dependencies, process, and unit test procedure(s). This
   script is executed as part of the Continuous Integration build process in
   order to automatically verify new software patches to the project. The
   Jenkins server runs the unit test script by cloning the openrpd repo and
   executing ``./openrpd/run-unit-tests.sh`` from the directory root. Please note
   that the repo is named `openrpd` and there is a folder in that directory
   called `openrpd` which contains the relevant code. This may be confusing to
   humans but it was done to adapt to the OpenWRT build system.

If you would like to run the unit tests, please use an **Ubuntu 14.04 LTS**
machine and follow these steps:

.. note:: If running unit tests from the OpenWRT build directory, the
   `$BASE_PATH` will be the path of the OpenWRT repo plus `/package/feeds/` in
   the examples below (``<OpenWRT>/package/feeds/``). If building from the
   OpenRPD directory, the `$BASE_PATH` is the path of the openrpd repo. The
   recommended method is to use the command:

   .. code-block:: bash

      BASE_PATH="<OpenWRT or OpenRPD path>"

1. First, due to the additional L2TP code, load the `l2tp_ip` kernel module
   into the OS:
   
   .. code-block:: bash

      sudo modprobe l2tp_ip
      sudo modprobe l2tp_ip6

2. Run all of the Unit tests:

   .. code-block:: bash

      cd $BASE_PATH
      ./openrpd/run-unit-tests.sh

   .. note:: You may need to execute ``sudo ./openrpd/run-unit-tests.sh`` because the
      build machine is set up to give passwordless sudo permission for the
      `python`, `pip`, and `apt-get` commands to the jenkins build user in
      order to install some dependencies.

.. note:: The location of the Unit Test sources is
   ``$BASE_PATH/openrpd/rpd/testing/`` and all `testing` subfolders:

   .. code-block:: bash

      cd <OpenWRT>/package/feeds/openrpd/rpd/ find -name 'testing' -type d

   ::

      ./rcp/gcp/gcp_lib/testing
      ./rcp/gcp/testing
      ./rcp/rcp_lib/testing
      ./rcp/testing
      ./hal/testing
      ./dispatcher/testing
      ./confdb/testing
      ./testing

Discussion of Unit Testing
--------------------------

The current `run-unit-tests.sh` script patches and compiles Python costing a
considerable amount of time in the process. To speed up unit testing on your
development machine, you may wish to manually patch, compile, and install
Python once and then run the unit tests separately during development.

Individual Unit Tests
=====================

Individual unit test files can also be run. For example:

.. note:: Need to verify that this works (I can't get it to work)

.. code-block:: bash

   python rcp/rcp_lib/testing/test_rcp.py

Or:

.. code-block:: bash

   cd <OpenWRT>/package/feeds/openrpd/
   python -m unittest -v rpd.rcp.rcp_lib.testing.test_rcp

Unit Tests for a single class within a single file can be run. For example:

.. code-block:: bash

   python -m unittest -v rpd.rcp.rcp_lib.testing.test_rcp.TestRCPSpecifics

One specific Unit Test case can be run. For example:

.. code-block:: bash

   python -m unittest -v rpd.rcp.rcp_lib.testing.test_rcp.TestRCPSpecifics.test_tlv_data


RPD VM Manual Creation
======================

Manually creating an RPD Virtual Machine using the built VMDK:

After the OpenRPD build completes successfully, a .vmdk (virtual machine
hard disk) file should be in the `<OpenWRT>/bin/x86/` directory
(``openwrt-x86-generic-combined-ext4.vmdk``). This file can be used during
the creation of a Virtual Machine.

Using VirtualBox, select the option to create a New Machine. For the `OS
Type`, select `Linux` and for the `Version` select `Other Linux (32-bit)`.
For the Hard Disk, select the option to `Use an existing virtual hard disk
file`, and make sure to select the .vmdk that you have built.

One more critical configuration is Network section. You **MUST** define 2
networking interfaces:

* eth0 - Management Interface
* eth1 - Connection to the DHCP Server, Time Protocol Server, and CCAP Core


CCAP Core Emulator Build
========================

The process for checking out and building the CCAP Core Emulator VMDK is very
similar to the process for checking out and building the RPD.

.. tip:: You can skip steps 1 & 2 if you already checked out this repo to
   build/test the RPD.

1. Clone the OpenWRT repository using either the SSH or HTTP method:

   .. note:: The 'master' branch of this repository is a mirror of the
      `official OpenWRT repository`_, and you will need to check out the
      specified branch to receive the changes necessary for CCAP Core Emulator.

   .. _official OpenWRT repository: https://github.com/openwrt/openwrt

   a. **HTTP**:

      .. code-block:: bash
      
         git clone -b chaos_calmer_openrpd https://gerrit.cablelabs.com/openwrt

   b. **SSH**:

      .. code-block:: bash

         git clone -b chaos_calmer_openrpd ssh://gerrit.cablelabs.com:29418/openwrt

2. Navigate into the cloned repository directory:

   .. code-block:: bash
   
      cd openwrt

3. Execute the ``build.sh`` script with the ``core-sim`` argument:

   .. code-block:: bash

      ./build.sh core-sim

*************************
Running Integration Tests
*************************

Software Prerequisites
======================

* Install the following prerequisites that are required to run the OpenRPD
  integration tests:

  .. code-block:: bash

      sudo apt-get install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-paramiko sshpass
      sudo pip install paramiko==1.16.0
      sudo pip install scp

* Verify that the prerequisites were installed correctly by running:

  .. code-block:: bash

     kvm-ok

  You should see the results::

    INFO: /dev/kvm exists
    KVM acceleration can be used

  .. note:: If you are running Ubuntu as a VM in Fusion, you must check the
     box for `Enable hypervisor applications in this virtual machine`, under
     `Processors & Memory`/`Advanced options`

     Other VM platforms/hypervisors may have similar options to enable
     passthrough support of CPU hardware virtualization.

.. note:: If KVM is not supported in your environment, the Integration Tests
   can be run using QEMU by passing the ``--qemu`` flag to the integration
   test command.

* Add the user that will run the tests to the "libvirtd" group.  This can be
  accomplished by running a command similar to:

  .. code-block:: bash

     sudo usermod -a -G libvirtd <username>

  Group membership can be verified by running the command:

  .. code-block:: bash
   
     groups
   
  You should see "libvirtd" in the output.

Running Automated Integration Tests
===================================

The script for creating topologies is stored in the CCAP Core Emulator source
tree. It requires PYTHONPATH to point to a specific directory in the workspace:

.. code-block:: bash

   export PYTHONPATH=<CCAP_Core_Emulator_OpenWRT>/package/feeds/openrpd/

The script will copy the VMDK images to the current directory, convert them to
the required format (qcow2), and start the Virtual Machines.

.. note:: You will need approximately 75 MB per VM.  Please make sure that you
   have enough free disk space.

.. note:: If the user that will run the tests is NOT in the "libvirtd" group,
   then the tests will fail unless they are run under sudo.

To run all integration tests in the script, execute:

.. code-block:: bash

   cd $PYTHONPATH
   python -m rpd_service_suite.its_basic --rpd-image="<PATH_OF_RPD.vmdk>" --server-image="<PATH_OF_CORE_EMULATOR.vmdk>"

To run one test specified by name, execute:

.. code-block:: bash

   python -m rpd_service_suite.its_basic --rpd-image="<PATH_OF_RPD.vmdk>" --server-image="<PATH_OF_CORE_EMULATOR.vmdk>" --test=test_01_basic_init


Adding Integration Tests
------------------------

The test infrastructure is already prepared in the file::

  <CCAP_Core_Emulator_OpenWRT>/package/feeds/openrpd/rpd_service_suite/its_basic.py

New test cases can be created by adding new methods with names starting with a
``test_`` prefix.  For example:

.. code-block:: python

   def test_02_example(self):

.. tip:: Detailed information about the python unit test framework can be found
   at https://docs.python.org/2/library/unittest.html#test-cases

Python Integration Test Notes
-----------------------------

Starting VMs
^^^^^^^^^^^^

From python there are three ways of creating and starting VMs:

1. Create and start a VM in one step.  This will create, start and wait until
   the VM is ready:

   a. For a CCAP Core Emulator VM (currently referred to in the code as
      "Service Suite"):

      .. code-block:: python

         server = self.topology.create_vm_service_suite("ServiceSuite1")

   b. For a RPD VM:

      .. code-block:: python

         rpd = self.topology.create_vm_open_rpd("RPD1")

2. Create a VM and start it manually after some time:

   .. code-block:: python

      server = self.topology.create_vm_service_suite("ServiceSuite1", start=False)
      # <...do something...>
      self.topology.start_vm(server.name)

3. Create one or more VMs and start all of them at once. This can save some
   time (parallel booting), but note that sometimes it is necessary to have
   one machine ready before another.

   .. code-block:: python

      server = self.topology.create_vm_service_suite("ServiceSuite1", start=False)
      rpd = self.topology.create_vm_open_rpd("RPD1", start=False)
      self.topology.start_and_wait_for_all()

Sending Commands to VMs
^^^^^^^^^^^^^^^^^^^^^^^

There are two ways to communicate with VMs:

1. Using prepared messages:
   
   The supported format of messages is defined in the google protobuf file::

     <CCAP_Core_Emulator_OpenWRT>/package/feeds/openrpd/rpd/it_api/it_api_msgs.proto

   Message defined to control a CCAP Core Emulator VM::
   
     t_ItApiServiceSuiteMessage

   Message for a RPD VM::

     t_ItApiRpdMessage

   A populated message can be sent using::

     vm.vm_command(msg)

   *Examples*:

   **Get the contents of a DB from a RPD VM**::

     msg = t_ItApiRpdMessage()
     msg.ItApiRpdMessageType = msg.IT_API_RPD_GET
     reply = rpd_vm.vm_command(msg)

   **Enable the DHCPv4 service on a CCAP Core Emulator VM** (Some helper methods
   were added to simplify enabling/disabling services)::

     msg = t_ItApiServiceSuiteMessage()
     msg.MessageType = msg.IT_API_SERVICE_SUITE_CONFIGURE
     msg.ServiceConfigureMessage.DHCPv4.enable = True
     reply = server.vm_command(msg)

2. Using shell commands:
   
   The following method can be used to execute a command in a VM shell in
   order to get extra information outside of the RPD process::
   
     output = rpd.run_command("netstat -ln | grep '0.0.0.0:6000'")


Enabling/Disabling Services on CCAP Core Emulator VM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A helper method was created to simplify the configuration of services
(for now only disabling and enabling)::

  server.prepare_config_message()

*Examples*:

* Enable IPv4 specific services (tps is the TimeProtocol service, listening
  for both IPv4 and IPv6 requests)::
  
    msg = server.prepare_config_message(dhcpv4=True, tps=True, ccapv4=True)
    reply = server.vm_command(msg)

* Disable all services::

    msg = server.prepare_config_message(dhcpv4=False, dhcpv6=False tps=False, ccapv4=False, ccapv6=False)


Running Manual Integration Tests
--------------------------------

As with the Automated Integration Tests, the `PYTHONPATH` must point to a
specific directory in the CCAP Core Emulator workspace::
  
  export PYTHONPATH=<CCAP_Core_Emulator_OpenWRT>/package/feeds/openrpd/

  
Starting VMs
^^^^^^^^^^^^

The script will copy the VMDK images to the current directory, convert them to
the required format (qcow2), and start the Virtual Machines.

.. note:: You will need approximately 75 MB per VM.  Please make sure that
   you have enough free disk space.

The following python code will start one RPD VM::

  python -m rpd_service_suite.testing.test_topology --rpd-image="<PATH_OF_RPD.vmdk>"

The following python code will start multiple RPD VMs (the same or different
images can be used)::

  python -m rpd_service_suite.testing.test_topology --rpd-image="<PATH_OF_RPD.vmdk>" --rpd-image="<PATH_OF_RPD.vmdk>"
  
The following python code will start one RPD VM and one CCAP Core Emulator VM::

  python -m rpd_service_suite.testing.test_topology --rpd-image="<PATH_OF_RPD.vmdk>" --server-image="<PATH_OF_CORE_EMULATOR.vmdk>"

The following python code will start one RPD VM and one CCAP Core Emulator VM
with the eth1 IP address configured to some specific value (both ipv4 and ipv6
are supported)::

  python -m rpd_service_suite.testing.test_topology --rpd-image="<PATH_OF_RPD.vmdk>" --server-image="<PATH_OF_CORE_EMULATOR.vmdk>" --server-addr="192.168.5.2"

Booting up VMs takes some time (about 30 seconds). When they are ready, a new
terminal (one per VM) should open, and you should see output similar to the
following::

  ...
  2016-02-24
  13:42:31,315
  topology:run_command:338:DEBUG:Stderr:

  Topology should be ready, press anything to kill it

By pressing any key, the topology is destroyed and all created files are removed

Extra Options
`````````````

If something was not destroyed correctly (VM or network), an optional parameter
can be appended to kill all VMs and networks at the beginning::

  python -m rpd_service_suite.testing.test_topology --rpd-image="<PATH_OF_RPD.vmdk>" --destroy-before
  
To connect to VMs manually instead of opening terminals by the script (a list
of VMs with IP addresses will be printed)::

  python -m rpd_service_suite.testing.test_topology --rpd-image="<PATH_OF_RPD.vmdk>" --disable-terminal

Which should produce output similar to::

  ...
  2016-02-24
  12:57:29,055
  topology:run_command:338:DEBUG:Stderr: 

  VM:
  'RPD1':
  '192.168.122.83'
  
  VM:
  'RPD2':
  '192.168.122.75'
  
  VM:
  'server':
  '192.168.122.31'
  
  Topology should be ready, press anything to kill it

Basic Integration Test Logs
===========================

Console Output & Logfiles:

These files demonstrate the console and logfile output from a successful run
of the OpenRPD basic integration tests by the original Cisco developers.
Test were run on 3/22.  The software version used for the run should match
the initial baseline (created March 4, 2016) in the OpenRPD Gerrit repository.

  :download:`Console Output <files/Integration_Test_basics_success.txt>`

  :download:`OpenRPD VM logfile  <files/open_rpd.log>`


***************
Tips and Tricks
***************

Reboot Hold
===========

Set the environment variable ``PC_REBOOT_HOLD`` to ``true`` or ``1`` and the
manager will not reboot the device automatically.

.. code-block:: bash

  export PC_REBOOT_HOLD=1


