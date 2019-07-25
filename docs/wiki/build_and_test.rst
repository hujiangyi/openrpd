######################
OpenRPD Build and Test
######################

.. note:: These instructions are intended to be used for setting up a
   OpenRPD development environment on a Ubuntu 14.04 system (bare metal 
   or VM) only, however, OpenWRT (bare metal or VM) is a testing and 
   deployment environment for OpenRPD.

***********************************
Relationship of OpenRPD and OpenWRT
***********************************

OpenWRT is a small footprint adaptable Linux operating system. It is 
well-suited for hosting embedded applications in communications equipment.  
OpenRPD is installed in a OpenWRT virtual machine during the Jenkins 
continuous integration process.  This involves building OpenWRT from source 
code, then building the OpenRPD source code and installing it as a feed_ into 
the OpenWRT package, then making this OpenWRT package an virtual machine.  
Conversely, the CCAP emulator is also separately built and brought into a 
separate OpenWRT virtual machine as a feed_.

It is recommended that OpenRPD be enhanced and tested initially independent of 
the OpenWRT environment.  Once working suitably, it may be build as part of 
the OpenWRT package and tested against integration tests and CCAP core 
emulator VM or CCAP core hardware. 

This section of the document will take the reader the steps necessary to 
create having OpenRPT code in a locale development setting, and then 
running it through its Unit Test suite.

*********************************************
Base OpenRPD Development Environment Creation
*********************************************

Though the target deployment environment of OpenRPD is a 32-bit OpenWRT, 
development and test of OpenRPD is done in an Ubuntu 14.04 Desktop (AMD64) 
setting.  This can either be done on a dedicated development desktop system, 
or in a completely dedicated virtual machine which can sit atop any of a 
variety of host operating systems.

Oracle's VirtualBox is an open source well-established virtual machine 
environment for running the guest Ubuntu 14.04 operating system on top of 
Windows, Mac OS X, or a variety of Linux host machines.  It may be obtained 
at:  [https://www.virtualbox.org/wiki/Downloads]

It is recommended that the virtual machine that will receive the Ubuntu 14.04 
Linux OS be provisioned to have 4GB of memory and 50GB of disk storage, 
at a minimum.

The Installable live CDROM ISO file for AMD64 verion of the Ubuntu 14.04.5 
Desktop OS can be obtained 
at [https://www.ubuntu.com/download/alternative-downloads] or alternately:

.. code-block:: bash

   wget releases.ubuntu.com/14.04/ubuntu-14.04.5-desktop-amd64.iso 


All code examples from this place forward will be assumed to take place in the 
Ubuntu 14.04.5 Terminal command line application.

Installing Software Prerequisites
=================================

Git is not installed with the standard Ubuntu 14.04 environment.  It needs to be 
installed to obtain the OpenRPD source code.

.. code-block:: bash

  sudo apt-get install git-core


OpenRPD Check Out and Build
===========================

1. Clone the current OpenRPT source repository into the Ubuntu 14.04 
   environment

You may use either SSH or HTTP method (if you want to commit and push 
any changes back to the repository, you'll want to create 
(instructions at 
[https://www.howtoforge.com/linux-basics-how-to-install-ssh-keys-on-the-shell]) 
and register a public ssh key with the CableLabs gerrit server at 
[https://gerrit.cablelabs.com/#/settings/ssh-keys] and use the SSH method.


  a. **HTTP**:
     
     .. code-block:: bash

        git clone https://gerrit.cablelabs.com/openrpd

  b. **SSH**:

     .. code-block:: bash

        git clone ssh://[username@]gerrit.cablelabs.com:29418/openrpd


2.  Install Prerequisite Software and libraries for OpenRPD

.. code-block:: bash

   cd ~/openrpd
   sudo ./.jenkinsfile/configure_node.sh


3.  Build an augmented l2tp support form of the Python run-time interpreter 
    and install necessary Python modules

.. code-block:: bash

   ./.jenkinsfile/build_python.sh
   export PYTHONPATH=`pwd`/openrpd:`pwd`/openrpd/rpd/l2tp
   source /tmp/openrpd/venv/bin/activate


4.  Build OpenRPD

.. code-block:: bash

   cd openrpd
   make
   cd ..

5.  Run the Unit Test Suite for OpenRPD

.. code-block:: bash

   cd ~/openrpd
   time ./.jenkinsfile/run_unit_tests.sh 2>&1 | tee ~/openrpd-unittests-1.log

.. note:: After a shutdown and later restart of the Ubuntu 14.04 machine or 
   VM, should the contents of /tmp not be preserved from the earlier session, 
   you will need to re-execute steps 3 and 4 above.


RPD Unit Testing on the Build Machine
=====================================

.. attention:: As the build process is undergoing continuous improvements, 
   please see the ``openrpd/.jenkinsfile/run_unit_tests.sh`` shell script for 
   the latest build dependencies, process, and unit test procedure(s). This 
   script is executed as part of the Continuous Integration build process in 
   order to automatically verify new software patches to the project. The 
   Jenkins server runs the unit test script by cloning the openrpd repo and 
   executing ``./openrpd/.jenkinsfile/run_unit_tests.sh`` from the directory 
   root ``./openrpd``. Please note that the repo is named `openrpd` and there 
   is a folder in that directory called `openrpd` which contains the relevant 
   code. This may be confusing to humans but it was done to adapt to the 
   OpenRPD / OpenWRT build system.

If you would like to run the unit tests, please use an **Ubuntu 14.04 LTS**
machine and follow these steps:

.. note:: If running unit tests from the OpenWRT build directory, the
   `$BASE_PATH` will be the path of the OpenWRT repo plus `/package/feeds/`
   in the examples below (``<OpenWRT>/package/feeds/``). If building from the
   OpenRPD directory, the `$BASE_PATH` is the path of the OpenRPD repo. The
   recommended method is to use the command:

   .. code-block:: bash

      BASE_PATH="<OpenWRT or OpenRPD path>"

Due to the additional L2TP code, load the `l2tp_ip` kernel module into the OS.
Check if the L2TP modules have been loaded into the kernel with

   .. code-block:: bash

      lsmod | grep l2tp

If they are not present, load them with:

   .. code-block:: bash

      sudo modprobe l2tp_ip
      sudo modprobe l2tp_ip6

Run all Unit Tests
------------------

   .. note:: It is assumed that any unit tests are run after the python virtual 
      environment is installed by "openrpd/.jenkinsfile/build_python.sh" and 
      activated and that the PYTHONPATH environment variable is set by:

      .. code-block:: bash
      
         source /tmp/openrpd/venv/bin/activate
         export PYTHONPATH=`pwd`/openrpd:`pwd`/openrpd/rpd/l2tp

   .. code-block:: bash

      cd ~/openrpd
      time ./.jenkinsfile/run_unit_tests.sh 2>&1 | tee ~/unittests-all.log

   .. note:: The unit tests must NOT be run as root.


Run all Unit Tests in a test module
-----------------------------------

   .. code-block:: bash

      cd ~/openrpd/openrpd
      python rpd/rcp/testing/test_rcp_process.py

Or:

   .. code-block:: bash

      cd ~/openrpd/openrpd
      python -m unittest -v rpd.rcp.testing.test_rcp_process


Run all Unit Tests in a single class within a single file
---------------------------------------------------------

   .. code-block:: bash

      cd ~/openrpd/openrpd
      python -m unittest -v rpd.rcp.gcp.testing.test_VspAvps.L2tpHalDrvVspAvpTest

      
Run a specific Unit Test
------------------------

   .. code-block:: bash

      cd ~/openrpd/openrpd
      python -m unittest -v rpd.rcp.gcp.testing.test_VspAvps.L2tpHalDrvVspAvpTest.test_add_avp



************************************************************
OpenWRT Checkout and Build of OpenRPD from Repository Source
************************************************************

The RPD and the CCAP Core Emulator build from the same branch.
The essence of the OpenWRT build scripts is to add the OpenRPD project repo as a feed_
in the OpenWRT package management system, and to configure and install the
RPD-specific packages from that feed_.

.. _feed: https://wiki.openwrt.org/doc/devel/feeds

1. Clone the OpenWRT repository using either the SSH or HTTP method:

  a. **HTTP**:
     
     .. code-block:: bash

        git clone -b chaos_calmer_openrpd https://gerrit.cablelabs.com/openwrt

  b. **SSH**:

     .. code-block:: bash

        git clone -b chaos_calmer_openrpd ssh://[username@]gerrit.cablelabs.com:29418/openwrt

2. Navigate into the cloned repository directory:

   ``cd openwrt``

3. Execute the ``build.sh`` script with the ``vRPD`` parameter:

   .. note:: Running this script will clone the OpenRPD repository into the
      correct filesystem location inside of the OpenWRT directory tree.

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

   .. tip:: For informational purposes, here is a :download:`successful build 
      log <files/RPD_15.05_build_log.txt>`.

   .. _successful build log: ./files/RPD_15.05_build_log.txt

OpenRPD VirtualBox Virtual Machine Creation
===========================================

Manually creating an RPD Virtual Machine using the built VMDK:

After the OpenRPD build completes successfully, a .vmdk (virtual machine
hard disk) file should be in the `<OpenWRT>/bin/x86/` directory
(``openwrt-x86-generic-combined-ext4.vmdk``). This file can be used during
the creation of a Virtual Machine.  

   .. NOTE:: Recommend you rename this vmdk file to indicate that it is the
      OpenRPD payload on the OpenWRT Virtual Machine.

Using VirtualBox, select the option to create a New Machine. For the `OS
Type`, select `Linux` and for the `Version` select `Other Linux (32-bit)`.
For the Hard Disk, select the option to `Use an existing virtual hard disk
file`, and make sure to select the .vmdk that you have built.

One more critical configuration is Network section. You **MUST** define 2
networking interfaces:

* eth0 - Management Interface
* eth1 - Connection to the DHCP Server, Time Protocol Server, and CCAP Core

This same process is also how the CCAP Core Emulator VirtualBox Virtual Machine
is created.


*******************************************************************
OpenWRT Checkout and Build of OpenRPD from Local Development Source
*******************************************************************

The RPD and the CCAP Core Emulator now build from the same branch.
The essence of this form of the OpenWRT build scripts is to add the 
local development OpenRPD project as a linked source feed_
in the OpenWRT package management system, and to configure and install the
RPD-specific packages from that feed_.  This build

.. _feed: https://wiki.openwrt.org/doc/devel/feeds

1. Clone the OpenWRT repository using either the SSH or HTTP method:

  a. **HTTP**:
     
     .. code-block:: bash

        git clone -b chaos_calmer_openrpd https://gerrit.cablelabs.com/openwrt


  b. **SSH**:

     .. code-block:: bash

        git clone -b chaos_calmer_openrpd ssh://[username@]gerrit.cablelabs.com:29418/openwrt


2. Navigate into the cloned repository directory:

   ``cd openwrt``

3. Execute the OpenRPD source tree configure_build.sh script from this location
   with parmeters set to link in the local OpenRPD.  There are two arguments to
   this command: (a) the path to the root location of the local separate 
   OpenRPD code tree, and (b) the location of the OpenWRT build configuration 
   file. This example shows the process:

   .. code-block:: bash

      ../openrpd/.jenkinsfile/configure_build.sh /home/<myname>/openrpd ./build/x86/x86.conf

4. Once the OpenRPD source files are linked into the OpenWRT build tree, build 
   OpenWRT:

   .. code-block:: bash

      make


***********************************************
CCAP Core Emulator Build from Repository Source
***********************************************

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

         git clone -b chaos_calmer_openrpd ssh://[username@]gerrit.cablelabs.com:29418/openwrt

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


