#################
Building manually
#################

Configure all necessary dependencies for building OpenRPD

.. code-block:: bash

   git clone ssh://gerrit.cablelabs.com:29418/openrpd
   cd ~/openrpd

.. code-block:: bash

   sudo ./.jenkinsfile/configure_node.sh

Build Python from source (from root of openrpd repo)

.. code-block:: bash

   ./.jenkinsfile/build_python.sh

Make OpenRPD (from root of openrpd repo)

.. code-block:: bash

   source /tmp/openrpd/venv/bin/activate
   cd openrpd
   make
   cd ..

Run unit tests (from root of openrpd repo)

.. code-block:: bash

   source /tmp/openrpd/venv/bin/activate
   export PYTHONPATH=`pwd`/openrpd:`pwd`/openrpd/rpd/l2tp
   ./.jenkinsfile/run_unit_tests.sh
