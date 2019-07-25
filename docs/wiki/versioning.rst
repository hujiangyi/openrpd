Versioning
==========

When releasing a new version of OpenRPD, create two annotated tags_ on the
commit that signify the new version. Generally the new `dev` tag is .1 greater
than the `rel` tag.

The script that outputs versioning info is located in the `./jenkinsfile/`
directory.

.. _tags: https://git-scm.com/book/en/v2/Git-Basics-Tagging

.. code-block:: bash

   git tag -a rel-1.0.0 -m "Release version 1.0.0"
   git tag -a dev-1.1.0 -m "Development version 1.1.0"

Usage
-----

This information should be available on the Jenkins build console output and
artifacts, as well as the `show version` command from within OpenRPD.
