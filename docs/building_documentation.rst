######################
Building Documentation
######################

If you would rather read this documentation in HTML format instead of 
reStructuredText_ format, you can build this documentation using Sphinx_.

.. _reStructuredText: http://docutils.sourceforge.net/rst.html

.. _Sphinx: http://www.sphinx-doc.org/

.. note:: It is best to build the documentation from the same environment
   that builds and tests the software, since Sphinx reads the docstrings by
   loading all of the Python modules. This is why we *must* wrap any scripts
   in ``if __name__ == "__main__":`` statements, otherwise we risk hanging
   the documentation build process.


1. Install Sphinx on the workstation:

   .. code-block:: bash
   
      pip install sphinx

2. Change to the ``docs/`` directory.
3. Regenerate the `RST` source files and documentation:

   .. code-block:: bash

      rm -Rf source/
      sphinx-apidoc -o ./source ../openrpd/
      make html

4. ``index.html`` will be contained in ``_build/html/``.

.. note:: If sphinx hangs or runs into other issues, you may use
   the following verbose output to locate where things may have gone wrong:

   .. code-block:: bash

      sphinx-build -vvv ./ ./_build/html/
