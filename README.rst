********
MiniAuth
********

MiniAuth is a small program (and a Python library) for user authentication,
providing an interface easy to integrate with other programs.

It's designed to be simple and portable.
MiniAuth is written in Python, supports Python versions 2.7 and Python 3.4+,
has no dependencies other than Python standard library.

.. code-block:: python

   >>> from miniauth.auth import MiniAuth
   >>> auth = MiniAuth('users.db')
   >>> auth.create_user('user', 'password')
   True
   >>> auth.verify_user('user', 'password')
   True
   >>> auth.verify_user('user', 'invalidpassword')
   False


A CLI tool helps to use a local database of users.

.. code-block::

   $ miniauth save testuser
   Password:
   $ miniauth verify testuser
   Password:


Installation
============

.. code-block:: bash

   $ pip install miniauth


Or installing from source:

.. code-block:: bash

   $ python setup.py install


Development
===========

Source code is on `GitHub <https://github.com/farzadghanei/miniauth>`_

In development/test environments `pytest <https://pypi.org/project/pytest/>`_, `mock <https://pypi.org/project/mock>`_
, `pycodestyle <https://pypi.org/project/pycodestyle/>`_ and `mypy <https://pypi.org/project/mypy/>`_ are required.


.. code-block:: bash

    # on dev/test env
    $ pip install -r requirements/dev.txt


Tests
-----

`Tox <https://pypi.org/project/tox/>`_ is most convenient to run tests with, since it handles virtualenvs

.. code-block:: bash

    $ tox

Or when development dependencies are installed (preferably with a virtual environment),
tests can be run by directly calling `pytest`.

.. code-block:: bash

    $ pytest


License
=======
MiniAuth is an open source project released under the terms of MIT license.

The MIT License (MIT)

Copyright (c) 2018-2019 Farzad Ghanei

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
