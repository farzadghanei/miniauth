********
MiniAuth
********

.. image:: https://travis-ci.org/farzadghanei/miniauth.svg?branch=master
    :target: https://travis-ci.org/farzadghanei/miniauth


MiniAuth is a small program (and a Python library) for user authentication.
with handy features, making it easy to use in different contexts and integrate with other programs.

MiniAuth is simple and portable, runs on Python versions 2.7 and Python 3.4+ and
has no dependencies other than Python standard library.

When the Python package is installed, the `miniauth` CLI entrypoint is provided to manage and use a local database of users,
using a SQLite backend.

Features:

* Passwords are stored salted and hashed. The hash is configurable per record, default is a secure choice (sha512)
* Supports enabling/disabling users
* Credentials can be specified in different ways: command line arguments, standard input, files
* When used as a Python library, a custom storage can be used instead of default SQLite storage

Here is how to create a user and password, then verifying the credentials:

.. code-block::

   $ miniauth save testuser
   Password:

   $ miniauth verify testuser
   Password:
   # exit codes report the result of verification


By default a SQLite DB file is created in current working directory named `miniauth.db`.
The path to this file can be configured with the `--storage` option.

When verifying the credentials, the password can be specified as an argument, or
read from standard input or a file.

.. code-block::

   $ miniauth --storage=user.db --verbose save testuser --password testpassword
   No DB detected on "user.db". Creating latest DB schema ...
   DB schema updated to version user.db on "1"
   created user testuser

   # read password from arguments
   $ miniauth --storage=user.db --verbose verify testuser testpassword
   user testuser credentials are correct

   # read password from a file
   $ cat file_with_password
   testpassword
   $ miniauth --storage=user.db --verbose verify testuser --password-file file_with_password
   user testuser credentials are correct

   # read username and password from a file
   $ cat file_with_creds
   testuser
   testpassword
   $ miniauth --storage=user.db --verbose verify --creds-file file_with_creds
   user testuser credentials are correct


Authenticating users can be done in other Python applications using miniauth as a library.

.. code-block:: python

   >>> from miniauth.auth import MiniAuth
   >>> auth = MiniAuth('users.db')
   >>> auth.create_user('user', 'password')
   True
   >>> auth.verify_user('user', 'password')
   True
   >>> auth.verify_user('user', 'invalidpassword')
   False


MiniAuth can use storage backends other than the default SQLite based one.
Storage classes should inherit `AbstractStorage` and implement the abstract methods.

.. code-block:: python

   >>> from miniauth.storage import AbstractStorage
   >>> class CustomStorage(AbstractStorage):
   ...      # implement abstract methods
   ...      pass
   >>> auth = MiniAuth('', CustomStorage())


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
