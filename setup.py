#!/usr/bin/env python
"""
MiniAuth is a simple program (and a Python library) for local user
authentication.
"""
from setuptools import setup, find_packages
from miniauth import __version__


classifiers = [
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    "Programming Language :: Python",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 2.7",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.4",
    "Programming Language :: Python :: 3.5",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    'Programming Language :: Python :: Implementation :: CPython',
    'Programming Language :: Python :: Implementation :: PyPy',
    'Topic :: Software Development :: Libraries',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: Utilities',
]

long_description = __doc__
with open('README.rst', 'rb') as fh:
    long_description = fh.read().decode('utf-8', errors='ignore')

setup_params = dict(
    name='miniauth',
    packages=find_packages(exclude=['tests', 'tests.*']),
    version=__version__,
    description='Simple local user authentication',
    long_description=long_description,
    author='Farzad Ghanei',
    author_email='farzad.ghanei@gmail.com',
    url='https://github.com/farzadghanei/miniauth',
    license='MIT',
    classifiers=classifiers,
    keywords='auth userdb',
    test_suite='tests',
    zip_safe=True,
    entry_points=dict(
        console_scripts=['miniauth=miniauth.main:main']
    ),
)

setup_params["extras_require"] = {"dev": ["pytest", "mock", "typing", "pycodestyle"]}


if __name__ == '__main__':
    setup(**setup_params)
