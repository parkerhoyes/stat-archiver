#!/usr/bin/env python3

import sys

if not ((3, 6) <= sys.version_info < (4,)):
    raise RuntimeError('Unsupported Python version (Python 3.6+ required)')

import importlib.util

from setuptools import setup

version_spec = importlib.util.spec_from_file_location('version', 'src/statar/version.py')
version = importlib.util.module_from_spec(version_spec)
version_spec.loader.exec_module(version)
del version_spec

setup(
    name='statar',
    version=version.VERSION_STR,
    description='File attribute archiver utility',
    author='Parker Hoyes',
    author_email='contact@parkerhoyes.com',
    url='https://github.com/parkerhoyes/stat-archiver',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: zlib/libpng License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: System :: Archiving',
        'Topic :: Utilities',
    ],
    python_requires='>=3.6',
    packages=[
        'statar',
    ],
    package_dir={
        'statar': 'src/statar',
    },
    scripts=[
        'src/scripts/statar',
    ],
    include_package_data=True,
)
