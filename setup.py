#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

if 'USE_SETUPTOOLS' in os.environ or 'setuptools' in sys.modules:
    from setuptools import setup
else:
    from distutils.core import setup

NAME = 'libnacl'
DESC = ('Python bindings for libsodium/tweetnacl based on ctypes')
VERSION = '0.9.1'

setup(name=NAME,
      version=VERSION,
      description=DESC,
      author='Thomas S Hatch',
      author_email='thatch45@gmail.com',
      url='https://github.com/thatch45/nacl',
      classifiers=[
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.4',
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Topic :: Security :: Cryptography',
          ],
      packages=['libnacl'])
