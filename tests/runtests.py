#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Import python libs
import os
import sys
import unittest

NACL_ROOT = os.path.abspath(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
UNIT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), 'unit'))

sys.path.insert(0, NACL_ROOT)


def run_suite(path=UNIT_ROOT):
    '''
    Execute the unttest suite
    '''
    loader = unittest.TestLoader()
    tests = loader.discover(path)
    unittest.TextTestRunner(verbosity=2).run(tests)



if __name__ == '__main__':
    run_suite()
