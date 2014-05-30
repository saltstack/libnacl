from distutils.core import setup

NAME = 'libnacl'
DESC = ('Python bindings for libsodium/tweetnacl based on ctypes')
VERSION = '0.9.0'

setup(name=NAME,
      version=VERSION,
      description=DESC,
      author='Thomas S Hatch',
      author_email='thatch45@gmail.com',
      url='https://github.com/thatch45/nacl',
      packages=['libnacl'])
