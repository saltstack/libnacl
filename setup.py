from distutils.core import setup

NAME = 'nacl'
DESC = ('A ctypes based libsodium wrapper')
VERSION = '0.1.0'

setup(name=NAME,
      version=VERSION,
      description=DESC,
      author='Thomas S Hatch',
      author_email='thatch45@gmail.com',
      url='https://github.com/thatch45/nacl',
      packages=['nacl'])
