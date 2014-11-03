# Import nacl libs
import libnacl

# Import python libs
import unittest


class TestGenericHash(unittest.TestCase):
    '''
    Test sign functions
    '''
    def test_keyless_generichash(self):
        msg1 = b'Are you suggesting coconuts migrate?'
        msg2 = b'Not at all, they could be carried.'
        chash1 = libnacl.crypto_generichash(msg1)
        chash2 = libnacl.crypto_generichash(msg2)
        self.assertNotEqual(msg1, chash1)
        self.assertNotEqual(msg2, chash2)
        self.assertNotEqual(chash2, chash1)
