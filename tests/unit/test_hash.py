# Import nacl libs
import nacl

# Import python libs
import unittest


class TestSecretBox(unittest.TestCase):
    '''
    Test sign functions
    '''
    def test_hash(self):
        msg1 = b'Are you suggesting coconuts migrate?'
        msg2 = b'Not at all, they could be carried.'
        chash1 = nacl.crypto_hash(msg1)
        chash2 = nacl.crypto_hash(msg2)
        self.assertNotEqual(msg1, chash1)
        self.assertNotEqual(msg2, chash2)
        self.assertNotEqual(chash2, chash1)

