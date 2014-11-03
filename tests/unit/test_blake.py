# Import nacl libs
import libnacl.blake

# Import python libs
import unittest


class TestBlake(unittest.TestCase):
    '''
    Test sign functions
    '''
    def test_keyless_blake(self):
        msg1 = b'Are you suggesting coconuts migrate?'
        msg2 = b'Not at all, they could be carried.'
        chash1 = libnacl.crypto_generichash(msg1)
        chash2 = libnacl.crypto_generichash(msg2)
        self.assertNotEqual(msg1, chash1)
        self.assertNotEqual(msg2, chash2)
        self.assertNotEqual(chash2, chash1)

    def test_key_blake(self):
        msg1 = b'Are you suggesting coconuts migrate?'
        msg2 = b'Not at all, they could be carried.'
        key1 = libnacl.utils.rand_nonce()
        key2 = libnacl.utils.rand_nonce()
        khash1_1 = libnacl.blake.Blake2b(msg1, key1).digest()
        khash1_1_2 = libnacl.blake.Blake2b(msg1, key1).digest()
        khash1_2 = libnacl.blake.Blake2b(msg1, key2).digest()
        khash2_1 = libnacl.blake.blake2b(msg2, key1).digest()
        khash2_2 = libnacl.blake.blake2b(msg2, key2).digest()
        self.assertNotEqual(msg1, khash1_1)
        self.assertNotEqual(msg1, khash1_2)
        self.assertNotEqual(msg2, khash2_1)
        self.assertNotEqual(msg2, khash2_2)
        self.assertNotEqual(khash1_1, khash1_2)
        self.assertNotEqual(khash2_1, khash2_2)
        self.assertNotEqual(khash1_1, khash2_1)
        self.assertNotEqual(khash1_2, khash2_2)
        self.assertEqual(khash1_1, khash1_1_2)
