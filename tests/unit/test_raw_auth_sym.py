# Import nacl libs
import libnacl
import libnacl.utils

# Import python libs
import unittest


class TestSecretBox(unittest.TestCase):
    '''
    Test sign functions
    '''
    def test_secret_box(self):
        msg = b'Are you suggesting coconuts migrate?'
        sk1 = libnacl.utils.salsa_key()
        nonce1 = libnacl.utils.rand_nonce()
        enc_msg = libnacl.crypto_secretbox(msg, nonce1, sk1)
        self.assertNotEqual(msg, enc_msg)
        clear_msg = libnacl.crypto_secretbox_open(enc_msg, nonce1, sk1)
        self.assertEqual(msg, clear_msg)
