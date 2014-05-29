# Import nacl libs
import nacl
import nacl.utils

# Import python libs
import unittest


class TestSecretBox(unittest.TestCase):
    '''
    Test sign functions
    '''
    def test_secret_box(self):
        msg = b'Are you suggesting coconuts migrate?'
        sk1 = nacl.utils.salsa_key()
        nonce1 = nacl.utils.time_nonce()
        enc_msg = nacl.crypto_secretbox(msg, nonce1, sk1)
        self.assertNotEqual(msg, enc_msg)
        clear_msg = nacl.crypto_secretbox_open(enc_msg, nonce1, sk1)
        self.assertEqual(msg, clear_msg)
