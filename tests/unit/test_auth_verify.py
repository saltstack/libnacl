# Import nacl libs
import libnacl
import libnacl.utils

# Import python libs
import unittest


class TestAuthVerify(unittest.TestCase):
    '''
    Test onetimeauth functions
    '''
    def test_auth_verify(self):
        msg = b'Anybody can invent a cryptosystem he cannot break himself. Except Bruce Schneier.'
        key1 = libnacl.utils.salsa_key()
        key2 = libnacl.utils.salsa_key()

        sig1 = libnacl.crypto_auth(msg, key1)
        sig2 = libnacl.crypto_auth(msg, key2)

        self.assertTrue(libnacl.crypto_auth_verify(sig1, msg, key1))
        self.assertTrue(libnacl.crypto_auth_verify(sig2, msg, key2))
        with self.assertRaises(ValueError) as context:
            libnacl.crypto_auth_verify(sig1, msg, key2)
        self.assertTrue('Failed to auth msg' in context.exception.args)

        with self.assertRaises(ValueError) as context:
            libnacl.crypto_auth_verify(sig2, msg, key1)
        self.assertTrue('Failed to auth msg' in context.exception.args)

    def test_onetimeauth_verify(self):
        msg = b'Anybody can invent a cryptosystem he cannot break himself. Except Bruce Schneier.'
        key1 = libnacl.utils.rand_nonce()
        key2 = libnacl.utils.rand_nonce()

        sig1 = libnacl.crypto_onetimeauth(msg, key1)
        sig2 = libnacl.crypto_onetimeauth(msg, key2)

        self.assertTrue(libnacl.crypto_onetimeauth_verify(sig1, msg, key1))
        self.assertTrue(libnacl.crypto_onetimeauth_verify(sig2, msg, key2))
        with self.assertRaises(ValueError) as context:
            libnacl.crypto_onetimeauth_verify(sig1, msg, key2)
        self.assertTrue('Failed to auth msg' in context.exception.args)

        with self.assertRaises(ValueError) as context:
            libnacl.crypto_onetimeauth_verify(sig2, msg, key1)
        self.assertTrue('Failed to auth msg' in context.exception.args)

