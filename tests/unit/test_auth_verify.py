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
        self.assertEqual("poly1305", libnacl.crypto_onetimeauth_primitive())

        msg = b'Anybody can invent a cryptosystem he cannot break himself. Except Bruce Schneier.'
        key1 = libnacl.randombytes(libnacl.crypto_onetimeauth_KEYBYTES)
        key2 = libnacl.randombytes(libnacl.crypto_onetimeauth_KEYBYTES)

        sig1 = libnacl.crypto_onetimeauth(msg, key1)
        sig2 = libnacl.crypto_onetimeauth(msg, key2)

        with self.assertRaises(ValueError):
            libnacl.crypto_onetimeauth(msg, b'too_short')

        with self.assertRaises(ValueError):
            libnacl.crypto_onetimeauth_verify(sig1, msg, b'too_short')

        with self.assertRaises(ValueError):
            libnacl.crypto_onetimeauth_verify(b'too_short', msg, key1)

        self.assertTrue(libnacl.crypto_onetimeauth_verify(sig1, msg, key1))
        self.assertTrue(libnacl.crypto_onetimeauth_verify(sig2, msg, key2))
        with self.assertRaises(ValueError) as context:
            libnacl.crypto_onetimeauth_verify(sig1, msg, key2)
        self.assertTrue('Failed to auth message' in context.exception.args)

        with self.assertRaises(ValueError) as context:
            libnacl.crypto_onetimeauth_verify(sig2, msg, key1)
        self.assertTrue('Failed to auth message' in context.exception.args)

