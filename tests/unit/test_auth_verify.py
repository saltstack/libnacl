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

    def test_auth_rejects_wrong_lengths(self):
        msg = b'Time is an illusion. Lunchtime doubly so.'
        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_auth(msg, bad_key)
            self.assertEqual(context.exception.args, ('Invalid secret key',))

    def test_auth_verify_rejects_wrong_key_lengths(self):
        msg = b"I'd take the awe of understanding over the awe of ignorance any day."
        good_key = b'This valid key is 32 bytes long.'
        good_token = b'This token is likewise also 32B.'

        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_auth_verify(good_token, msg, bad_key)
            self.assertEqual(context.exception.args, ('Invalid secret key',))

        for bad_token in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_auth_verify(bad_token, msg, good_key)
            self.assertEqual(context.exception.args, ('Invalid authenticator',))

    def test_onetimeauth_rejects_wrong_lengths(self):
        msg = b"Are the most dangerous creatures the ones that use doors or the ones that don't?"
        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_onetimeauth(msg, bad_key)
            self.assertEqual(context.exception.args, ('Invalid secret key',))

    def test_onetimeauth_verify_rejects_wrong_key_lengths(self):
        msg = b"Of all the dogs I've known in my life, I've never seen a better driver."
        good_key = b'This valid key is 32 bytes long.'
        good_token = b'1time tokens=16B'

        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_onetimeauth_verify(good_token, msg, bad_key)
            self.assertEqual(context.exception.args, ('Invalid secret key',))

        for bad_token in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_onetimeauth_verify(bad_token, msg, good_key)
            self.assertEqual(context.exception.args, ('Invalid authenticator',))
