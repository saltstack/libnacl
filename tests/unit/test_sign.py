# Import libnacl libs
import libnacl.sign

# Import pythonlibs
import unittest


class TestSigning(unittest.TestCase):
    '''
    '''
    def test_sign(self):
        msg = (b'Well, that\'s no ordinary rabbit.  That\'s the most foul, '
               b'cruel, and bad-tempered rodent you ever set eyes on.')
        signer = libnacl.sign.Signer()
        signed = signer.sign(msg)
        signature = signer.signature(msg)
        self.assertNotEqual(msg, signed)
        veri = libnacl.sign.Verifier(signer.hex_vk())
        verified = veri.verify(signed)
        verified2 = veri.verify(signature + msg)
        self.assertEqual(verified, msg)
        self.assertEqual(verified2, msg)

    def test_key_decomposition(self):
        prv_key = b'The two halves are understood to'
        pub_key = b'be essentially arbitrary values.'
        secret_key = prv_key + pub_key
        # The following functions should simply decompose a secret key
        # without performing real computation. libsodium understands secret
        # keys to be (private seed bytes || derived public key bytes).
        self.assertEqual(prv_key, libnacl.crypto_sign_ed25519_sk_to_seed(secret_key))
        self.assertEqual(pub_key, libnacl.crypto_sign_ed25519_sk_to_pk(secret_key))

    def test_key_decomposition_rejects_wrong_key_lengths(self):
        """
        Too few bytes in a key passed through to libsodium will lead to bytes past the end
        of the string being read. We should be guarding against this dangerous case.
        """
        for test_func in (libnacl.crypto_sign_ed25519_sk_to_seed, libnacl.crypto_sign_ed25519_sk_to_pk):
            for bad_key in (b'too short', b'too long' * 100):
                with self.assertRaises(ValueError) as context:
                    test_func(bad_key)
                self.assertEqual(context.exception.args, ('Invalid secret key',))

    def test_sign_rejects_wrong_key_lengths(self):
        """
        Too few bytes in a key passed through to libsodium will lead to bytes past the end
        of the string being read. We should be guarding against this dangerous case.
        """
        msg = b'The message does not matter.'
        for test_func in (libnacl.crypto_sign, libnacl.crypto_sign_detached):
            for bad_key in (b'too short', b'too long' * 100):
                with self.assertRaises(ValueError) as context:
                    test_func(msg, bad_key)
                self.assertEqual(context.exception.args, ('Invalid secret key',))

    def test_open_rejects_wrong_key_lengths(self):
        """
        Too few bytes in a key passed through to libsodium will lead to bytes past the end
        of the string being read. We should be guarding against this dangerous case.
        """
        msg = b'The message does not matter.'
        good_key = b'This valid key is 32 bytes long.'
        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_sign_open(msg, bad_key)
            self.assertEqual(context.exception.args, ('Invalid public key',))

        with self.assertRaises(ValueError) as context:
            libnacl.crypto_sign_open(msg, good_key)
        self.assertEqual(context.exception.args, ('Failed to validate message',))

    def test_verify_detached_rejects_wrong_key_lengths(self):
        """
        Too few bytes in a key passed through to libsodium will lead to bytes past the end
        of the string being read. We should be guarding against this dangerous case.
        """
        msg = b'The message does not matter.'
        good_signature = b'This is a valid signature; it is 64 bytes long, no more, no less'
        good_key = b'This valid key is 32 bytes long.'
        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_sign_verify_detached(good_signature, msg, bad_key)
            self.assertEqual(context.exception.args, ('Invalid public key',))

        for bad_signature in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_sign_verify_detached(bad_signature, msg, good_key)
            self.assertEqual(context.exception.args, ('Invalid signature',))

        with self.assertRaises(ValueError) as context:
            libnacl.crypto_sign_verify_detached(good_signature, msg, good_key)
        self.assertEqual(context.exception.args, ('Failed to validate message',))
