# Import libnacl libs
import libnacl.sign

# Import pythonlibs
import unittest


class TestStream(unittest.TestCase):
    def test_stream_rejects_wrong_lengths(self):
        """
        Too few bytes in a key or nonce passed through to libsodium will lead to bytes past the end
        of the string being read. We should be guarding against this dangerous case.
        """
        msg_len = 100  # whatever
        good_nonce= b'Nonces must be 24 bytes.'
        good_key = b'This valid key is 32 bytes long.'
        for bad_nonce in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_stream(msg_len, bad_nonce, good_key)
            self.assertEqual(context.exception.args, ('Invalid nonce',))

        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_stream(msg_len, good_nonce, bad_key)
            self.assertEqual(context.exception.args, ('Invalid secret key',))

    def test_stream_xor_rejects_wrong_lengths(self):
        """
        Too few bytes in a key or nonce passed through to libsodium will lead to bytes past the end
        of the string being read. We should be guarding against this dangerous case.
        """
        msg = b'The message does not matter.'
        good_nonce = b'Nonces must be 24 bytes.'
        good_key = b'This valid key is 32 bytes long.'
        for bad_nonce in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_stream_xor(msg, bad_nonce, good_key)
            self.assertEqual(context.exception.args, ('Invalid nonce',))

        for bad_key in (b'too short', b'too long' * 100):
            with self.assertRaises(ValueError) as context:
                libnacl.crypto_stream_xor(msg, good_nonce, bad_key)
            self.assertEqual(context.exception.args, ('Invalid secret key',))
