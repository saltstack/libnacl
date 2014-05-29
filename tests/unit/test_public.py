# Import nacl libs
import nacl
import nacl.utils

# Import python libs
import unittest


class TestPublic(unittest.TestCase):
    '''
    Test public functions
    '''
    def test_gen(self):
        pk1, sk1 = nacl.crypto_box_keypair()
        pk2, sk2 = nacl.crypto_box_keypair()
        pk3, sk3 = nacl.crypto_box_keypair()
        self.assertEqual(len(pk1), nacl.crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(sk1), nacl.crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(pk2), nacl.crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(sk2), nacl.crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(pk3), nacl.crypto_box_PUBLICKEYBYTES)
        self.assertEqual(len(sk3), nacl.crypto_box_PUBLICKEYBYTES)
        self.assertNotEqual(pk1, sk1)
        self.assertNotEqual(pk2, sk2)
        self.assertNotEqual(pk3, sk3)
        self.assertNotEqual(pk1, pk2)
        self.assertNotEqual(pk1, pk3)
        self.assertNotEqual(sk1, sk2)
        self.assertNotEqual(sk2, sk3)

    def test_box(self):
        msg = b'Are you suggesting coconuts migrate?'
        # run 1
        nonce1 = nacl.utils.time_nonce()
        pk1, sk1 = nacl.crypto_box_keypair()
        pk2, sk2 = nacl.crypto_box_keypair()
        enc_msg = nacl.crypto_box(msg, nonce1, pk2, sk1)
        self.assertNotEqual(msg, enc_msg)
        clear_msg = nacl.crypto_box_open(enc_msg, nonce1, pk1, sk2)
        self.assertEqual(clear_msg, msg)
        # run 2
        nonce2 = nacl.utils.time_nonce()
        pk3, sk3 = nacl.crypto_box_keypair()
        pk4, sk4 = nacl.crypto_box_keypair()
        enc_msg2 = nacl.crypto_box(msg, nonce2, pk4, sk3)
        self.assertNotEqual(msg, enc_msg)
        clear_msg2 = nacl.crypto_box_open(enc_msg2, nonce2, pk3, sk4)
        self.assertEqual(clear_msg2, msg)
        # Check bits
        self.assertNotEqual(nonce1, nonce2)
        self.assertNotEqual(enc_msg, enc_msg2)

    # Needs more work on the nm routines
    def not_test_boxnm(self):
        msg = b'Are you suggesting coconuts migrate?'
        # run 1
        nonce1 = nacl.utils.time_nonce()
        pk1, sk1 = nacl.crypto_box_keypair()
        pk2, sk2 = nacl.crypto_box_keypair()
        k1 = nacl.crypto_box_beforenm(pk2, sk1)
        k2 = nacl.crypto_box_beforenm(pk1, sk2)
        enc_msg = nacl.crypto_box_afternm(msg, nonce1, k1)
        self.assertNotEqual(msg, enc_msg)
        clear_msg = nacl.crypto_box_open_afternm(enc_msg, nonce1, k2)
        self.assertEqual(clear_msg, msg)
