# Import nacl libs
import nacl
import nacl.utils

# Import python libs
import unittest


class TestSign(unittest.TestCase):
    '''
    Test sign functions
    '''
    def test_gen(self):
        vk1, sk1 = nacl.crypto_sign_keypair()
        vk2, sk2 = nacl.crypto_sign_keypair()
        vk3, sk3 = nacl.crypto_sign_keypair()
        self.assertEqual(len(vk1), nacl.crypto_sign_PUBLICKEYBYTES)
        self.assertEqual(len(sk1), nacl.crypto_sign_SECRETKEYBYTES)
        self.assertEqual(len(vk2), nacl.crypto_sign_PUBLICKEYBYTES)
        self.assertEqual(len(sk2), nacl.crypto_sign_SECRETKEYBYTES)
        self.assertEqual(len(vk3), nacl.crypto_sign_PUBLICKEYBYTES)
        self.assertEqual(len(sk3), nacl.crypto_sign_SECRETKEYBYTES)
        self.assertNotEqual(vk1, sk1)
        self.assertNotEqual(vk2, sk2)
        self.assertNotEqual(vk3, sk3)
        self.assertNotEqual(vk1, vk2)
        self.assertNotEqual(vk1, vk3)
        self.assertNotEqual(sk1, sk2)
        self.assertNotEqual(sk2, sk3)

    def test_box(self):
        msg = b'Are you suggesting coconuts migrate?'
        # run 1
        vk1, sk1 = nacl.crypto_sign_keypair()
        sig = nacl.crypto_sign(msg, sk1)
        self.assertEqual(msg, sig[nacl.crypto_sign_BYTES:])
        sig_msg = nacl.crypto_sign_open(sig, vk1)
        self.assertEqual(msg, sig_msg)
