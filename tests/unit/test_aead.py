# Import libnacl libs
import libnacl.aead
# Import python libs
import unittest

class TestAEAD(unittest.TestCase):
    '''
    '''
    @unittest.skipUnless(libnacl.HAS_AEAD_AES256GCM, 'AES256-GCM AEAD not available')
    def test_gcm_aead(self):
        msg = b"You've got two empty halves of coconuts and your bangin' 'em together."
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD().useAESGCM()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD(box.sk).useAESGCM()
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)

    @unittest.skipUnless(libnacl.HAS_AEAD_AES256GCM, 'AES256-GCM AEAD not available')
    def test_gcm_aead_class(self):
        msg = b"You've got two empty halves of coconuts and your bangin' 'em together."
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD_AESGCM()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD_AESGCM(box.sk)
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)

    @unittest.skipUnless(libnacl.HAS_AEAD_CHACHA20POLY1305_IETF, 'IETF variant of ChaCha20Poly1305 AEAD not available')
    def test_ietf_aead(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD(box.sk)
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))

    @unittest.skipUnless(libnacl.HAS_AEAD_CHACHA20POLY1305_IETF, 'IETF variant of ChaCha20Poly1305 AEAD not available')
    def test_ietf_aead_class(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD_CHACHA()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD_CHACHA(box.sk)
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))

    @unittest.skipUnless(libnacl.HAS_AEAD_XCHACHA20POLY1305_IETF, 'IETF variant of xChaCha20Poly1305 AEAD not available')
    def test_ietf_aead_xchacha(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD().useXCHACHA()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD(box.sk).useXCHACHA()
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)
        self.assertEqual(clear3, msg)


    @unittest.skipUnless(libnacl.HAS_AEAD_XCHACHA20POLY1305_IETF, 'IETF variant of xChaCha20Poly1305 AEAD not available')
    def test_ietf_aead_xchacha_class(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD_XCHACHA()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD_XCHACHA(box.sk)
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)
        self.assertEqual(clear3, msg)


    @unittest.skipUnless(libnacl.HAS_AEAD_AEGIS256, 'AEAD AEGIS256 not available')
    def test_ietf_aead_aegis256(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD().useAEGIS256()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD(box.sk).useAEGIS256()
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)
        self.assertEqual(clear3, msg)


    @unittest.skipUnless(libnacl.HAS_AEAD_AEGIS256, 'AEAD AEGIS256 not available')
    def test_ietf_aead_aegis256_class(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD_AEGIS256()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD_AEGIS256(box.sk)
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)
        self.assertEqual(clear3, msg)

    @unittest.skipUnless(libnacl.HAS_AEAD_AEGIS128L, 'AEAD AEGIS128L not available')
    def test_ietf_aead_aegis128l(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD(keysize=libnacl.crypto_aead_aegis128l_KEYBYTES).useAEGIS128L()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD(box.sk,keysize=libnacl.crypto_aead_aegis128l_KEYBYTES).useAEGIS128L()
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)
        self.assertEqual(clear3, msg)


    @unittest.skipUnless(libnacl.HAS_AEAD_AEGIS128L, 'AEAD AEGIS128L not available')
    def test_ietf_aead_aegis128l_class(self):
        msg = b"Our King? Well i didn't vote for you!!"
        aad = b'\x00\x11\x22\x33'
        box = libnacl.aead.AEAD_AEGIS128L()
        ctxt = box.encrypt(msg, aad)
        self.assertNotEqual(msg, ctxt)

        box2 = libnacl.aead.AEAD_AEGIS128L(box.sk)
        clear1 = box.decrypt(ctxt, len(aad))
        self.assertEqual(msg, clear1)
        clear2 = box2.decrypt(ctxt, len(aad))
        self.assertEqual(clear1, clear2)
        ctxt2 = box2.encrypt(msg, aad)
        clear3 = box.decrypt(ctxt2, len(aad))
        self.assertEqual(clear3, msg)
        self.assertEqual(clear3, msg)
