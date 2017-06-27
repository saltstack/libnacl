# Import libnacl libs
import libnacl.aead
# Import python libs
import unittest

class TestAEAD(unittest.TestCase):
    '''
    '''
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
        self.assertEqual(clear3, msg)
