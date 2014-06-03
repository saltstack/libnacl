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

