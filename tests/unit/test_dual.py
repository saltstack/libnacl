# Import libnacl libs
import libnacl.public
import libnacl.dual

# Import python libs
import unittest

class TestDual(unittest.TestCase):
    '''
    '''
    def test_secretkey(self):
        '''
        '''
        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        bob = libnacl.dual.DualSecret()
        alice = libnacl.dual.DualSecret()
        bob_box = libnacl.public.Box(bob.sk, alice.pk)
        alice_box = libnacl.public.Box(alice.sk, bob.pk)
        bob_ctxt = bob_box.encrypt(msg)
        self.assertNotEqual(msg, bob_ctxt)
        bclear = alice_box.decrypt(bob_ctxt)
        self.assertEqual(msg, bclear)
        alice_ctxt = alice_box.encrypt(msg)
        self.assertNotEqual(msg, alice_ctxt)
        aclear = alice_box.decrypt(alice_ctxt)
        self.assertEqual(msg, aclear)
        self.assertNotEqual(bob_ctxt, alice_ctxt)

    def test_publickey(self):
        '''
        '''
        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        bob = libnacl.dual.DualSecret()
        alice = libnacl.dual.DualSecret()
        alice_pk = libnacl.public.PublicKey(alice.pk)
        bob_box = libnacl.public.Box(bob.sk, alice_pk)
        alice_box = libnacl.public.Box(alice.sk, bob.pk)
        bob_ctxt = bob_box.encrypt(msg)
        self.assertNotEqual(msg, bob_ctxt)
        bclear = alice_box.decrypt(bob_ctxt)
        self.assertEqual(msg, bclear)

    def test_sign(self):
        msg = (b'Well, that\'s no ordinary rabbit.  That\'s the most foul, '
               b'cruel, and bad-tempered rodent you ever set eyes on.')
        signer = libnacl.dual.DualSecret()
        signed = signer.sign(msg)
        signature = signer.signature(msg)
        self.assertNotEqual(msg, signed)
        veri = libnacl.sign.Verifier(signer.hex_vk())
        verified = veri.verify(signed)
        verified2 = veri.verify(signature + msg)
        self.assertEqual(verified, msg)
        self.assertEqual(verified2, msg)
