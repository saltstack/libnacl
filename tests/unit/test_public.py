# Import libnacl libs
import libnacl.public

# Import python libs
import unittest

class TestPublic(unittest.TestCase):
    '''
    '''
    def test_secretkey(self):
        '''
        '''
        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        bob = libnacl.public.SecretKey()
        alice = libnacl.public.SecretKey()
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
        bob = libnacl.public.SecretKey()
        alice = libnacl.public.SecretKey()
        alice_pk = libnacl.public.PublicKey(alice.pk)
        bob_box = libnacl.public.Box(bob.sk, alice_pk)
        alice_box = libnacl.public.Box(alice.sk, bob.pk)
        bob_ctxt = bob_box.encrypt(msg)
        self.assertNotEqual(msg, bob_ctxt)
        bclear = alice_box.decrypt(bob_ctxt)
        self.assertEqual(msg, bclear)

