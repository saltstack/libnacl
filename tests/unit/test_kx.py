# Import libnacl libs
import libnacl.kx

# Import python libs
import unittest

class TestKX(unittest.TestCase):
    '''
    '''
    def test_exchange_key(self):
        '''
        '''
        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        aad = b'A Duck!'
        # Make Bob and Alice Exchange Keys
        bob = libnacl.kx.ExchangeKey()
        alice = libnacl.kx.ExchangeKey()
        # Encrypt with bob as clientm alic as server
        bob_ctxt = bob.encrypt_client(alice.kx_pk, msg, aad)
        self.assertNotEqual(msg, bob_ctxt)
        bclear, clear_aad = alice.decrypt_server(bob.kx_pk, bob_ctxt, len(aad))
        self.assertEqual(aad, clear_aad)
        self.assertEqual(msg, bclear)
        alice_ctxt = alice.encrypt_server(bob.kx_pk, msg, aad)
        aclear, aad = bob.decrypt_client(alice.kx_pk, alice_ctxt, len(aad))
        self.assertEqual(aad, clear_aad)
        self.assertEqual(msg, aclear)
        self.assertNotEqual(msg, alice_ctxt)
        # Encrypt with Alice as client bob as server
        alice_ctxt = alice.encrypt_client(bob.kx_pk, msg, aad)
        self.assertNotEqual(msg, alice_ctxt)
        bclear, aad = bob.decrypt_server(alice.kx_pk, alice_ctxt, len(aad))
        self.assertEqual(aad, clear_aad)
        self.assertEqual(msg, bclear)

