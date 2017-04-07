# Import libnacl libs
import libnacl.sealed
import libnacl.public

# Import python libs
import unittest

class TestSealed(unittest.TestCase):
    '''
    '''
    def test_secretkey(self):
        '''
        '''
        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        key = libnacl.public.SecretKey()
        box = libnacl.sealed.SealedBox(key)
        ctxt = box.encrypt(msg)
        self.assertNotEqual(msg, ctxt)
        bclear = box.decrypt(ctxt)
        self.assertEqual(msg, bclear)

    def test_publickey_only(self):
        '''
        '''
        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        key = libnacl.public.SecretKey()
        key_public = libnacl.public.PublicKey(key.pk)

        box = libnacl.sealed.SealedBox(key_public)
        ctxt = box.encrypt(msg)
        self.assertNotEqual(msg, ctxt)

        decrypting_box = libnacl.sealed.SealedBox(key)
        bclear = decrypting_box.decrypt(ctxt)
        self.assertEqual(msg, bclear)

