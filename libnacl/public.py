'''
High level classes and routines around public key encryption and decryption
'''
# import libnacl libs
import libnacl
import libnacl.utils
import libnacl.encode


class PublicKey(libnacl.utils.BaseKey):
    '''
    This class is used to manage public keys
    '''
    def __init__(self, pk):
        self.pk = pk


class SecretKey(libnacl.utils.BaseKey):
    '''
    This class is used to manage keypairs
    '''
    def __init__(self, sk=None):
        '''
        If a secret key is not passed in then it will be generated
        '''
        if sk is None:
            self.sk, self.pk = libnacl.crypto_box_keypair()
        elif len(sk) == libnacl.crypto_box_SECRETKEYBYTES:
            self.sk = sk
            self.pk = libnacl.crypto_scalarmult_base(sk)
        else:
            raise ValueError('Passed in invalid secret key')


class Box(object):
    '''
    TheBox class is used to create cryptographic boxes and unpack
    cryptographic boxes
    '''
    def __init__(self, sk, pk):
        if isinstance(sk, SecretKey):
            sk = sk.sk
        if isinstance(pk, SecretKey):
            raise ValueError('Passed in secret key as public key')
        if isinstance(pk, PublicKey):
            pk = pk.pk
        if pk and sk:
            self._k = libnacl.crypto_box_beforenm(sk, pk)

    def encrypt(self, msg, nonce=None, pack_nonce=True):
        '''
        Encrypt the given message with the given nonce, if the nonce is not
        provided it will be generated from the libnacl.utils.time_nonce
        function
        '''
        if nonce is None:
            nonce = libnacl.utils.time_nonce()
        elif len(nonce) != libnacl.crypto_box_NONCEBYTES:
            raise ValueError('Invalid nonce size')
        ctxt = libnacl.crypto_box_afternm(msg, nonce, self._k)
        if pack_nonce:
            return nonce + ctxt
        else:
            return nonce, ctxt

    def decrypt(self, ctxt, nonce=None):
        '''
        Decrypt the given message, if a nonce is passed in attempt to decrypt
        it with the given nonce, otherwise assum that the nonce is attached
        to the message
        '''
        if nonce is None:
            nonce = ctxt[:libnacl.crypto_box_NONCEBYTES]
            ctxt = ctxt[libnacl.crypto_box_NONCEBYTES:]
        elif len(nonce) != libnacl.crypto_box_NONCEBYTES:
            raise ValueError('Invalid nonce')
        msg = libnacl.crypto_box_open_afternm(ctxt, nonce, self._k)
        return msg
