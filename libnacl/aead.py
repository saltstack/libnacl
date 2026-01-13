# -*- coding: utf-8 -*-
'''
Utilities to make secret box encryption simple
'''
# Import libnacl
import libnacl
import libnacl.utils
import libnacl.base

_DEFAULT_KEY_SIZE = libnacl.crypto_aead_chacha20poly1305_ietf_KEYBYTES


class AEAD(libnacl.base.BaseKey):
    '''
    Manage AEAD encryption using the IETF ChaCha20-Poly1305(default), AES-GCM, AEGIS128l or AEGIS256 algorithm
    If using AEGIS128l, you must set keysize to appropriate size, or use AEAD_AEGIS128L class.
    '''

    def __init__(self, key=None, keysize=_DEFAULT_KEY_SIZE):
        if key is None:
            if keysize == _DEFAULT_KEY_SIZE:
                key = libnacl.utils.aead_key()
            elif keysize == libnacl.crypto_aead_aegis128l_KEYBYTES:
                key = libnacl.utils.aead_aegis128l_key()

        self.sk = key
        if len(self.sk) != keysize:  # same size for both
            raise ValueError('Invalid key')
        self.usingAES = False
        self.usingXCHACHA = False
        self.usingAEGIS256 = False
        self.usingAEGIS128L = False
        super().__init__()

    def useAESGCM(self):
        self.usingAES = True
        if len(self.sk) != libnacl.crypto_aead_aes256gcm_KEYBYTES:  # same size for both
            raise ValueError('Invalid key')
        return self

    def useXCHACHA(self):
        self.usingXCHACHA = True
        if len(self.sk) != libnacl.crypto_aead_xchacha20poly1305_ietf_KEYBYTES:  # same size for both
            raise ValueError('Invalid key')
        return self

    def useAEGIS256(self):
        if len(self.sk) != libnacl.crypto_aead_aegis256_KEYBYTES:  # same size for both
            raise ValueError('Invalid key')
        self.usingAEGIS256 = True
        return self

    def useAEGIS128L(self):
        if len(self.sk) != libnacl.crypto_aead_aegis128l_KEYBYTES:  # same size for both
            raise ValueError('Invalid key')
        self.usingAEGIS128L = True
        return self

    def encrypt(self, msg, aad, nonce=None, pack_nonce_aad=True):
        '''
        Encrypt the given message. If a nonce is not given it will be
        generated via the rand_nonce function
        '''
        if nonce is None:
            if self.usingXCHACHA:
                nonce = libnacl.utils.rand_aead_xchacha_nonce()
            elif self.usingAEGIS256:
                nonce = libnacl.utils.rand_aead_aegis256_nonce()
            elif self.usingAEGIS128L:
                nonce = libnacl.utils.rand_aead_aegis128l_nonce()
            else:
                nonce = libnacl.utils.rand_aead_nonce()
        if self.usingXCHACHA:
            if len(nonce) != libnacl.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
                raise ValueError('Invalid nonce')
        elif self.usingAEGIS256:
            if len(nonce) != libnacl.crypto_aead_aegis256_NPUBBYTES:
                raise ValueError('Invalid nonce')
        elif self.usingAEGIS128L:
            if len(nonce) != libnacl.crypto_aead_aegis128l_NPUBBYTES:
                raise ValueError('Invalid nonce')
        else:
            if len(nonce) != libnacl.crypto_aead_aes256gcm_NPUBBYTES:
                raise ValueError('Invalid nonce')

        if self.usingXCHACHA:
            ctxt = libnacl.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, self.sk)
        elif self.usingAES:
            ctxt = libnacl.crypto_aead_aes256gcm_encrypt(msg, aad, nonce, self.sk)
        elif self.usingAEGIS256:
            ctxt = libnacl.crypto_aead_aegis256_encrypt(msg, aad, nonce, self.sk)
        elif self.usingAEGIS128L:
            ctxt = libnacl.crypto_aead_aegis128l_encrypt(msg, aad, nonce, self.sk)
        else:
            ctxt = libnacl.crypto_aead_chacha20poly1305_ietf_encrypt(msg, aad, nonce, self.sk)

        if pack_nonce_aad:
            return aad + nonce + ctxt
        else:
            return aad, nonce, ctxt

    def decrypt(self, ctxt, aadLen):
        '''
        Decrypt the given message, if no nonce or aad are given they will be
        extracted from the message
        '''
        aad = ctxt[:aadLen]
        if self.usingXCHACHA:
            nonce = ctxt[aadLen:aadLen+libnacl.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
            ctxt = ctxt[aadLen+libnacl.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:]
            if len(nonce) != libnacl.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
                raise ValueError('Invalid nonce')
        elif self.usingAEGIS256:
            nonce = ctxt[aadLen:aadLen+libnacl.crypto_aead_aegis256_NPUBBYTES]
            ctxt = ctxt[aadLen+libnacl.crypto_aead_aegis256_NPUBBYTES:]
            if len(nonce) != libnacl.crypto_aead_aegis256_NPUBBYTES:
                raise ValueError('Invalid nonce')
        elif self.usingAEGIS128L:
            nonce = ctxt[aadLen:aadLen+libnacl.crypto_aead_aegis128l_NPUBBYTES]
            ctxt = ctxt[aadLen+libnacl.crypto_aead_aegis128l_NPUBBYTES:]
            if len(nonce) != libnacl.crypto_aead_aegis128l_NPUBBYTES:
                raise ValueError('Invalid nonce')
        else:
            nonce = ctxt[aadLen:aadLen+libnacl.crypto_aead_aes256gcm_NPUBBYTES]
            ctxt = ctxt[aadLen+libnacl.crypto_aead_aes256gcm_NPUBBYTES:]
            if len(nonce) != libnacl.crypto_aead_aes256gcm_NPUBBYTES:
                raise ValueError('Invalid nonce')
        if self.usingXCHACHA:
            return libnacl.crypto_aead_xchacha20poly1305_ietf_decrypt(ctxt, aad, nonce, self.sk)
        if self.usingAES:
            return libnacl.crypto_aead_aes256gcm_decrypt(ctxt, aad, nonce, self.sk)
        if self.usingAEGIS256:
            return libnacl.crypto_aead_aegis256_decrypt(ctxt, aad, nonce, self.sk)
        if self.usingAEGIS128L:
            return libnacl.crypto_aead_aegis128l_decrypt(ctxt, aad, nonce, self.sk)
        return libnacl.crypto_aead_chacha20poly1305_ietf_decrypt(ctxt, aad, nonce, self.sk)

    def decrypt_unpacked(self, aad, nonce, ctxt):
        '''
        Decrypt the given message, if no nonce or aad are given they will be
        extracted from the message
        '''
        if len(nonce) != libnacl.crypto_aead_aes256gcm_NPUBBYTES:
            raise ValueError('Invalid nonce')
        if self.usingAES:
            return libnacl.crypto_aead_aes256gcm_decrypt(ctxt, aad, nonce, self.sk)
        if self.usingAEGIS256:
            return libnacl.crypto_aead_aegis256_decrypt(ctxt, aad, nonce, self.sk)
        if self.usingAEGIS128L:
            return libnacl.crypto_aead_aegis128l_decrypt(ctxt, aad, nonce, self.sk)
        return libnacl.crypto_aead_chacha20poly1305_ietf_decrypt(ctxt, aad, nonce, self.sk)


class AEAD_AESGCM(AEAD):
    def __init__(self, key=None):
        super().__init__(key)
        self.useAESGCM()


class AEAD_XCHACHA(AEAD):
    def __init__(self, key=None):
        super().__init__(key)
        self.useXCHACHA()


class AEAD_CHACHA(AEAD):
    def __init__(self, key=None):
        super().__init__(key)

class AEAD_AEGIS256(AEAD):
    def __init__(self, key=None):
        super().__init__(key)
        self.useAEGIS256()

class AEAD_AEGIS128L(AEAD):
    def __init__(self, key=None):
        super().__init__(key, keysize=libnacl.crypto_aead_aegis128l_KEYBYTES)
        self.useAEGIS128L()
