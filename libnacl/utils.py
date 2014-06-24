# -*- coding: utf-8 -*-

# Import nacl libs
import libnacl
import libnacl.encode

# Import python libs
import os
import time
import binascii


class BaseKey(object):
    '''
    Include methods for key management convenience
    '''
    def hex_sk(self):
        if hasattr(self, 'sk'):
            return libnacl.encode.hex_encode(self.sk)
        else:
            return ''

    def hex_pk(self):
        if hasattr(self, 'pk'):
            return libnacl.encode.hex_encode(self.pk)

    def hex_vk(self):
        if hasattr(self, 'vk'):
            return libnacl.encode.hex_encode(self.vk)

    def hex_seed(self):
        if hasattr(self, 'seed'):
            return libnacl.encode.hex_encode(self.seed)

    def save(self, path, serial='json'):
        '''
        Safely save keys with perms of 0400
        '''
        pre = {}
        sk = self.hex_sk()
        pk = self.hex_pk()
        vk = self.hex_vk()
        seed = self.hex_seed()
        if sk:
            pre['priv'] = sk
        if pk:
            pre['pub'] = pk
        if vk:
            pre['verify'] = vk
        if seed:
            pre['sign'] = seed
        if serial == 'msgpack':
            import msgpack
            packaged = msgpack.dumps(pre)
        elif serial == 'json':
            import json
            packaged = json.dumps(pre)
        cumask = os.umask(191)
        with open(path, 'w+') as fp_:
            fp_.write(packaged)
        os.umask(cumask)


def load_key(path, serial='json'):
    '''
    Read in a key from a file and return the applicable key object based on
    the contents of the file
    '''
    with open(path, 'rb') as fp_:
        packaged = fp_.read()
    if serial == 'msgpack':
        import msgpack
        key_data = msgpack.loads(packaged)
    elif serial == 'json':
        import json
        key_data = json.loads(packaged)
    if 'priv' and 'seed' in key_data:
        return libnacl.dual.DualSecret(
                libnacl.encode.hex_decode(key_data['priv']),
                libnacl.encode.hex_decode(key_data['seed']))
    elif 'priv' in key_data:
        return libnacl.public.SecretKey(
                libnacl.encode.hex_decode(key_data['priv']))
    elif 'sign' in key_data:
        return libnacl.sign.Signer(
                libnacl.encode.hex_decode(key_data['sign']))
    elif 'pub' in key_data:
        return libnacl.public.PublicKey(
                libnacl.encode.hex_decode(key_data['pub']))
    elif 'verify' in key_data:
        return libnacl.sign.Verifier(key_data['verify'])
    raise ValueError('Found no key data')


def salsa_key():
    '''
    Generates a salsa2020 key
    '''
    return libnacl.randombytes(libnacl.crypto_secretbox_KEYBYTES)


def time_nonce():
    '''
    Generates a safe nonce

    The nonce generated here is done by grabbing the 20 digit microsecond
    timestamp and appending 4 random chars
    '''
    nonce = '{0}{1}'.format(
            str(int(time.time() * 1000000)),
            binascii.hexlify(libnacl.randombytes(24)).decode(encoding='UTF-8'))
    return nonce.encode(encoding='UTF-8')[:libnacl.crypto_box_NONCEBYTES]
