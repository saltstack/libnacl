# Import nacl libs
import libnacl

# Import python libs
import datetime
import binascii


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
    nonce = '{0:%Y%m%d%H%M%S%f}{1}'.format(
            datetime.datetime.now(),
            binascii.hexlify(libnacl.randombytes(2)).decode(encoding='UTF-8'))
    return nonce
