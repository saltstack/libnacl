# Import nacl libs
import nacl

# Import python libs
import time
import binascii


def salsa_key():
    '''
    Generates a salsa2020 key
    '''
    return nacl.randombytes(nacl.crypto_secretbox_KEYBYTES)


def time_nonce():
    '''
    Generates a safe nonce

    The nonce generated here is done by grabbing the 20 digit microsecond
    timestamp and appending 4 random chars
    '''
    nonce = '{0}{1}'.format(
            time.time(),
            binascii.hexlify(nacl.randombytes(4)))
    return nonce
