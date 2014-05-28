'''
Wrap libsodium routines
'''

# Import python libs
import ctypes
import sys

# Import libsodium
if sys.platform.startswith('win'):
    libnacl = ctypes.cdll.LoadLibrary('libsodium')
else:
    libnacl = ctypes.cdll.LoadLibrary('libsodium.so')

crypto_box_PUBLICKEYBYTES = 32L
crypto_box_SECRETKEYBYTES = 32L
crypto_box_BEFORENMBYTES = 32L
crypto_box_NONCEBYTES = 24L
crypto_box_ZEROBYTES = 32L
crypto_box_BOXZEROBYTES = 16L
crypto_box_MACBYTES = crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES
crypto_secretbox_KEYBYTES = 32L
crypto_secretbox_NONCEBYTES = 24L
crypto_secretbox_KEYBYTES = 32L
crypto_secretbox_ZEROBYTES = 32L
crypto_secretbox_BOXZEROBYTES = 16L
crypto_secretbox_MACBYTES = crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES
crypto_sign_PUBLICKEYBYTES = 32L
crypto_sign_SECRETKEYBYTES = 64L
crypto_sign_SEEDBYTES = 32L
crypto_stream_KEYBYTES = 32L
crypto_stream_NONCEBYTES = 24L
crypto_generichash_BYTES = 32L
crypto_scalarmult_curve25519_BYTES = 32L
crypto_scalarmult_BYTES = 32L
crypto_sign_BYTES = 64L

# Pubkey defs


def crypto_box_keypair():
    '''
    Generate and return a new keypair

    pk, sk = nacl.crypto_box_keypair()
    '''
    pk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    libnacl.crypto_box_keypair(pk, sk)
    return pk.raw, sk.raw


def crypto_box(msg, nonce, pk, sk):
    '''
    Using a public key and a secret key encrypt the given message. A nonce
    must also be passed in, never reuse the nonce

    enc_msg = nacl.crypto_box('secret message', <unique nonce>, <public key string>, <secret key string>)
    '''
    if None in (msg, nonce, pk, sk):
        raise ValueError('Invalid input')
    pad = b'\x00' * crypto_box_ZEROBYTES + msg
    c = ctypes.create_string_buffer(len(pad))
    ret = libnacl.crypto_box(c, pad, ctypes.c_ulonglong(len(pad)), nonce, pk, sk)
    if ret:
        raise ValueError('Unable to encrypt message')
    return c.raw[crypto_box_BOXZEROBYTES:]


def crypto_box_open(ctxt, nonce, pk, sk):
    '''
    Decrypts a message given the receivers private key, and senders public key
    '''
    if None in (ctxt, nonce, pk, sk):
        raise ValueError('Invalid input')
    pad = b'\x00' * crypto_box_BOXZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = libnacl.crypto_box_open(
            msg,
            pad,
            ctypes.c_ulonglong(len(pad)),
            nonce,
            pk,
            sk)
    if ret:
        raise ValueError('Unable to decrypt ciphertext')
    return msg.raw[crypto_box_ZEROBYTES:]


def crypto_box_beforenm(pk, sk):
    '''
    Partially performs the computation required for both encryption and decryption of data
    '''
    if None in (pk, sk):
        raise ValueError('Invalid input')
    k = ctypes.create_string_buffer(crypto_box_BEFORENMBYTES)
    libnacl.crypto_box_beforenm(k, pk, sk)
    return k.raw


def crypto_box_afternm(msg, nonce, k):
    '''
    Encrypts a given a message, using partial computed data
    '''
    pad = b'\x00' * crypto_box_ZEROBYTES + msg
    c = ctypes.create_string_buffer(len(pad))
    ret = libnacl.crypto_box_afternm(c, msg, ctypes.c_ulonglong(len(pad)), nonce, k)
    if ret:
        raise ValueError('Unable to encrypt messsage')
    return c.raw[crypto_box_BOXZEROBYTES:]


def crypto_box_open_afternm(ctxt, nonce, k):
    '''
    Decrypts a ciphertext ctxt given k
    '''
    pad = b'\x00' * crypto_box_ZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = libnacl.crypto_box_open_afternm(
            msg,
            ctxt,
            ctypes.c_ulonglong(len(pad)),
            nonce,
            k)
    if ret:
        raise ValueError('unable to decrypt message')
    return msg.raw[crypto_box_ZEROBYTES:]
