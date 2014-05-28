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
crypto_sign_BYTES = 64L
crypto_sign_PUBLICKEYBYTES = 32L
crypto_sign_SECRETKEYBYTES = 64L
crypto_sign_SEEDBYTES = 32L
crypto_box_MACBYTES = crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES
crypto_secretbox_KEYBYTES = 32L
crypto_secretbox_NONCEBYTES = 24L
crypto_secretbox_KEYBYTES = 32L
crypto_secretbox_ZEROBYTES = 32L
crypto_secretbox_BOXZEROBYTES = 16L
crypto_secretbox_MACBYTES = crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES
crypto_stream_KEYBYTES = 32L
crypto_stream_NONCEBYTES = 24L
crypto_auth_BYTES = 32L
crypto_auth_KEYBYTES = 32L
crypto_onetimeauth_BYTES = 16L
crypto_onetimeauth_KEYBYTES = 32L
crypto_generichash_BYTES = 32L
crypto_scalarmult_curve25519_BYTES = 32L
crypto_scalarmult_BYTES = 32L
crypto_hash_BYTES = 64

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

# Signing functions


def crypto_sign_keypair():
    '''
    Generates a signing/verification key pair
    '''
    vk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    ret = libnacl.crypto_sign_keypair(vk, sk)
    if ret:
        raise ValueError('Failed to generate keypair')
    return vk.raw, sk.raw


def crypto_sign(msg, sk):
    '''
    Sign the given message witht he given signing key
    '''
    sig = ctypes.create_string_buffer(len(msg) + crypto_sign_BYTES)
    slen = ctypes.pointer(ctypes.c_ulonglong())
    ret = libnacl.crypto_sign(sig, slen, msg, sk)
    if ret:
        raise ValueError('Failed to sign message')
    return sig.raw


def crypto_sign_open(sig, vk):
    '''
    Verifies the signed message sig using the signer's verification key
    '''
    msg = ctypes.create_string_buffer(len(sig))
    msglen = ctypes.c_ulonglong()
    msglenp = ctypes.pointer(msglen)
    ret = libnacl.crypto_sign_open(
            msg,
            msglenp,
            sig,
            ctypes.c_ulonglong(len(sig)),
            vk)
    if ret:
        raise ValueError('Failed to validate message')
    return msg.raw[:msglen.value]


# Authenticated Symmetric Encryption


def crypto_secretbox(msg, nonce, key):
    '''
    Encrypts and authenticates a message using the given secret key, and nonce
    '''
    pad = b'\x00' * crypto_secretbox_ZEROBYTES + msg
    ctxt = ctypes.create_string_buffer(len(pad))
    ret = libnacl.crypto_secretbox(ctxt, pad, ctypes.c_ulonglong(len(pad)), nonce, key)
    if ret:
        raise ValueError('Failed to encrypt message')
    return ctxt.raw[crypto_secretbox_BOXZEROBYTES:]


def crypto_secretbox_open(ctxt, nonce, key):
    '''
    Decrypts a ciphertext ctxt given the receivers private key, and senders
    public key
    '''
    pad = b'\x00' * crypto_secretbox_ZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = libnacl.crypto_secretbox_open(
            msg,
            pad,
            ctypes.c_ulonglong(len(pad)),
            nonce,
            key)
    if ret:
        raise ValueError('Failed to decrypt message')
    return msg.raw[crypto_secretbox_ZEROBYTES:]

# Symmetric Encryption


def crypto_stream(slen, nonce, key):
    '''
    Generates a stream using the given secret key and nonce
    '''
    stream = ctypes.create_string_buffer(slen)
    ret = libnacl.crypto_stream(stream, ctypes.c_ulonglong(slen), nonce, key)
    if ret:
        raise ValueError('Failed to init stream')
    return stream.raw


def crypto_stream_xor(msg, nonce, key):
    '''
    Encrypts the given message using the given secret key and nonce

    The crypto_stream_xor function guarantees that the ciphertext is the
    plaintext (xor) the output of crypto_stream. Consequently
    crypto_stream_xor can also be used to decrypt
    '''
    stream = ctypes.create_string_buffer(len(msg))
    ret = libnacl.crypto_stream_xor(
            stream,
            msg,
            ctypes.c_ulonglong(len(msg)),
            nonce,
            key)
    if ret:
        raise ValueError('Failed to init stream')
    return stream.raw


# Authentication


def crypto_auth(msg, key):
    '''
    Constructs a one time authentication token for the given message msg
    using a given secret key
    '''
    tok = ctypes.create_string_buffer(crypto_auth_BYTES)
    ret = libnacl.crypto_auth(tok, msg, len(msg), key)
    if ret:
        raise ValueError('Failed to auth msg')
    return tok.raw[:crypto_auth_BYTES]


def crypto_auth_verify(msg, key):
    '''
    Verifies that the given authentication token is correct for the given
    message and key
    '''
    tok = ctypes.create_string_buffer(crypto_auth_BYTES)
    ret = libnacl.crypto_auth_verify(tok, msg, len(msg), key)
    if ret:
        raise ValueError('Failed to auth msg')
    return tok.raw[:crypto_auth_BYTES]

# One time authentication


def crypto_onetimeauth(msg, key):
    '''
    Constructs a one time authentication token for the given message msg using
    a given secret key
    '''
    tok = ctypes.create_string_buffer(crypto_onetimeauth_BYTES)
    ret = libnacl.crypto_onetimeauth(tok, msg, len(msg), key)
    if ret:
        raise ValueError('Failed to auth msg')
    return tok.raw[:crypto_onetimeauth_BYTES]


def crypto_onetimeauth_verify(msg, key):
    '''
    Verifies that the given authentication token is correct for the given
    message and key
    '''
    tok = ctypes.create_string_buffer(crypto_onetimeauth_BYTES)
    ret = libnacl.crypto_onetimeauth(tok, msg, len(msg), key)
    if ret:
        raise ValueError('Failed to auth msg')
    return tok.raw[:crypto_onetimeauth_BYTES]

# Hashing


def crypto_hash(msg):
    '''
    Compute a hash of the given message
    '''
    hbuf = ctypes.create_string_buffer(crypto_hash_BYTES)
    libnacl.crypto_hash(hbuf, msg, len(msg))
    return hbuf.raw

# String cmp


def crypto_verify_16(string1, string2):
    '''
    Compares the first crypto_verify_16_BYTES of the given strings

    The time taken by the function is independent of the contents of string1
    and string2. In contrast, the standard C comparison function
    memcmp(string1,string2,16) takes time that is dependent on the longest
    matching prefix of string1 and string2. This often allows for easy
    timing attacks.
    '''
    return not libnacl.crypto_verify_16(string1, string2)


def crypto_verify_32(string1, string2):
    '''
    Compares the first crypto_verify_32_BYTES of the given strings

    The time taken by the function is independent of the contents of string1
    and string2. In contrast, the standard C comparison function
    memcmp(string1,string2,16) takes time that is dependent on the longest
    matching prefix of string1 and string2. This often allows for easy
    timing attacks.
    '''
    return not libnacl.crypto_verify_16(string1, string2)


# Random byte generation

def randombytes(size):
    '''
    Return a string of random bytes of the given size
    '''
    size = int(size)
    buf = ctypes.create_string_buffer(size)
    libnacl.randombytes(buf, size)
    return  buf


def randombytes_buf(size):
    '''
    Return a string of random bytes of the given size
    '''
    size = int(size)
    buf = ctypes.create_string_buffer(size)
    libnacl.randombytes_buf(buf, size)
    return  buf


def randombytes_close():
    '''
    Close the file descriptor or the handle for the cryptographic service
    provider
    '''
    libnacl.randombytes_close()


def randombytes_random():
    '''
    Return a random 32-bit unsigned value
    '''
    return libnacl.randombytes_random()


def randombytes_stir():
    '''
    Generate a new key for the pseudorandom number generator

    The file descriptor for the entropy source is kept open, so that the
    generator can be reseeded even in a chroot() jail.
    '''
    libnacl.randombytes_stir()


def randombytes_uniform(upper_bound):
    '''
    Return a value between 0 and upper_bound using a uniform distribution
    '''
    return libnacl.randombytes_uniform(upper_bound)

# Utility functions


def sodium_version_major():
    '''
    Return the major version number
    '''
    return libnacl.sodium_version_major()


def sodium_version_minor():
    '''
    Return the minor version number
    '''
    return libnacl.sodium_version_minor()


def sodium_version_string():
    '''
    Return the version string
    '''
    return libnacl.sodium_version_string()
