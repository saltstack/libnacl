# -*- coding: utf-8 -*-
'''
Wrap libsodium routines
'''
# pylint: disable=C0103
# Import libnacl libs
from libnacl.version import __version__
# Import python libs
import ctypes
import sys
import os

__SONAMES = (18, 17, 13, 10, 5, 4)


def _get_nacl():
    '''
    Locate the nacl c libs to use
    '''
    # Import libsodium
    if sys.platform.startswith('win'):
        try:
            return ctypes.cdll.LoadLibrary('libsodium')
        except OSError:
            pass
        for soname_ver in __SONAMES:
            try:
                return ctypes.cdll.LoadLibrary(
                    'libsodium-{0}'.format(soname_ver)
                )
            except OSError:
                pass
        msg = 'Could not locate nacl lib, searched for libsodium'
        raise OSError(msg)
    elif sys.platform.startswith('darwin'):
        try:
            return ctypes.cdll.LoadLibrary('libsodium.dylib')
        except OSError:
            pass
        try:
            libidx = __file__.find('lib')
            if libidx > 0:
                libpath = __file__[0:libidx+3] + '/libsodium.dylib'
                return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            msg = 'Could not locate nacl lib, searched for libsodium'
            raise OSError(msg)
    else:
        try:
            return ctypes.cdll.LoadLibrary('libsodium.so')
        except OSError:
            pass
        try:
            return ctypes.cdll.LoadLibrary('/usr/local/lib/libsodium.so')
        except OSError:
            pass
        try:
            libidx = __file__.find('lib')
            if libidx > 0:
                libpath = __file__[0:libidx+3] + '/libsodium.so'
                return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            pass

        for soname_ver in __SONAMES:
            try:
                return ctypes.cdll.LoadLibrary(
                    'libsodium.so.{0}'.format(soname_ver)
                )
            except OSError:
                pass
        try:
            # fall back to shipped libsodium, trust os version first
            libpath = os.path.join(os.path.dirname(__file__), 'libsodium.so')
            return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            pass
        msg = 'Could not locate nacl lib, searched for libsodium.so, '
        for soname_ver in __SONAMES:
            msg += 'libsodium.so.{0}, '.format(soname_ver)
        raise OSError(msg)

nacl = _get_nacl()


# Define exceptions
class CryptError(Exception):
    """
    Base Exception for cryptographic errors
    """

sodium_init = nacl.sodium_init
sodium_init.res_type = ctypes.c_int
if sodium_init() < 0:
    raise RuntimeError('sodium_init() call failed!')

# Define constants
crypto_box_SECRETKEYBYTES = nacl.crypto_box_secretkeybytes()
crypto_box_SEEDBYTES = nacl.crypto_box_seedbytes()
crypto_box_PUBLICKEYBYTES = nacl.crypto_box_publickeybytes()
crypto_box_NONCEBYTES = nacl.crypto_box_noncebytes()
crypto_box_ZEROBYTES = nacl.crypto_box_zerobytes()
crypto_box_BOXZEROBYTES = nacl.crypto_box_boxzerobytes()
crypto_box_BEFORENMBYTES = nacl.crypto_box_beforenmbytes()
crypto_box_SEALBYTES = nacl.crypto_box_sealbytes()
crypto_scalarmult_BYTES = nacl.crypto_scalarmult_bytes()
crypto_scalarmult_SCALARBYTES = nacl.crypto_scalarmult_scalarbytes()
crypto_sign_BYTES = nacl.crypto_sign_bytes()
crypto_sign_SEEDBYTES = nacl.crypto_sign_secretkeybytes() // 2
crypto_sign_PUBLICKEYBYTES = nacl.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = nacl.crypto_sign_secretkeybytes()
crypto_box_MACBYTES = crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES
crypto_secretbox_KEYBYTES = nacl.crypto_secretbox_keybytes()
crypto_secretbox_NONCEBYTES = nacl.crypto_secretbox_noncebytes()
crypto_secretbox_ZEROBYTES = nacl.crypto_secretbox_zerobytes()
crypto_secretbox_BOXZEROBYTES = nacl.crypto_secretbox_boxzerobytes()
crypto_secretbox_MACBYTES = crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES
crypto_stream_KEYBYTES = nacl.crypto_stream_keybytes()
crypto_stream_NONCEBYTES = nacl.crypto_stream_noncebytes()
crypto_auth_BYTES = nacl.crypto_auth_bytes()
crypto_auth_KEYBYTES = nacl.crypto_auth_keybytes()
crypto_onetimeauth_BYTES = nacl.crypto_onetimeauth_bytes()
crypto_onetimeauth_KEYBYTES = nacl.crypto_onetimeauth_keybytes()
crypto_generichash_BYTES = nacl.crypto_generichash_bytes()
crypto_generichash_BYTES_MIN = nacl.crypto_generichash_bytes_min()
crypto_generichash_BYTES_MAX = nacl.crypto_generichash_bytes_max()
crypto_generichash_KEYBYTES = nacl.crypto_generichash_keybytes()
crypto_generichash_KEYBYTES_MIN = nacl.crypto_generichash_keybytes_min()
crypto_generichash_KEYBYTES_MAX = nacl.crypto_generichash_keybytes_max()
crypto_scalarmult_curve25519_BYTES = nacl.crypto_scalarmult_curve25519_bytes()
crypto_hash_BYTES = nacl.crypto_hash_sha512_bytes()
crypto_hash_sha256_BYTES = nacl.crypto_hash_sha256_bytes()
crypto_hash_sha512_BYTES = nacl.crypto_hash_sha512_bytes()
crypto_verify_16_BYTES = nacl.crypto_verify_16_bytes()
crypto_verify_32_BYTES = nacl.crypto_verify_32_bytes()
crypto_verify_64_BYTES = nacl.crypto_verify_64_bytes()
# pylint: enable=C0103


# Pubkey defs


def crypto_box_keypair():
    '''
    Generate and return a new keypair

    pk, sk = nacl.crypto_box_keypair()
    '''
    pk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_box_SECRETKEYBYTES)
    nacl.crypto_box_keypair(pk, sk)
    return pk.raw, sk.raw


def crypto_box(msg, nonce, pk, sk):
    '''
    Using a public key and a secret key encrypt the given message. A nonce
    must also be passed in, never reuse the nonce

    enc_msg = nacl.crypto_box('secret message', <unique nonce>, <public key string>, <secret key string>)
    '''
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError('Invalid public key')
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError('Invalid secret key')
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError('Invalid nonce')
    pad = b'\x00' * crypto_box_ZEROBYTES + msg
    c = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_box(c, pad, ctypes.c_ulonglong(len(pad)), nonce, pk, sk)
    if ret:
        raise CryptError('Unable to encrypt message')
    return c.raw[crypto_box_BOXZEROBYTES:]


def crypto_box_open(ctxt, nonce, pk, sk):
    '''
    Decrypts a message given the receivers private key, and senders public key
    '''
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError('Invalid public key')
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError('Invalid secret key')
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError('Invalid nonce')
    pad = b'\x00' * crypto_box_BOXZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_box_open(
            msg,
            pad,
            ctypes.c_ulonglong(len(pad)),
            nonce,
            pk,
            sk)
    if ret:
        raise CryptError('Unable to decrypt ciphertext')
    return msg.raw[crypto_box_ZEROBYTES:]


def crypto_box_beforenm(pk, sk):
    '''
    Partially performs the computation required for both encryption and decryption of data
    '''
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError('Invalid public key')
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError('Invalid secret key')
    k = ctypes.create_string_buffer(crypto_box_BEFORENMBYTES)
    ret = nacl.crypto_box_beforenm(k, pk, sk)
    if ret:
        raise CryptError('Unable to compute shared key')
    return k.raw


def crypto_box_afternm(msg, nonce, k):
    '''
    Encrypts a given a message, using partial computed data
    '''
    if len(k) != crypto_box_BEFORENMBYTES:
        raise ValueError('Invalid shared key')
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError('Invalid nonce')
    pad = b'\x00' * crypto_box_ZEROBYTES + msg
    ctxt = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_box_afternm(ctxt, pad, ctypes.c_ulonglong(len(pad)), nonce, k)
    if ret:
        raise CryptError('Unable to encrypt messsage')
    return ctxt.raw[crypto_box_BOXZEROBYTES:]


def crypto_box_open_afternm(ctxt, nonce, k):
    '''
    Decrypts a ciphertext ctxt given k
    '''
    if len(k) != crypto_box_BEFORENMBYTES:
        raise ValueError('Invalid shared key')
    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError('Invalid nonce')
    pad = b'\x00' * crypto_box_BOXZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_box_open_afternm(
            msg,
            pad,
            ctypes.c_ulonglong(len(pad)),
            nonce,
            k)
    if ret:
        raise CryptError('unable to decrypt message')
    return msg.raw[crypto_box_ZEROBYTES:]

def crypto_box_seal(msg, pk):
    '''
    Using a public key to encrypt the given message. The identity of the sender cannot be verified.

    enc_msg = nacl.crypto_box_seal('secret message', <public key string>)
    '''
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError('Invalid public key')
    if not isinstance(msg, bytes):
        raise TypeError('Message must be bytes')

    c = ctypes.create_string_buffer(len(msg) + crypto_box_SEALBYTES)
    ret = nacl.crypto_box_seal(c, msg, ctypes.c_ulonglong(len(msg)), pk)
    if ret:
        raise CryptError('Unable to encrypt message')
    return c.raw

def crypto_box_seal_open(ctxt, pk, sk):
    '''
    Decrypts a message given the receiver's public and private key.
    '''
    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError('Invalid public key')
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError('Invalid secret key')
    if not isinstance(ctxt, bytes):
        raise TypeError('Message must be bytes')
    
    c = ctypes.create_string_buffer(len(ctxt) - crypto_box_SEALBYTES)
    ret = nacl.crypto_box_seal_open(c, ctxt, ctypes.c_ulonglong(len(ctxt)), pk, sk)
    if ret:
        raise CryptError('Unable to decrypt message')
    return c.raw

# Signing functions


def crypto_sign_keypair():
    '''
    Generates a signing/verification key pair
    '''
    vk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    ret = nacl.crypto_sign_keypair(vk, sk)
    if ret:
        raise ValueError('Failed to generate keypair')
    return vk.raw, sk.raw


def crypto_sign(msg, sk):
    '''
    Sign the given message witht he given signing key
    '''
    sig = ctypes.create_string_buffer(len(msg) + crypto_sign_BYTES)
    slen = ctypes.pointer(ctypes.c_ulonglong())
    ret = nacl.crypto_sign(
            sig,
            slen,
            msg,
            ctypes.c_ulonglong(len(msg)),
            sk)
    if ret:
        raise ValueError('Failed to sign message')
    return sig.raw


def crypto_sign_seed_keypair(seed):
    '''
    Computes and returns the secret and verify keys from the given seed
    '''
    if len(seed) != crypto_sign_SEEDBYTES:
        raise ValueError('Invalid Seed')
    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    vk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)

    ret = nacl.crypto_sign_seed_keypair(vk, sk, seed)
    if ret:
        raise CryptError('Failed to generate keypair from seed')
    return (vk.raw, sk.raw)


def crypto_sign_open(sig, vk):
    '''
    Verifies the signed message sig using the signer's verification key
    '''
    msg = ctypes.create_string_buffer(len(sig))
    msglen = ctypes.c_ulonglong()
    msglenp = ctypes.pointer(msglen)
    ret = nacl.crypto_sign_open(
            msg,
            msglenp,
            sig,
            ctypes.c_ulonglong(len(sig)),
            vk)
    if ret:
        raise ValueError('Failed to validate message')
    return msg.raw[:msglen.value]  # pylint: disable=invalid-slice-index

# Authenticated Symmetric Encryption


def crypto_secretbox(message, nonce, key):
    """Encrypts and authenticates a message using the given secret key, and nonce

    Args:
        message (bytes): a message to encrypt
        nonce (bytes): nonce, does not have to be confidential must be
            `crypto_secretbox_NONCEBYTES` in length
        key (bytes): secret key, must be `crypto_secretbox_KEYBYTES` in
            length

    Returns:
        bytes: the ciphertext

    Raises:
        ValueError: if arguments' length is wrong or the operation has failed.
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise ValueError('Invalid key')

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise ValueError('Invalid nonce')

    pad = b'\x00' * crypto_secretbox_ZEROBYTES + message
    ctxt = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_secretbox(
        ctxt, pad, ctypes.c_ulonglong(len(pad)), nonce, key)
    if ret:
        raise ValueError('Failed to encrypt message')
    return ctxt.raw[crypto_secretbox_BOXZEROBYTES:]


def crypto_secretbox_open(ctxt, nonce, key):
    """
    Decrypts a ciphertext ctxt given the receivers private key, and senders
    public key
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise ValueError('Invalid key')

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise ValueError('Invalid nonce')

    pad = b'\x00' * crypto_secretbox_BOXZEROBYTES + ctxt
    msg = ctypes.create_string_buffer(len(pad))
    ret = nacl.crypto_secretbox_open(
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
    ret = nacl.crypto_stream(stream, ctypes.c_ulonglong(slen), nonce, key)
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
    ret = nacl.crypto_stream_xor(
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
    ret = nacl.crypto_auth(tok, msg, ctypes.c_ulonglong(len(msg)), key)
    if ret:
        raise ValueError('Failed to auth msg')
    return tok.raw[:crypto_auth_BYTES]


def crypto_auth_verify(tok, msg, key):
    '''
    Verifies that the given authentication token is correct for the given
    message and key
    '''
    ret = nacl.crypto_auth_verify(tok, msg, ctypes.c_ulonglong(len(msg)), key)
    if ret:
        raise ValueError('Failed to auth msg')
    return msg

# One time authentication


def crypto_onetimeauth_primitive():
    """
    Return the onetimeauth underlying primitive

    Returns:
        str: always ``poly1305``
    """
    func = nacl.crypto_onetimeauth_primitive
    func.restype = ctypes.c_char_p
    return func().decode()


def crypto_onetimeauth(message, key):
    """
    Constructs a one time authentication token for the given message using
    a given secret key

    Args:
        message (bytes): message to authenticate.
        key (bytes): secret key - must be of crypto_onetimeauth_KEYBYTES length.

    Returns:
        bytes: an authenticator, of crypto_onetimeauth_BYTES length.

    Raises:
        ValueError: if arguments' length is wrong.
    """
    if len(key) != crypto_onetimeauth_KEYBYTES:
        raise ValueError('Invalid secret key')

    tok = ctypes.create_string_buffer(crypto_onetimeauth_BYTES)
    # cannot fail
    _ = nacl.crypto_onetimeauth(
        tok, message, ctypes.c_ulonglong(len(message)), key)

    return tok.raw[:crypto_onetimeauth_BYTES]


def crypto_onetimeauth_verify(token, message, key):
    """
    Verifies, in constant time, that ``token`` is a correct authenticator for
    the message using the secret key.

    Args:
        token (bytes): an authenticator of crypto_onetimeauth_BYTES length.
        message (bytes): The message to authenticate.
        key: key (bytes): secret key - must be of crypto_onetimeauth_KEYBYTES
            length.

    Returns:
        bytes: secret key - must be of crypto_onetimeauth_KEYBYTES length.

    Raises:
        ValueError: if arguments' length is wrong or verification has failed.
    """
    if len(key) != crypto_onetimeauth_KEYBYTES:
        raise ValueError('Invalid secret key')
    if len(token) != crypto_onetimeauth_BYTES:
        raise ValueError('Invalid authenticator')

    ret = nacl.crypto_onetimeauth_verify(
        token, message, ctypes.c_ulonglong(len(message)), key)
    if ret:
        raise ValueError('Failed to auth message')
    return message

# Hashing


def crypto_hash(msg):
    '''
    Compute a hash of the given message
    '''
    hbuf = ctypes.create_string_buffer(crypto_hash_BYTES)
    nacl.crypto_hash(hbuf, msg, ctypes.c_ulonglong(len(msg)))
    return hbuf.raw


def crypto_hash_sha256(msg):
    '''
    Compute the sha256 hash of the given message
    '''
    hbuf = ctypes.create_string_buffer(crypto_hash_sha256_BYTES)
    nacl.crypto_hash_sha256(hbuf, msg, ctypes.c_ulonglong(len(msg)))
    return hbuf.raw


def crypto_hash_sha512(msg):
    '''
    Compute the sha512 hash of the given message
    '''
    hbuf = ctypes.create_string_buffer(crypto_hash_sha512_BYTES)
    nacl.crypto_hash_sha512(hbuf, msg, ctypes.c_ulonglong(len(msg)))
    return hbuf.raw

# Generic Hash


def crypto_generichash(msg, key=None):
    '''
    Compute the blake2 hash of the given message with a given key
    '''
    hbuf = ctypes.create_string_buffer(crypto_generichash_BYTES)
    if key:
        key_len = len(key)
    else:
        key_len = 0
    nacl.crypto_generichash(
            hbuf,
            ctypes.c_size_t(len(hbuf)),
            msg,
            ctypes.c_ulonglong(len(msg)),
            key,
            ctypes.c_size_t(key_len))
    return hbuf.raw

# scalarmult


def crypto_scalarmult_base(n):
    '''
    Computes and returns the scalar product of a standard group element and an
    integer "n".
    '''
    buf = ctypes.create_string_buffer(crypto_scalarmult_BYTES)
    ret = nacl.crypto_scalarmult_base(buf, n)
    if ret:
        raise CryptError('Failed to compute scalar product')
    return buf.raw

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
    return not nacl.crypto_verify_16(string1, string2)


def crypto_verify_32(string1, string2):
    '''
    Compares the first crypto_verify_32_BYTES of the given strings

    The time taken by the function is independent of the contents of string1
    and string2. In contrast, the standard C comparison function
    memcmp(string1,string2,32) takes time that is dependent on the longest
    matching prefix of string1 and string2. This often allows for easy
    timing attacks.
    '''
    return not nacl.crypto_verify_32(string1, string2)


def crypto_verify_64(string1, string2):
    '''
    Compares the first crypto_verify_64_BYTES of the given strings

    The time taken by the function is independent of the contents of string1
    and string2. In contrast, the standard C comparison function
    memcmp(string1,string2,64) takes time that is dependent on the longest
    matching prefix of string1 and string2. This often allows for easy
    timing attacks.
    '''
    return not nacl.crypto_verify_64(string1, string2)


def bytes_eq(a, b):
    '''
    Compares two byte instances with one another. If `a` and `b` have
    different lengths, return `False` immediately. Otherwise `a` and `b`
    will be compared in constant time.

    Return `True` in case `a` and `b` are equal. Otherwise `False`.

    Raises :exc:`TypeError` in case `a` and `b` are not both of the type
    :class:`bytes`.
    '''
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        raise TypeError('Both arguments must be bytes.')

    len_a = len(a)
    len_b = len(b)
    if len_a != len_b:
        return False

    return nacl.sodium_memcmp(a, b, len_a) == 0

# Random byte generation


def randombytes(size):
    '''
    Return a string of random bytes of the given size
    '''
    buf = ctypes.create_string_buffer(size)
    nacl.randombytes(buf, ctypes.c_ulonglong(size))
    return buf.raw


def randombytes_buf(size):
    '''
    Return a string of random bytes of the given size
    '''
    size = int(size)
    buf = ctypes.create_string_buffer(size)
    nacl.randombytes_buf(buf, size)
    return buf.raw


def randombytes_close():
    '''
    Close the file descriptor or the handle for the cryptographic service
    provider
    '''
    nacl.randombytes_close()


def randombytes_random():
    '''
    Return a random 32-bit unsigned value
    '''
    return nacl.randombytes_random()


def randombytes_stir():
    '''
    Generate a new key for the pseudorandom number generator

    The file descriptor for the entropy source is kept open, so that the
    generator can be reseeded even in a chroot() jail.
    '''
    nacl.randombytes_stir()


def randombytes_uniform(upper_bound):
    '''
    Return a value between 0 and upper_bound using a uniform distribution
    '''
    return nacl.randombytes_uniform(upper_bound)


# Utility functions

def sodium_library_version_major():
    '''
    Return the major version number
    '''
    return nacl.sodium_library_version_major()


def sodium_library_version_minor():
    '''
    Return the minor version number
    '''
    return nacl.sodium_library_version_minor()


def sodium_version_string():
    '''
    Return the version string
    '''
    func = nacl.sodium_version_string
    func.restype = ctypes.c_char_p
    return func()


def crypto_box_seed_keypair(seed):
    '''
    Computes and returns the public and secret keys from the given seed
    '''
    if len(seed) != crypto_box_SEEDBYTES:
        raise ValueError('Invalid Seed')
    pk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_box_SECRETKEYBYTES)

    ret = nacl.crypto_box_seed_keypair(pk, sk, seed)
    if ret:
        raise CryptError('Failed to generate keypair from seed')
    return (pk.raw, sk.raw)
