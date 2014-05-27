'''
Wrap libsodium routines
'''

# Import python libs
import ctypes
import sys

# Import libsodium
if sys.platform.startswith('win'):
    libsodium = ctypes.cdll.LoadLibrary('libsodium')
else:
    libsodium = ctypes.cdll.LoadLibrary('libsodium.so')

crypto_box_NONCEBYTES = 24L
crypto_box_PUBLICKEYBYTES = 32L
crypto_box_SECRETKEYBYTES = 32L
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
