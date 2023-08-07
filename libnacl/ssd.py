"""
This module presents classes that allow for "Signed, sealed, delivered" encryption.

The SSD system uses signing keys for identification verification, then packs exchange
keys in sucha way that the signed exchange keys can be used to generate a session
key used to encrypt the body of a message with AEAD encryption
"""

import Signer from libnacl.sign
import ExchangeKey from libnacl.kx


# 1. Serialize the message
# 2. Sign the message
# 3. Create the header/ad (verifier identity, client/server mode for AEAD, kx_pk)
# 4. Encrypt the signed message and ad with AEAD

# 1. Get the protocol data from the ad
# 2. Decrypt the message per the ad data
# 3. Veirfy the message with the verify key

class SSD(Signer, ExchangeKey):
    def __init__(self, seed=None, kx_sx=None, enc=None):
        Signer.__init__(seed)
        ExchangeKey.__init__(kx_sk, enc)
