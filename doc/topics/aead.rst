=============================================
Authenticated Encryption with Associated Data
=============================================

One of the most powerful symmetric encryption models available i s known as AEAD.
The libsodium library enables four models of AEAD encryption. As of libnacl 2.0
we expose 3 of them.

Using AEAD with libnacl is very easy and can be executed following the same models
as the rest of libnacl.

The recommended algorithm to use is `XChaCha20-Poly1305-IETF`. Some organizations
require the use of AES, in these cases please use AESGCM.

For more information on AEAD please see the libsodium documentation

Using the AEAD system is very easy.

.. code-block:: python

    import libnacl.aead

    msg = b"Our King? Well i didn't vote for you!!"
    aad = b'\x00\x11\x22\x33'
    box = libnacl.aead.AEAD_XCHACHA()
    ctxt = box.encrypt(msg, aad)

    box2 = libnacl.aead.AEAD_XCHACHA(box.sk)
    clear1 = box.decrypt(ctxt, len(aad))

    ctxt2 = box2.encrypt(msg, aad)
    clear3 = box.decrypt(ctxt2, len(aad))

