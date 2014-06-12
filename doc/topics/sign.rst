==============================
Signing and Verifying Messages
==============================

The nacl libs have the capability to sign and verify messages. Please be
advised that public key encrypted messages do not need to be signed, the
nacl box construct verifies the validity of the sender.

To sign and verify messages use the Signer and Verifier classes:

.. code-block:: python

    msg = (b'Well, that\'s no ordinary rabbit.  That\'s the most foul, '
           b'cruel, and bad-tempered rodent you ever set eyes on.')
    # Create a Signer Object, if the key seed value is not passed in the
    # signing keys will be automatically generated
    signer = libnacl.sign.Signer()
    # Sign the message, the signed string is the message itself plus the
    # signature
    signed = signer.sign(msg)
    # If only the signature is desired without the message:
    signature = signer.signature(msg)
    # To create a verifier pass in the verify key:
    veri = libnacl.sign.Verifier(signer.hex_vk())
    # Verify the message!
    verified = veri.verify(signed)
    verified2 = veri.verify(signature + msg)
