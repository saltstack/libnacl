======================
Raw Message Signatures
======================

.. note::

    While these routines are perfectly safe, higher level convenience
    wrappers are under development to make these routines easier.

Signing messages ensures that the message itself has not been tampered with.
The application of a signature to a message is something that is is
automatically applied when using the public key encryption and is not a
required step when sending encrypted messages. This document however is
intended to illustrate how to sign plain text messages.

The nacl libs use a separate keypair for signing then is used for
public key encryption, it is a high performance key signing algorithm
called ed25519, more information on ed25519 can be found here:
http://ed25519.cr.yp.to/

The sign messages first generate a signing keypair, this constitutes the
signing key which needs to be kept secret, and the verify key which is
made available to message recipients.

.. code-block:: python

    import libnacl

    vk, sk = libnacl.crypto_sign_keypair()

With the signing keypair in hand a message can be signed:

.. code-block:: python

    msg = 'And that, my liege, is how we know the Earth to be banana-shaped.'
    signed = libnacl.crypto_sign(msg, sk)

The signed message is really just the plain text of the message prepended with
the signature. The crypto_sign_open function will read the signed message
and return me original message without the signature:

.. code-block:: python

    orig = libnacl.crypto_sign_open(signed, vk)

Put all together:

.. code-block:: python

    import libnacl

    vk, sk = libnacl.crypto_sign_keypair()
    
    msg = 'And that, my liege, is how we know the Earth to be banana-shaped.'
    signed = libnacl.crypto_sign(msg, sk)

    orig = libnacl.crypto_sign_open(signed, vk)
