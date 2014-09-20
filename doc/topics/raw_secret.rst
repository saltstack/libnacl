=========================
Raw Secret Key Encryption
=========================

.. note::

    While these routines are perfectly safe, higher level convenience
    wrappers are under development to make these routines easier.

Secret key encryption is high speed encryption based on a shared secret key.

.. note::

    The nacl library uses the salsa20 stream encryption cipher for secret key
    encryption, more information about the salsa20 cipher can be found here:
    http://cr.yp.to/salsa20.html

The means of encryption assumes that the two sides of the conversation both
have access to the same shared secret key. First generate a secret key, libnacl
provides a convenience function for the generation of this key called
libnacl.utils.salsa_key, then generate a nonce, a new nonce should be used
every time a new message is encrypted. A convenience function to create a unique
nonce based on random bytes:

.. code-block:: python

    import libnacl
    import libnacl.utils

    key = libnacl.utils.salsa_key()
    nonce = libnacl.utils.rand_nonce()

With the key and nonce in hand, the cryptographic secret box can now be
generated:

.. code-block:: python

    msg = 'Who are you who are so wise in the ways of science?'
    box = libnacl.crypto_secretbox(msg, nonce, key)

Now the message can be decrypted on the other end. The nonce and the key are
both required to decrypt:

.. code-block:: python

    clear_msg = libnacl.crypto_secretbox_open(box, nonce, key)

When placed all together the sequence looks like this:

.. code-block:: python

    import libnacl
    import libnacl.utils

    key = libnacl.utils.salsa_key()
    nonce = libnacl.utils.rand_nonce()

    msg = 'Who are you who are so wise in the ways of science?'
    box = libnacl.crypto_secretbox(msg, nonce, key)

    clear_msg = libnacl.crypto_secretbox_open(box, nonce, key)
