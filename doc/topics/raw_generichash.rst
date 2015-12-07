====================================
Raw Generic Hash (Blake2b) Functions
====================================

The nacl library comes with blake hashing libraries.

More information on Blake can be found here:
https://blake2.net

The blake2b hashing algorithm is a keyed hashing algorithm, which allows
for a key to be associated with a hash. Blake can be executed with or without
a key.

With a key (they key can should be between 16 and 64 bytes):

.. code-block:: python

    import libnacl

    msg = 'Is there someone else up there we could talk to?'
    key = libnacl.randombytes(32)
    h_msg = libnacl.crypto_generichash(msg, key)

Without a key:

.. code-block:: python

    import libnacl

    msg = 'Is there someone else up there we could talk to?'
    h_msg = libnacl.crypto_generichash(msg)
