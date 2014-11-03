==================
Raw Hash Functions
==================

The nacl library comes with sha256 and sha512 hashing libraries. They do not
seem to offer any benefit over python's hashlib, but for completeness they are
included. Creating a hash of a message is very simple:

.. code-block:: python

    import libnacl

    msg = 'Is there someone else up there we could talk to?'
    h_msg = libnacl.crypto_hash(msg)

crypto_hash defaults to sha256, sha512 is also available:

.. code-block:: python

    import libnacl

    msg = 'Is there someone else up there we could talk to?'
    h_msg = libnacl.crypto_hash_sha512(msg)
