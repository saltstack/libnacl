=======================
Key Exchange Encryption
=======================

The X25519 key exchange algorithm in libsodium allows for key exchange encryption
to be safely executed. The ExchangeKey class makes it easy to use key exchange wrapping
AEAD encryption. This class works similarly to sealed boxes, but offers more functionality
and better security.

When using the ExchangeKey encryption class you can select which AEAD encryption
subsystem to use, but it is recommended to stick with the default XChaCha algorithm.

To use the ExchangeKey system, simply create an ExchangeKey class for `bob` and `alice`
and then encrypt a message and additional unencrypted data and send them back and forth.

In this example, bob acts as the client, and alice acts as the server. The underlying
nature of the connections are irrelevant, just that once end needs to call the server
functions and the other needs to call the client functions.

.. code-block:: python

        # Import libnacl libs
        import libnacl.kx

        msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'
        aad = b'A Duck!'
        # Make Bob and Alice Exchange Keys
        bob = libnacl.kx.ExchangeKey()
        alice = libnacl.kx.ExchangeKey()
        # Encrypt with bob as client and alice as server
        bob_ctxt = bob.encrypt_client(alice.kx_pk, msg, aad)
        bclear, clear_aad = alice.decrypt_server(bob.kx_pk, bob_ctxt, len(aad))
        # Similarly you can have alice encrypt as server and bob decrypt as client
        alice_ctxt = alice.encrypt_server(bob.kx_pk, msg, aad)
        aclear, clear_aad = bob.decrypt_client(alice.kx_pk, alice_ctxt, len(aad))
