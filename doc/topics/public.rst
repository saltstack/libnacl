=====================
Public Key Encryption
=====================

Unlike traditional means for public key asymmetric encryption, the nacl
encryption systems are very high speed. The CurveCP network protocol for
instance only uses public key encryption for all transport.

Public key encryption is very simple, as is evidenced with this communication
between Alice and Bob:

.. code-block:: python

    import libnacl.public

    # Define a message to send
    msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'

    # Generate the key pairs for Alice and bob, if secret keys already exist
    # they can be passed in, otherwise new keys will be automatically generated
    bob = libnacl.public.SecretKey()
    alice = libnacl.public.SecretKey()

    # Create the boxes, this is an object which represents the combination of the
    # sender's secret key and the receiver's public key
    bob_box = libnacl.public.Box(bob.sk, alice.pk)
    alice_box = libnacl.public.Box(alice.sk, bob.pk)

    # Bob's box encrypts messages for Alice
    bob_ctxt = bob_box.encrypt(msg)
    # Alice's box decrypts messages from Bob
    bclear = alice_box.decrypt(bob_ctxt)
    # Alice can send encrypted messages which only Bob can decrypt
    alice_ctxt = alice_box.encrypt(msg)
    aclear = bob_box.decrypt(alice_ctxt)

.. note::

    Every encryption routine requires a nonce. The nonce is a 24 char string
    that must never be used twice with the same keypair. If no nonce is passed
    in then a nonce is generated based on random data.
    If it is desired to generate a nonce manually this can be done by passing
    it into the encrypt method.

.. _secretkey-object:

SecretKey Object
================

The SecretKey object is used to manage both public and secret keys, this object
contains a number of methods for both convenience and utility. The key data is
also available.

Keys
----

The raw public key is available as SecretKey.sk, to generate a hex encoded
version of the key the sk_hex method is available. The same items are
available for the public keys:

.. code-block:: python

    import libnacl.public
    
    fred = libnacl.public.SecretKey()

    raw_sk = fred.sk
    hex_sk = fred.hex_sk()

    raw_pk = fred.pk
    hex_pk = fred.hex_pk()

By saving only the binary keys in memory libnacl ensures that the minimal
memory footprint is needed.

.. _publickey-object:

PublicKey Object
================

To manage only the public key end, a public key object exists:

.. code-block:: python

    import libnacl.public

    tom = libnacl.public.PublicKey(tom_public_key_hex)

    raw_pk = tom.pk
    hex_pk = tom.hex_pk()

Saving Keys to Disk
===================

All libnacl key objects can be safely saved to disk via the save method. This
method changes the umask before saving the key file to ensure that the saved
file can only be read by the user creating it and cannot be written to.

.. code-block:: python

    import libnacl.public

    fred = libnacl.public.SecretKey()
    fred.save('/etc/nacl/fred.key')
