===================
Dual Key Management
===================

The libnacl library abstracts a "Dual Key" model. The Dual Key creates a single
key management object that can be used for both signing and encrypting, it
generates and maintains a Curve25519 encryption key pair and an ED25519 signing
keypair. All methods for encryption and signing work with and from Dual Keys.

To encrypt messages using Dual Keys:

.. code-block:: python

    import libnacl.dual

    # Define a message to send
    msg = b"You've got two empty halves of coconut and you're bangin' 'em together."

    # Generate the key pairs for Alice and bob, if secret keys already exist
    # they can be passed in, otherwise new keys will be automatically generated
    bob = libnacl.dual.DualSecret()
    alice = libnacl.dual.DualSecret()

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
    aclear = alice_box.decrypt(alice_ctxt)

.. note::

    Every encryption routine requires a nonce. The nonce is a 24 char string
    that must never be used twice with the same keypair. If no nonce is passed
    in then a nonce is generated based on random data.
    If it is desired to generate a nonce manually this can be done by passing
    it into the encrypt method.

DualKey Object
==============

The DualKey object is used to manage both public and secret keys, this object
contains a number of methods for both convenience and utility. The key data is
also available.

Keys
----

The raw public key is available as DualKey.pk, to generate a hex encoded
version of the key the pk_hex method is available:

.. code-block:: python

    import libnacl.dual
    
    fred = libnacl.dual.DualKey()

    raw_sk = fred.sk
    hex_sk = fred.hex_sk()

    raw_pk = fred.pk
    hex_pk = fred.hex_pk()

By saving only the binary keys in memory libnacl ensures that the minimal
memory footprint is needed.

Saving Keys to Disk
===================

All libnacl key objects can be safely saved to disk via the save method. This
method changes the umask before saving the key file to ensure that the saved
file can only be read by the user creating it and cannot be written to.
When using dual keys the encrypting and signing keys will be saved togather in
a single file.

.. code-block:: python

    import libnacl.dual

    fred = libnacl.dual.DualKey()
    fred.save('/etc/nacl/fred.key')
