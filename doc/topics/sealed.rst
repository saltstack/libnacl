=====================
Sealed Box
=====================

Sealed box is a variant of :doc:`public key encryption scheme </topics/public>`
which only the receiver's public key is required. As such, the sender of the
message cannot be cryptographically authenticated.

.. code-block:: python

    import libnacl.sealed
    import libnacl.public	

    # Define a message to send
    msg = b'You\'ve got two empty halves of coconut and you\'re bangin\' \'em together.'

    # Generate the key pair
    keypair = libnacl.public.SecretKey()

    # Create the box
    box = libnacl.sealed.SealedBox(keypair)

    # Encrypt messages
    ctxt = box.encrypt(msg)
    # Decrypt messages
    bclear = box.decrypt(ctxt)

Creating Box
======================
SealedBox instances can be created by supplying a public and private key. The
private key is only required when decrypting.

The public key can be supplied as:

* Instance of :ref:`SecretKey <secretkey-object>`, which supply both the public
  and private key.
* Instance of :ref:`PublicKey <publickey-object>`
* Raw binary representation
