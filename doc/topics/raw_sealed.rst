=========================
Raw Sealed Box Encryption
=========================

Sealed box is a variant of :doc:`public key encryption scheme </raw_public.rst>`
where the sender is not authenticated. This is done by generating an
ephemeral key pair, which the public key is prefixed to the cipher text.

First, generate a keypair for the receiver. The sender doesn't need a keypair.

.. code-block:: python

    import libnacl

    pk, sk = libnacl.crypto_keypair()

Then a sealed box is created by the sender, using the receiver's public key

.. code-block:: python

    msg = 'Quiet, quiet.  Quiet!  There are ways of telling whether she is a witch.'
    box = libnacl.crypto_box_seal(msg, pk)

The receiver then can decrypt the box using their keypair.

.. code-block:: python

    clear_msg = libnacl.crypto_box_seal_open(box, pk, sk)

To bring it all together:

.. code-block:: python

    import libnacl

    pk, sk = libnacl.crypto_keypair()

    msg = 'Quiet, quiet.  Quiet!  There are ways of telling whether she is a witch.'
    box = libnacl.crypto_box_seal(msg, pk)

    clear_msg = libnacl.crypto_box_seal_open(box, pk, sk)
