=========================
Raw Public Key Encryption
=========================

.. note::

    While these routines are perfectly safe, higher level convenience
    wrappers are under development to make these routines easier.

Public key encryption inside the nacl library has been constructed to ensure
that all cryptographic routines are executed correctly and safely.

The public key encryption is executed via the functions which begin with
`crypto_box` and can be easily executed.

First generate a public key and secret key keypair for the two communicating
parties, who for tradition's sake, will be referred to as Alice and Bob:

.. code-block:: python

    import libnacl

    alice_pk, alice_sk = libnacl.crypto_keypair()
    bob_pk, bob_sk = libnacl.crypto_keypair()

Once the keys have been generated a cryptographic box needs to be created. The
cryptographic box takes the party's secret key and the receiving party's public
key. These are used to create a message which is both signed and encrypted.

Before creating the box a nonce is required. The nonce is a 24 character
string which should only be used for this message, the nonce should never be
reused. This means that the nonce needs to be generated in such a way that
the probability of reusing the nonce string with the same keypair is very
low. The libnacl wrapper ships with a convenience function which generates a
nonce from random bytes:

.. code-block:: python

    import libnacl.utils
    nonce = libnacl.utils.rand_nonce()

Now, with a nonce a cryptographic box can be created, Alice will send a
message:

.. code-block:: python

    msg = 'Quiet, quiet.  Quiet!  There are ways of telling whether she is a witch.'
    box = libnacl.crypto_box(msg, nonce, bob_pk, alice_sk)

Now with a box in hand it can be decrypted by Bob:

.. code-block:: python

    clear_msg = libnacl.crypto_box_open(box, nonce, alice_pk, bob_sk)

The trick here is that the box AND the nonce need to be sent to Bob, so he can
decrypt the message. The nonce can be safely sent to Bob in the clear.

To bring it all together:

.. code-block:: python

    import libnacl
    import libnacl.utils

    alice_pk, alice_sk = libnacl.crypto_keypair()
    bob_pk, bob_sk = libnacl.crypto_keypair()

    nonce = libnacl.utils.rand_nonce()

    msg = 'Quiet, quiet.  Quiet!  There are ways of telling whether she is a witch.'
    box = libnacl.crypto_box(msg, nonce, bob_pk, alice_sk)

    clear_msg = libnacl.crypto_box_open(box, nonce, alice_pk, bob_sk)
