=====================
Secret Key Encryption
=====================

Secret key encryption is the method of using a single key for both encryption
and decryption of messages. One of the classic examples from history of secret
key, or symmetric, encryption is the Enigma machine.

The SecretBox class in libnacl.secret makes this type of encryption very easy
to execute:

.. code-block:: python

    msg = b'But then of course African swallows are not migratory.'
    # Create a SecretBox object, if not passed in the secret key is
    # Generated purely from random data
    box = libnacl.secret.SecretBox()
    # Messages can now be safely encrypted
    ctxt = box.encrypt(msg)
    # An additional box can be created from the original box secret key
    box2 = libnacl.secret.SecretBox(box.sk)
    # Messages can now be easily encrypted and decrypted
    clear1 = box.decrypt(ctxt)
    clear2 = box2.decrypt(ctxt)
    ctxt2 = box2.encrypt(msg)
    clear3 = box.decrypt(ctxt2)

.. note::

    Every encryption routine requires a nonce. The nonce is a 24 char string
    that must never be used twice with the same keypair. If no nonce is passed
    in then a nonce is generated based on random data.
    If it is desired to generate a nonce manually this can be done by passing
    it into the encrypt method.
