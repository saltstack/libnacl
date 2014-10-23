=================
Utility Functions
=================

The libnacl system comes with a number of utility functions, these functions
are made available to make some of the aspects of encryption and key management
easier. These range from nonce generation to loading saved keys.

Loading Saved Keys
==================

After keys are saved using the key save method reloading the keys is easy. The
`libnacl.utils.load_key` function will detect what type of key object saved
said key and then create the object from the key and return it.

.. code-block:: python

    import libnacl.utils

    key_obj = libnacl.utils.load_key('/etc/keys/bob.key')

The load_key and save routines also support inline key serialization. The
default is json but msgpack is also supported.

Salsa Key
=========

A simple function that will return a random byte string suitable for use in
SecretKey encryption.

.. code-block:: python

    import libnacl.utils

    key = libnacl.utils.salsa_key()

This routine is only required with the raw encryption functions, as the
`libnacl.secret.SecretBox` will generate the key automatically.

Nonce Routines
==============

A few functions are available to help with creating nonce values, these
routines are available because there is some debate about what the best approach
is.

We recommend a pure random string for the nonce which is returned from
`rand_nonce`, but some have expressed a desire to create nonces which are
designed to avoid re-use by more than simply random data and therefore
the `time_nonce` function is also available.
