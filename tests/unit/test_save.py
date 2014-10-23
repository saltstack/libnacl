# -*- coding: utf-8 -*-
# Import libnacl libs
import libnacl.dual
import libnacl.sign
import libnacl.utils

# Import pythonlibs
import os
import stat
import unittest
import tempfile


class TestSave(unittest.TestCase):
    '''
    '''
    def test_save_load(self):
        msg = b'then leap out of the rabbit, taking the French by surprise'
        bob = libnacl.dual.DualSecret()
        alice = libnacl.dual.DualSecret()
        fh_, bob_path = tempfile.mkstemp()
        fh_, alice_path = tempfile.mkstemp()
        bob.save(bob_path)
        alice.save(alice_path)
        bob_box = libnacl.public.Box(bob, alice.pk)
        alice_box = libnacl.public.Box(alice, bob.pk)
        bob_enc = bob_box.encrypt(msg)
        alice_enc = alice_box.encrypt(msg)
        bob_load = libnacl.utils.load_key(bob_path)
        alice_load = libnacl.utils.load_key(alice_path)
        bob_load_box = libnacl.public.Box(bob_load, alice_load.pk)
        alice_load_box = libnacl.public.Box(alice_load, bob_load.pk)
        self.assertEqual(bob.sk, bob_load.sk)
        self.assertEqual(bob.pk, bob_load.pk)
        self.assertEqual(bob.vk, bob_load.vk)
        self.assertEqual(bob.seed, bob_load.seed)
        self.assertEqual(alice.sk, alice_load.sk)
        self.assertEqual(alice.pk, alice_load.pk)
        self.assertEqual(alice.vk, alice_load.vk)
        self.assertEqual(alice.seed, alice_load.seed)
        bob_dec = alice_load_box.decrypt(bob_enc)
        alice_dec = bob_load_box.decrypt(alice_enc)
        self.assertEqual(bob_dec, msg)
        self.assertEqual(alice_dec, msg)
        os.remove(bob_path)
        os.remove(alice_path)

    def test_save_load_sign(self):
        msg = b'then leap out of the rabbit, taking the French by surprise'
        signer = libnacl.sign.Signer()
        fh_, sign_path = tempfile.mkstemp()
        signer.save(sign_path)
        signer_load = libnacl.utils.load_key(sign_path)
        signed1 = signer.sign(msg)
        signed2 = signer_load.sign(msg)
        self.assertEqual(signed1, signed2)

    def test_save_perms(self):
        bob = libnacl.dual.DualSecret()
        fh_, bob_path = tempfile.mkstemp()
        bob.save(bob_path)
        stats = os.stat(bob_path)
        self.assertEqual(stats[stat.ST_MODE], 33152)
        os.remove(bob_path)
