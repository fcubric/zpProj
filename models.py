import hashlib
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class KeyRingPrivate:
    def __init__(self,email,name, password,key_size,algorithm):

        self.user_id=email+name
        self.password=password
        self.public_key=None
        self.private_key=None
        self.timestamp=datetime.now()
        cast_key = hashlib.sha1(password.encode()).digest()
        initial_vector = os.urandom(16)
        cipher = Cipher(algorithms.CAST5(cast_key), mode=modes.CBC(initial_vector))
        encryptor = cipher.encryptor()


        print(cast_key)
        if algorithm=="RSA":
            real_prviateKey = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            private_key_bytes = real_prviateKey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            print("PRIVATNI KLJUC", real_prviateKey , "\nPRIVATNI KLJUC BYTES", private_key_bytes)

            self.private_key = encryptor.update(private_key_bytes) + encryptor.finalize()
            self.public_key =real_prviateKey.public_key()

            decryptor = cipher.decryptor()
            private_key_bytes2 = decryptor.update(self.private_key) + decryptor.finalize()
            print("PRIVATNI KLJUC", real_prviateKey, "\nPRIVATNI KLJUC BYTES", private_key_bytes)


        else:
            KeyRingPrivate.generate_key_pair_elgamal_dsa(self,key_size)
        self.keyId=self.public_key.public_numbers().n % 2**64
        print(self.keyId)


    @staticmethod
    def generate_key_pair_rsa(keyring,size):
        print("xd")
        keyring.private_key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=size
        )
        keyring.public_key = keyring.private_key.public_key()



    @staticmethod
    def generate_key_pair_elgamal_dsa(keyring, size):
        pass