import hashlib

from datetime import datetime

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from hashlib import shake_128, sha1

user_logged=None

class KeyRing:
    def __init__(self,email,name, password,key_size,algorithm):

        self.user_id=email
        self.password=password #already encoded
        self.public_key=None
        self.private_key=None
        self.timestamp=datetime.now()

        self.algorithm=algorithm

        if algorithm=="RSA":
            KeyRing.generate_key_pair_rsa(self,key_size)
        elif algorithm=="DSA":
            KeyRing.generate_key_pair_dsa(self,key_size)
        elif algorithm=="ELG":
            KeyRing.generate_key_pair_elgamal(self,key_size)

        self.keyId=self.public_key.public_numbers().n % 2**64
        try:
            self.hash_private_key()
        except Exception as e:
            print(e)
        print(self.keyId)


    @staticmethod
    def generate_key_pair_rsa(keyring,size):
        keyring.private_key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=size
        )
        keyring.public_key = keyring.private_key.public_key()


    @staticmethod
    def generate_key_pair_elgamal(keyring, size):
        #ana napravi nesto
        pass

    @staticmethod
    def generate_key_pair_dsa(keyring, size):
        #call ugradjeni dsa
        pass

    def hash_private_key(self):



        # ciphertext = self.public_key.encrypt(
        #     b"test poruka",
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )

        private_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.password)
        )

        self.private_key = private_key_bytes


        #print("\nPRIVATNI KLJUC BYTES\n", private_key_bytes)

        # private = serialization.load_pem_private_key(self.private_key,password=self.password)
        #
        # plaintext = private.decrypt(
        #     ciphertext,
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )
        #
        # print(plaintext)

        #self.private_key = encryptor.update(private_key_bytes) + encryptor.finalize()


        #decryptor = cipher.decryptor()
        #private_key_bytes2 = decryptor.update(self.private_key) + decryptor.finalize()
        #print("\nPRIVATNI KLJUC BYTES\n", private_key_bytes)


class User:
    def __init__(self, name, email, password):
        self.name=name
        self.email=email
        self.password=sha1(password.encode()).digest()
        self.my_keys=dict()
        self.other_keys=dict()

class Users_Set:
    users=dict()
    @staticmethod
    def add_user(user):
        if Users_Set.users.keys().__contains__(user.email):
            return
        Users_Set.users[user.email]=user

    @staticmethod
    def login( email, pw):
        global user_logged
        pw=sha1(pw.encode()).digest()
        if not Users_Set.users.keys().__contains__(email):
            return "User doesnt exist"
        if Users_Set.users[email].password==pw:
            user_logged=Users_Set.users[email]
            return "Logged in successfully"
        return "Passwords do not match"

    @staticmethod
    def logout():
        global user_logged
        user_logged=None
        return "Logged out successfully"

    @staticmethod
    def register(name, email, pw):
        global user_logged
        if Users_Set.users.keys().__contains__(email):
            return "Email already in use"
        user=User(name,email,pw)
        Users_Set.users[user.email]=user
        user_logged=user
        return "Registered successfully"