from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa

class KeyRingPrivate:
    def __init__(self,email,name, password,key_size,algorithm):

        self.user_id=email+name
        self.password=password
        self.public_key=None
        self.private_key=None
        self.timestamp=datetime.now()
        if algorithm=="RSA":
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            self.public_key = self.private_key.public_key()
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