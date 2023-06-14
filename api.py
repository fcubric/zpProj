# API for zp proj
import models
from models import *



def generate_new_keypair(name, password, email, size, algorithm):
    '''

    :param name: name of user
    :param password: password of user
    :param email: email of user
    :param size: chosen keysize
    :param algorithm: chosen algorithm (possible values: 'RSA', 'DSA')
    :return:  descriptive message / error
    '''
    keyring_enc=None
    keyring_sig=None
    if algorithm=="DSA":
        keyring_sig = KeyRing(email, name, password, size, algorithm)
        keyring_enc = KeyRing(email, name, password, size, "ELG")
    else:
        keyring_sig=KeyRing(email,name,password,size,algorithm)
        keyring_enc=KeyRing(email,name,password,size,algorithm)

    models.user_logged.my_keys[keyring_enc.keyId]=keyring_enc
    models.user_logged.my_keys[keyring_sig.keyId]=keyring_sig
    return ""

def delete_keypair(keys):
    '''

    :param keys: id of key pair in the structure to be deleted
    :return: descriptive message / error
    '''
    return ""

def import_key(filename, path, password, req):
    '''

    :param filename: file from which key is imported
    :param path: path to file
    :param password: user password
    :param req: if the password is required (True-private key, False-public key)
    :return: descriptive message / error
    '''
    return ""

def export_key(filename, path, password, req):
    '''

    :param filename: file to which key is exported
    :param path: path to file
    :param password: user password
    :param req: if the password is required (True-private key, False-public key)
    :return: descriptive message / error
    '''
    return ""

def show_ring(pw):
    '''

    :param pw: password for showing a private key pair
    :return: descriptive message / error
    '''
    return ""

def send_message(filename, path, enc, sign, compress, radix, message):
    '''

    :param filename: file to which message is exported
    :param path: path to file
    :param enc: encription object
            enc={
                'alg' : algorithm of encryption
                'key' : encryption public key
            }
            can be empty if the option for encryption is not chosen
    :param sign: signature object
            sign={
                'alg' : algorithm of signature
                'key' : signature private key
            }
            can be empty if the option for signature is not chosen
    :param compress: True if compress option is chosen, otherwise False
    :param radix: True if conversion option is chosen, otherwise False
    :param message: message to be seng
    :return: descriptive message / error
    '''
    return ""

def receive_message(filename_from,path_from,filename_to,path_to,errors):
    '''

    :param filename_from: file from which message is read
    :param path_from: path to file_form
    :param filename_to: file to which decrypted message is stored
    :param path_to: path to file_to
    :param errors: array of length 2
            errors[0] - says whether the authentication was successful
            errors[1] - says whether the verificatoin was successful
    :return: descriptive message / error
    '''
    return ""
