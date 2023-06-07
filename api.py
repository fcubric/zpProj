# API for zp proj
from models import *
def generate_new_keypair(name, password, email, size, algorithm):
    '''

    :param name: name of user
    :param password: password of user
    :param email: email of user
    :param size: chosen keysize
    :param algorithm: chosen algorithm (possible values: 'RSA', 'DSA')
    :return: message saying the operation was successful or error message
    '''
    keyring=KeyRingPrivate(email,name,password,size,algorithm)
    print("halo")
    return ""


def delete_keypair(keys):
    '''

    :param keys: not sure what this is yet
    :return:
    '''
    return ""

def import_key(filename, path, password, req):
    return ""

def export_key(filename, path, password, req):
    return ""

def show_ring(pw):
    return ""

def send_message(filename, path, enc, sign, compress, radix):
    return ""

def receive_message(filename_from,path_from,filename_to,path_to,errors):
    return ""
