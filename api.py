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
        keyring_sig = KeyRing(email,algorithm, "", password, size)
        keyring_enc = KeyRing(email, "ELG", "", password, size)
    else:
        keyring_sig=KeyRing(email,algorithm, "",password,size)
        keyring_enc=KeyRing(email,algorithm, "",password,size)

    models.user_logged.my_keys[keyring_enc.keyId]=keyring_enc
    models.user_logged.my_keys[keyring_sig.keyId]=keyring_sig
    return ""

def delete_keypair(keys,which):
    '''

    :param keys: id of key pair in the structure to be deleted
    :return: descriptive message / error
    '''
    if which==0:
        models.user_logged.my_keys.pop(keys)
    else:
        models.user_logged.other_keys.pop(keys)
    return "Key deleted successfully"

def import_key(filename, path, password, req):
    '''

    :param filename: file from which key is imported
    :param path: path to file
    :param password: user password
    :param req: if the password is required (True-private key, False-public key)
    :return: descriptive message / error
    '''
    alg = ""
    full_path="./users/"
    if path!="": full_path=full_path+path+"/"
    full_path=full_path+filename+".pem"
    with open(full_path,"r") as f:
        row = f.readline().split(" ")
        key = f.read()
        if ("PUBLIC" in key) and ("PRIVATE" not in key):
            if(row[0]==models.user_logged.email):
                return "You cannot import your own public key!"
            if row[1]=="ELG":
                key=key.split('- -')
                key[0]=key[0]+'-'
                key[1]='-'+key[1]+'-'
                key[2]='-'+key[2]
            k=KeyRingPublic(row[0],row[1],key)
            models.user_logged.other_keys[k.keyId]=k
        else:
            if(row[0]!=models.user_logged.email):
                return "You cannot import someone else's private key!"
            if row[1]=="ELG":
                key=key.split('- -')
                key[0]=key[0]+'-'
                key[1]='-'+key[1]+'-'
                key[2]='-'+key[2]+'-'
                key[3]='-'+key[3]
            k=KeyRing(row[0],row[1],key)
            models.user_logged.my_keys[k.keyId]=k
    return ""

def export_key(filename, path, keyid,req):
    '''

    :param filename: file to which key is exported
    :param path: path to file
    :param req: if the password is required (True-private key, False-public key)
    :return: descriptive message / error
    '''

    title=models.user_logged.email
    keyid = int(keyid)
    if(models.user_logged.my_keys[keyid].algorithm=='RSA'):
        title+=' RSA '
    elif(models.user_logged.my_keys[keyid].algorithm=='DSA'):
        title+=' DSA '
    else:
        title+=' ELG '
    title+='\n'
    full_path='./users/'+models.user_logged.email+'/'
    if path!="": full_path=full_path+path+"/"
    full_path=full_path+filename+".pem"
    with open(full_path,"wb") as f:
        f.write(title.encode())
        if (req == True):
            to_write=models.user_logged.my_keys[keyid].private_key
            if models.user_logged.my_keys[keyid].algorithm=="ELG":
                to_write=to_write+' '+PEM.encode(
                    data= bytes(str(models.user_logged.my_keys[keyid].public_key.p), 'ascii'),
                    marker="PUBLIC KEY P"
                    # passphrase=models.user_logged.password
                )
                to_write=to_write+' '+PEM.encode(
                    data= bytes(str(models.user_logged.my_keys[keyid].public_key.g), 'ascii'),
                    marker="PUBLIC KEY G"
                    # passphrase=models.user_logged.password
                )
                to_write = to_write+' '+PEM.encode(
                    data=bytes(str(models.user_logged.my_keys[keyid].public_key.y), 'ascii'),
                    marker="PUBLIC KEY Y"
                    # passphrase=models.user_logged.password
                )
                to_write=bytes(to_write,'ascii')
            f.write(to_write)
        else:
            if  models.user_logged.my_keys[keyid].algorithm=="ELG":
                to_write = PEM.encode(
                    data=bytes(str(models.user_logged.my_keys[keyid].public_key.p), 'ascii'),
                    marker="PUBLIC KEY P"
                    # passphrase=models.user_logged.password
                )
                to_write = to_write + ' ' + PEM.encode(
                    data=bytes(str(models.user_logged.my_keys[keyid].public_key.g), 'ascii'),
                    marker="PUBLIC KEY G"
                    # passphrase=models.user_logged.password
                )
                to_write = to_write + ' ' + PEM.encode(
                    data=bytes(str(models.user_logged.my_keys[keyid].public_key.y), 'ascii'),
                    marker="PUBLIC KEY Y"
                    # passphrase=models.user_logged.password
                )
                f.write(bytes(to_write,'ascii'))
            else:
                f.write(models.user_logged.my_keys[keyid].public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
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

    hash_message=sha1(message)
    whole_message=''
    if (sign):
        pass


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
