#!/usr/bin/env python
#Filename: rsaEncryptor_rev.01022017a.py
#Author: Rod Chubb

#Purpose: This script encrypts a file using an  RSA public key.

#Description: This script encrypts a file using an RSA public key.

#Script usage is:
#"python rsaEncryptor_rev.01022017a.py public_key_file file_to_be_encrypted"
#The output is an encrypted file that is named with name of the
#file_to_be_encrypted with a ".enc" extension added


#Imports
import argparse
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


#Command Line 
parser = argparse.ArgumentParser(description='This script encrypts a file using the specified RSA public key. EX.rsaEncryptor.py public_key_file file_to_be_encrypted')
parser.add_argument("public_key_file", nargs=1,
                    help='The first command line argument that must be supplied is the name of the public key file.')
parser.add_argument("file_to_be_encrypted", nargs=1,
                    help='The second command line argument that must be supplied is the name of thefile to be encrypted.')

args = parser.parse_args()


#Constants
file_to_be_encrypted_argument = args.file_to_be_encrypted #This creates a list, the list item needs to be converted to a string
orig_filename = str(file_to_be_encrypted_argument[0])
public_key_file_argument = args.public_key_file #This creates a list, the list item needs to be converted to a string
public_key_filename = str(public_key_file_argument[0])

encrypteddata_file_name_base = orig_filename
encrypteddata_file_name_suffix = ".enc"
encrypteddata_file_name_entire = encrypteddata_file_name_base + encrypteddata_file_name_suffix
orig_filename_size = os.path.getsize(orig_filename)
plaintextdata = open(orig_filename, 'rb').read(orig_filename_size)

encrypteddata = open(encrypteddata_file_name_entire, "wb")

public_key = RSA.import_key(open(public_key_filename).read())
session_key = get_random_bytes(16)


#Script
#Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(public_key)
encrypteddata.write(cipher_rsa.encrypt(session_key))

#Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(plaintextdata)
[ encrypteddata.write(x) for x in (cipher_aes.nonce, tag, ciphertext) ]
