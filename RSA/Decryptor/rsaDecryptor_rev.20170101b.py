#!/usr/bin/env python
#Filename: rsaDecryptor_rev.01012017b.py
#Author: Rod Chubb

#Purpose: This script decrypts a file using an RSA private key.

#Description: This script decrypts a file using an RSA private key.

#Script usage is:
#"python rsaDecryptor_rv.01012017b.py private_key_file secret file_to_be_decrypted"
#The output is a decrypted file that is named with name of the
#file_to_be_decrypted with a ".unenc" extension added


#Imports
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


#Command Line 
parser = argparse.ArgumentParser(description='This script decrypts a file using the specified RSA private key. EX.rsaDecryptor.py private_key_file secret file_to_be_decrypted')
parser.add_argument("private_key_file", nargs=1,
                    help='The first command line argument that must be supplied is the name of the private key file.')
parser.add_argument("secret", nargs=1,
                    help='The second command line argument that must be supplied is the name of thefile to be encrypted.')
parser.add_argument("file_to_be_decrypted", nargs=1,
                    help='The third command line argument that must be supplied is the name of the file to be decrypted.')

args = parser.parse_args()

#Constants
private_key_file_argument = args.private_key_file #This creates a list, the list item needs to be converted to a string
private_key_filename = str(private_key_file_argument[0])
secret_argument = args.secret #This creates a list, the list item needs to be converted to a string
secret_string = str(secret_argument[0])
file_to_be_decrypted_argument = args.file_to_be_decrypted #This creates a list, the list item needs to be converted to a string
file_to_be_decrypted_filename = str(file_to_be_decrypted_argument[0])
decrypted_filename_suffix = ".unenc"
decrypted_filename = file_to_be_decrypted_filename + decrypted_filename_suffix

private_key_object = open(private_key_filename, 'rb')

encrypteddata = open(file_to_be_decrypted_filename, "rb")
private_key = RSA.import_key(private_key_object.read(),passphrase=secret_string)

enc_session_key, nonce, tag, ciphertext = [ encrypteddata.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

#Decrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

#Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
plaintext = open(decrypted_filename, "wb").write(data)
