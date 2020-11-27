#!/usr/bin/python3

import argparse
import sys
from base64 import b64encode, b64decode

class ProductCipher:

    def __init__(self, plaintext='', key='', ciphertext=''):
        self.plaintext = plaintext.upper()
        self.key = key
        self.ciphertext = ciphertext

    #encrypt
    def encrypt(self):
        
        #set all values
        key_length = len(self.key)
        key_int = [ord(i) for i in self.key]
        plaintext_int = [ord(i) for i in self.plaintext]
        self.ciphertext = ''
        
        #encrypt
        for i in range(len(plaintext_int)):
            value = (plaintext_int[i] + key_int[i % key_length]) % 52
            self.ciphertext += chr(value + 65)

        return self.ciphertext
    
    #decrypt
    def decrypt(self):
        
        #set all values
        key_length = len(self.key)
        key_int = [ord(i) for i in key]
        ciphertext_int = [ord(i) for i in self.ciphertext]
        self.plaintext = ''
        
        #decrypt
        for i in range(len(ciphertext_int)):
            value = (ciphertext_int[i] - key_int[i % key_length]) % 52
            self.plaintext += chr(value + 65)

        return self.plaintext

#get values
parser = argparse.ArgumentParser(description="Product Cipher: Implements base64 with vigenere")
parser.add_argument("-p", metavar="plaintext", help="plaintext message to encrypt")
parser.add_argument("-k", metavar="key", help="key to use for encryption/decryption")
parser.add_argument("-c", metavar="ciphertext", help="ciphertext to decrypt")
args = parser.parse_args()

#get values and create object
plaintext = args.p
key = args.k
ciphertext = args.c


if key == None:
    parser.print_help()
    exit(1)

elif plaintext == None:
    productcipher = ProductCipher(ciphertext=ciphertext, key=key)
    dectext = productcipher.decrypt()
    print("Ciphertext: {}\nKey: {}\nPlaintext: {}".format(ciphertext, key, dectext))
    exit(0)

elif ciphertext == None:
    productcipher = ProductCipher(plaintext=plaintext, key=key)
    enctext = productcipher.encrypt()
    print("Plaintext: {}\nKey: {}\nCiphertext: {}".format(plaintext, key, enctext))
    exit(0)

elif ciphertext != None and plaintext != None:
    print("You cannot have -c and -m together!")
    exit(1)

else:
    print("idk how you got this message")
    exit(1)
