#!/usr/bin/python3

"""
lets explain RSA algorithm first
theres 2 prime numbers, p and q
n = p*q is the modulus for both public and private keys

phi(n) or t is the totient. totient 't' is a number smaller than 'n', such that 't' shares no common factors with 'n' (co-primes). For a prime number 'p', t = p-1 (Eulters totient function) hence phi(n) = (p-1).(q-1), since n = p.q

e is the public key exponent, such that 1 < e < phi(n) and e and phi(n) are co-primes. so gcd(e, phi(n)) = 1
d is the private key exponent, such that d = x/e, d has to be an integer
x is any integer. it is prefebaly chosen as x = 1+ i*phi(n) and x%e = 0. Here i is a value between 1 and 10

ENCRYPTION: ciphertext = plaintext ^ e % n
DECRYPTION: plaintext = ciphertext ^ d % n
"""

from math import gcd
from base64 import b64encode, b64decode
import argparse

class RSA:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        
        #generate n and phi(n)
        self.n = p*q
        self.phi = (p-1)*(q-1)

        #generate public and private exponentials
        self.e = self.get_e()
        self.d = self.get_d()

    def get_e(self):
        for e in range(2, self.phi):
            if gcd(e, self.phi) == 1:
                return e

    def get_d(self):
        for i in range(1,10):
            x = 1 + i*self.phi
            if x % self.e == 0:
                d = int(x/self.e)
                return d

    def encrypt(self, plaintext):
        plaintext = [ord(i) for i in plaintext]
        ciphertext = [(i**self.e)%self.n for i in plaintext]
        enctext = ''.join(chr(i) for i in ciphertext)
        return (b64encode(enctext.encode('utf-8'))).decode('utf-8')

    def decrypt(self, ciphertext):
        ciphertext = b64decode(ciphertext.encode('utf-8')).decode('utf-8')
        ciphertext = [ord(i) for i in ciphertext]
        plaintext = [(i**self.d)%self.n for i in ciphertext]
        dectext = ''.join(chr(i) for i in plaintext)
        return dectext

parser = argparse.ArgumentParser(description="RSA Cryptosystem")
parser.add_argument("-p", metavar="prime1", help="first prime")
parser.add_argument("-q", metavar="prime2", help="second prime")
parser.add_argument("-e", metavar="plaintext", help="plaintext to encrypt")
parser.add_argument("-c", metavar="ciphertext", help="ciphertext to decrypt")
args = parser.parse_args()

#get primes
p = int(args.p)
q = int(args.q)
plaintext = args.e
ciphertext = args.c

rsa = RSA(p, q)

if ciphertext == None:
    enctext = rsa.encrypt(plaintext)
    print("private exponential: {}\npublic exponential: {}\nciphertext: {}".format(rsa.e, rsa.d, enctext))
elif plaintext == None:
    dectext = rsa.decrypt(ciphertext)
    print("private exponential: {}\npublic exponential: {}\nplaintext: {}".format(rsa.e, rsa.d, dectext))
elif plaintext != None and ciphertext != None:
    print("You cannot have -e and -c together!")
