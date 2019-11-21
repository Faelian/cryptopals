#!/usr/bin/env python3
# coding: utf8

import secrets
import random
from Crypto.Cipher import AES
from set2_10 import aes_cbc_encrypt, aes_cbc_decrypt
from set2_10 import pad_pkcs7

def aes_ecb_encrypt(cleartext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	len_last_block = len(cleartext) % 16

	cleartext = pad_pkcs7(cleartext, len(cleartext) + (16-len_last_block))
	ciphertext = cipher.encrypt(cleartext)

	return ciphertext

def generate_random_aes_key():
	return secrets.token_bytes(16)

def encryption_oracle(cleartext):
	aes_key = generate_random_aes_key()

	# append bytes before and after cleartext
	nb_bytes_before = random.randint(5,10)
	nb_bytes_after = random.randint(5,10)

	cleartext = secrets.token_bytes(nb_bytes_before) + cleartext
	cleartext = cleartext + secrets.token_bytes(nb_bytes_after)

	# encrypt ecb / cbc half of the time
	if random.randint(0,1) == 0: # encrypt ECB
		ciphertext = aes_ecb_encrypt(cleartext, aes_key)

	else : # encrypt CBC
		# generate IV
		iv = secrets.token_bytes(16)
		ciphertext = aes_cbc_encrypt(iv, cleartext, aes_key)

	return ciphertext

# In ECB, if the clear is a constant as b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
# The second and third block should be identical
# otherwise, it's probably CBC
def detect_aes_mode(ciphertext):
	blocks = [ciphertext[i:i+16] for i in range (0, len(ciphertext), 16)]

	if blocks[1] == blocks[2]:
		return "ECB"

	else:
		return "CBC"


if __name__ == '__main__':
	msg = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
	ciphertext = encryption_oracle(msg)
	print ("The mode is %s " % detect_aes_mode(ciphertext))
