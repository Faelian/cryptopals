#!/usr/bin/env python3
# coding: utf-8

from Crypto.Cipher import AES
from base64 import b64decode

from set3_18 import aes_ctr, generate_keystream, xor_blocks
from set3_19 import scoreString, break_single_key_xor
from pprint import pprint

IV = b'\x00'*8
KEY = bytes.fromhex('2df42ea1f5d236fb8966a6726606b9db') # generated with secrets.token_bytes(16)

def split_in_single_key(message, single_key_blocks):
	for i in range(len(message)):
		single_key_blocks[i].append(message[i])

def decrypt_message(ciphertext, keystream):
	decrypted = ''

	for i in range(len(ciphertext)):
		k = keystream[i]
		c = ciphertext[i]

		decrypted += chr(k ^ c)

	return decrypted


# Apparently I was already using the statistical method in challenge 19.
# We just do the same thing here.

if __name__ == '__main__':
	# initalize the challenge:
	# encrypt every message with the KEY
	ciphertexts = []

	with open('20.txt') as f:
		for line in f:
			encrypted_message = aes_ctr(IV, b64decode(line), KEY)
			ciphertexts.append(encrypted_message)

	#ciphertexts = sorted(ciphertexts, key=len)
	ciphertexts.sort(key=len, reverse=True)

	# for ciphertext in ciphertexts:
	# 	print(ciphertext.hex())

	max_length_of_ciphertext = max([len(ciphertext) for ciphertext in ciphertexts])

	single_key_blocks = [[] for _ in range(max_length_of_ciphertext)]


	# create array of single byte arry
	for encrypted_message in ciphertexts:
		split_in_single_key(encrypted_message, single_key_blocks)	

	keystream = []

	for single_key_bytes in single_key_blocks:
		key, message = break_single_key_xor(single_key_bytes)
		keystream.append(key)

	ciphertext = ciphertexts[0]
	cleartext = []

	# We have a few missing chars at the end. But it's pretty correct

	for ciphertext in ciphertexts:
		print(decrypt_message(ciphertext, keystream))
