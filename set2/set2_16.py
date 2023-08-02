#!/usr/bin/env python3
# coding: utf-8

from set2_10 import unpad_pkcs7, pad_pkcs7
from set2_10 import aes_cbc_encrypt, aes_cbc_decrypt
from set2_14 import split_into_chunks, print_hex_chunks


AES_KEY = b'\xaeJK^\xe1d\xb1M\xfb\xb3[%-\x9c\x14\xe1'
IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

def encryption_oracle(cleartext):
	# sanitize input
	cleartext = cleartext.replace(b'=',b'')
	cleartext = cleartext.replace(b';',b'')

	cleartext = b"comment1=cooking%20MCs;userdata=" + cleartext
	cleartext = cleartext + b";comment2=%20like%20a%20pound%20of%20bacon"

	ciphertext = aes_cbc_encrypt(IV, cleartext, AES_KEY)

	return ciphertext

def is_admin(ciphertext):
	cleartext = aes_cbc_decrypt(IV, ciphertext, AES_KEY)
	cleartext = cleartext.decode()
	
	tokens = dict(x.split("=") for x in cleartext.split(";"))

	print(repr(tokens))

	for key, value in tokens.items():
		if key == 'admin' and value.lower() == 'true':
			return True

	return False



ciphertext = encryption_oracle(b"hello-world")

print_hex_chunks(ciphertext)





#print(aes_cbc_decrypt(IV, ciphertext, AES_KEY))