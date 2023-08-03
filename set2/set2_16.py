#!/usr/bin/env python3
# coding: utf-8

from set2_10 import unpad_pkcs7, pad_pkcs7
from set2_10 import aes_cbc_encrypt, aes_cbc_decrypt
from set2_14 import split_into_chunks, print_hex_chunks
from hexdoor import  hexdump


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
	hexdump(cleartext)

	if b';admin=true;' in cleartext:
		return True
	else:
		return False

def xor(a, b, c):
	return ord(a) ^ b ^ ord(c)

if __name__ == '__main__':

	ciphertext = encryption_oracle(b'A'*16 + b':admin<true')

	hexdump(ciphertext)
	print(is_admin(ciphertext))

	print("~~~~~ Bit Flipping ~~~~")

	ciphertext[0x20] = xor(b':', ciphertext[0x20], b';')
	ciphertext[0x26] = xor(b'<', ciphertext[0x26], b'=')
	# ciphertext[0x20] = ciphertext[0x20] - 1
	# ciphertext[0x26] = ciphertext[0x26] + 1
	hexdump(ciphertext)

	print(is_admin(ciphertext))




