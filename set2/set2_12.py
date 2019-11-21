#!/usr/bin/env python3
# coding: utf8

from Crypto.Cipher import AES
from set2_11 import aes_ecb_encrypt, detect_aes_mode
import base64
import string

AES_KEY = b'\xac\xdb\x9a\xf1\xc5(0\x96\xf5H\x80\xc3\x1eG\x8c\x8f'
unknown_b64_string = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

def encryption_oracle_ecb(cleartext):
	# encrypt ecb / cbc half of the time
	cleartext = cleartext + base64.b64decode(unknown_b64_string)
	ciphertext = aes_ecb_encrypt(cleartext, AES_KEY)


	return ciphertext

def byte_a_time_ECB_decryption():
	print ("À l'assaut !")

	# detect the block size of the cipher
	"""
	We know that AES use padding (as it work on blocks of constent length).
	We can detect the blocksize by adding bytes at the end until we saw a change
	in the length of the ciphertext.
	The difference of size between the inital and the new length of the ciphertext
	is the size of an AES block.
	"""

	len1 = len(encryption_oracle_ecb(b''))
	len2 = None

	for i in range(0, 8):
		length_of_ciphertext = len(encryption_oracle_ecb(b'A' * i))

		if length_of_ciphertext != len1:
			len2 = length_of_ciphertext
			size_of_input_for_no_padding = i - 1
			break

	blocksize_of_the_cipher = len2 - len1
	print (blocksize_of_the_cipher)

	# detect if the encryption mode is ECB
	"""
	If ECB is used, the second and third block of ciphertext should be identical for a constant input
	ex : b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
	"""
	AES_mode = detect_aes_mode(encryption_oracle_ecb(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'))
	print (AES_mode)

	if AES_mode != 'ECB':
		raise ('The mode is not ECB, and byte_a_time_ECB_decryption() only works with ECB. :/')
		return

	# get the last encrypted byte
	input_length = blocksize_of_the_cipher - 1 	# so we have AAA...A and
												# the first encryted byte
												# (in the first block)
	ciphertext = encryption_oracle_ecb(b'A' * input_length)

	first_encrypted_byte = ciphertext[blocksize_of_the_cipher - 1] # because lists begins at 0

	# bruteforce the last byte
	for letter in string.printable:
		ciphertext = encryption_oracle_ecb (b'A' * input_length + letter.encode())

		if ciphertext [blocksize_of_the_cipher - 1] == first_encrypted_byte:
			decrypted_byte = letter
			print ("The first letter is %s !" % letter)


	# repeat !



if __name__ == '__main__':
	byte_a_time_ECB_decryption()