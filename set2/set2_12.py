#!/usr/bin/env python3
# coding: utf8

from Crypto.Cipher import AES
from set2_11 import aes_ecb_encrypt, detect_aes_mode
import base64
import string

#debug 
import re

AES_KEY = b'\xac\xdb\x9a\xf1\xc5(0\x96\xf5H\x80\xc3\x1eG\x8c\x8f'
unknown_b64_string = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoK"
# unknown_b64_string = """
# Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
# aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
# dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
# YnkK"""

def encryption_oracle_ecb(cleartext):
	# encrypt ecb / cbc half of the time
	cleartext = cleartext + base64.b64decode(unknown_b64_string)
	#print ("clear : %s" % cleartext)
	ciphertext = aes_ecb_encrypt(cleartext, AES_KEY)

	return ciphertext


def bruteforce_block (blocksize_of_the_cipher):
	decrypted = ""

	len_ciphertext = len(encryption_oracle_ecb(b''))
	number_of_blocks = int(len_ciphertext / blocksize_of_the_cipher)

	# for block_number in range(0, number_of_blocks):
	# 	for i in range (blocksize_of_the_cipher-1, -1, -1):
	# 		input_length = i + block_number * blocksize_of_the_cipher
	# 		print (input_length)	


	for i in range(blocksize_of_the_cipher-1, 0, -1):
		decrypted = decrypted + bruteforce_byte(blocksize_of_the_cipher, i, decrypted)
		print(i)
		print (decrypted)

def bruteforce_byte(blocksize_of_the_cipher, input_length, decrypted):
	## get the last encrypted byte
	ciphertext = encryption_oracle_ecb(b'A' * input_length)
	formated_ciphertext = ":".join("{:02x}".format(c) for c in ciphertext)
	# print ("debug : " +formated_ciphertext[:23] + ' ' + formated_ciphertext[24:47] + ' '
	# 	+ formated_ciphertext[48:71] + ' ' + formated_ciphertext[72:] )

	first_encrypted_byte = ciphertext[blocksize_of_the_cipher - 1] # because lists begins at 0
	# print ("debug : " + "0x{:02x}".format(first_encrypted_byte))
	# print ("debug : " + repr(first_encrypted_byte))

	## bruteforce the last byte
	decrypted_byte = '.'
	for letter in string.printable:
		# We need to add the already decrypted text at the begining of the input
		# otherwise the ciphertext won't match the cleartext
		ciphertext = encryption_oracle_ecb (b'A' * input_length + decrypted.encode() + letter.encode())

		if ciphertext [blocksize_of_the_cipher - 1] == first_encrypted_byte:
			decrypted_byte = letter
			print (letter)
			break

	return decrypted_byte

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

	for i in range(0, 128):
		length_of_ciphertext = len(encryption_oracle_ecb(b'A' * i))

		if length_of_ciphertext != len1:
			len2 = length_of_ciphertext
			break

	blocksize_of_the_cipher = len2 - len1

	# detect if the encryption mode is ECB
	"""
	If ECB is used, the second and third block of ciphertext should be identical for a constant input
	ex : b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
	"""
	AES_mode = detect_aes_mode(encryption_oracle_ecb(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'))

	if AES_mode != 'ECB':
		raise ('The mode is not ECB, and byte_a_time_ECB_decryption() only works with ECB. :/')
		return

	bruteforce_block(blocksize_of_the_cipher)


	# repeat !



if __name__ == '__main__':
	byte_a_time_ECB_decryption()