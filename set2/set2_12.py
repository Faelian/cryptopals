#!/usr/bin/env python3
# coding: utf8

from Crypto.Cipher import AES
from set2_11 import aes_ecb_encrypt, detect_aes_mode
import base64
import string
from hexdump import hexdump

AES_KEY = b'\xac\xdb\x9a\xf1\xc5(0\x96\xf5H\x80\xc3\x1eG\x8c\x8f'
BLOCKSIZE = 16
# unknown_b64_string = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoK"
unknown_b64_string = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

def print_hex_string(data):
    result = ''

    for c in data:
        result += f'\\x{c:02x}'

    print("b'" + result + "'")


def encryption_oracle_ecb(cleartext):
	cleartext = cleartext + base64.b64decode(unknown_b64_string)
	ciphertext = aes_ecb_encrypt(cleartext, AES_KEY)

	return ciphertext



def decrypt_byte_first_block(blocksize, decrypted):

	padding = b'A'* (blocksize - len(decrypted) - 1)

	ciphertext = encryption_oracle_ecb(padding)
	first_block = ciphertext[:blocksize-1] # list start at 0

	for letter in string.printable:
		encrypted = encryption_oracle_ecb(padding + decrypted + letter.encode())

		if encrypted[:blocksize-1] == first_block:
			return letter.encode()

	return '.'.encode()


# Divide the ciphertext in chunk of `size`, and return the chunk n
# (start at 0 like arrays)
def get_block(ciphertext, n, size):
	return ciphertext[size*n:size*(n+1)]

def decrypt_byte(decrypted):
	global BLOCKSIZE

	"""
	In ECB, 2 identical input will produce the same output

	We use our oracle to encrypt 15 'A' + the 1st byte of cleartext.

	We can then test 15 'A' + X, to find X = 1st char of plaintext

	Decrease the padding, add the decrypted text and repeat
	i.e: 14 'A' + Decrypted + X

	----------------------------------------------------------------------

	Once we have decrypted the 1st block.
	We will have to watch the 2nd block for the decryption. Then 3rd, etc
	
	"""

	# the block to watch, 
	n_block, _ = divmod(len(decrypted), BLOCKSIZE)

	# how much b'A' we use to pad the text
	pad_length = 15 - len(decrypted) % BLOCKSIZE

	ciphertext = encryption_oracle_ecb(b'A'*pad_length)
	reference_ciphertext_block = get_block(ciphertext, n_block, BLOCKSIZE)

	for letter in string.printable:
		encrypted = encryption_oracle_ecb(b'A'*pad_length + decrypted + letter.encode())

		block_to_watch = get_block(encrypted, n_block, BLOCKSIZE)

		if  block_to_watch == reference_ciphertext_block:
			return letter.encode()

	return b''



def byte_a_time_ECB_decryption():
	global BLOCKSIZE

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
		ciphertext = encryption_oracle_ecb(b'A' * i)
		length_of_ciphertext = len(ciphertext)

		if length_of_ciphertext != len1:
			len2 = length_of_ciphertext
			break

	BLOCKSIZE = len2 - len1 # 16 with AES

	# detect if the encryption mode is ECB
	"""
	If ECB is used, the second and third block of ciphertext should be identical for a constant input
	ex : b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
	"""
	AES_mode = detect_aes_mode(encryption_oracle_ecb(b'A'*BLOCKSIZE*4))

	if AES_mode != 'ECB':
		raise ('The mode is not ECB, and byte_a_time_ECB_decryption() only works with ECB. :/')
		return

	"""
	Now let's decrypt the ECB ciphertext. One byte at the time
	"""

	decrypted = b''
	max_length_of_ciphertext = len(encryption_oracle_ecb(b''))

	for i in range(0, max_length_of_ciphertext):
		decrypted += decrypt_byte(decrypted)

	# Victory !
	print(decrypted.decode())


if __name__ == '__main__':
	byte_a_time_ECB_decryption()