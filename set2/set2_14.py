#!/usr/bin/env python3
# coding: utf-8

import base64
from set2_11 import aes_ecb_encrypt, aes_ecb_decrypt
from set2_13 import print_hex
import hexdump
import hexdoor
import string

random_prefix = b'G\xb4\xdd%1R?\xde\x89\x1b$Ln\xeawC\xa8\xc4J~Rm|\x90'
AES_KEY = b'\xaeJK^\xe1d\xb1M\xfb\xb3[%-\x9c\x14\xe1'

secret_b64_string = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

BLOCKSIZE = 16

# Divide the ciphertext in chunk of `size`, and return the chunk n
# (start at 0 like arrays)
def get_block(ciphertext, n, size):
	return ciphertext[size*n:size*(n+1)]

def encryption_oracle(cleartext):
	cleartext = random_prefix + cleartext + base64.b64decode(secret_b64_string)
	ciphertext = aes_ecb_encrypt(cleartext, AES_KEY)
	return ciphertext

def split_into_chunks(byte_string, chunk_size=16):
    for i in range(0, len(byte_string), chunk_size):
        yield byte_string[i:i + chunk_size]

def print_hex_chunks(ciphertext):
	i = 0
	for chunk in split_into_chunks(ciphertext):
		print(f"{i:02}: {chunk.hex()}")
		i += 1

def length_change_ciphertext_size():
	ciphertext = encryption_oracle(b'')
	original_length = len(ciphertext)

	for i in range(0, 32):
		l = len(encryption_oracle(b'A'*i))

		if l != original_length:
			break

	print(i)
	return i

def find_identical_blocks(ciphertext):
	previous_chunk = None
	index = 0

	for chunk in split_into_chunks(ciphertext):
		if previous_chunk == chunk:
			# print(f"identical blocks at index {index} :\n{chunk.hex()}")
			# print_hex_chunks(ciphertext)
			return index

		previous_chunk = chunk
		index += 1

	return None


def find_prefix_offsets():
	for i in range(0, 512):
		padding = b'B'*i
		ciphertext = encryption_oracle(padding + b'A'*2*BLOCKSIZE)

		index_block = find_identical_blocks(ciphertext)
		if (index_block):
			return (index_block-1, padding)


def decrypt_byte(decrypted, offset_block, prefix_padding):
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
	n_block = n_block + offset_block

	# how much b'A' we use to pad the text
	pad_length = 15 - len(decrypted) % BLOCKSIZE

	ciphertext = encryption_oracle(prefix_padding + b'A'*pad_length)
	reference_ciphertext_block = get_block(ciphertext, n_block, BLOCKSIZE)

	for letter in string.printable:
		encrypted = encryption_oracle(prefix_padding + b'A'*pad_length + decrypted + letter.encode())

		block_to_watch = get_block(encrypted, n_block, BLOCKSIZE)

		if  block_to_watch == reference_ciphertext_block:
			return letter.encode()

	return b''


if __name__ == '__main__':
	
	block_to_watch = 2
	prefix_padding = b'B'*8

	block_to_watch, prefix_padding = find_prefix_offsets()

	print(f"index block: {block_to_watch}, prefix_padding: {prefix_padding}")

	decrypted = decrypt_byte(b'', block_to_watch, prefix_padding)

	for i in range(0, 100):
		decrypted += decrypt_byte(decrypted, block_to_watch, prefix_padding)

	print(decrypted.decode())
	
