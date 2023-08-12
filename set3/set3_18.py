#!/usr/bin/env python3
# coding: utf-8

from Crypto.Cipher import AES
from hexdoor import hexdump
import base64

BLOCKSIZE = 16

# can also be used to decrypt, replace cleartext with ciphertext
def aes_ctr(iv, cleartext, key):
	ciphertext = b''
	length = len(cleartext)

	keystream = generate_keystream(length, iv, key)

	return xor_blocks(cleartext, keystream)

def generate_keystream(length, iv, key):
	if len(iv) != 8:
		raise Exception(f"IV must be 8 bytes. {iv.hex()}")

	# for the exercice we implement CBC with ECB
	cipher = AES.new(key, AES.MODE_ECB) 

	n_block, _ = divmod(length, BLOCKSIZE)
	keystream = b''

	for ctr in range(0, n_block + 1):
		block_input = iv + ctr.to_bytes(8, 'little')
		keystream += cipher.encrypt(block_input)

	return keystream[:length]


def xor_blocks(block1, block2):
	xored_array = [a ^ b for (a, b) in zip (block1, block2)]
	return bytes(xored_array)


iv = b'\x00'*8
key = b'YELLOW SUBMARINE'

ciphertext = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
cleartext = aes_ctr(iv, ciphertext, key)
print(cleartext.decode())