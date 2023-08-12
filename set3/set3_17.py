#!/usr/bin/env python3
# coding: utf-8

from aes_cbc import aes_cbc_encrypt, pad_pkcs7, unpad_pkcs7, xor_blocks
from secrets import token_bytes
from base64 import b64decode
from random import randrange
from Crypto.Cipher import AES
from hexdoor import hexdump

AES_KEY = b'\xfb0\x1e\x06@\xd7q:\xb0\x03\xee\\\xfe\xd4\x9aX'

secret_strings = [
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

# ~~~ Exercice functions ~~~

def encryption_oracle():
	selected_secrettext = randrange(len(secret_strings))
	#selected_secrettext = 0
	secret = secret_strings[selected_secrettext]
	cleartext = b64decode(secret)
	
	iv = token_bytes(16)
	#iv = b'\x00'*15 + b'\x42'
	ciphertext = aes_cbc_encrypt(iv, cleartext, AES_KEY)

	return (iv, ciphertext)

# return True if padding is correct, False if the padding is incorrect
def check_pkcs7_padding(padded_block):
	pad_length = padded_block[-1]

	# let check if we effectively have padding
	padding = padded_block[-pad_length:]
	for byte_pad in padding:
		if byte_pad != pad_length:
			return False

	return True

def decryption_oracle(iv, ciphertext, key):
	# divide the ciphertext in blocks of 16 bytes (AES standard block)
	blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

	# for the exercice we implement CBC with ECB
	cipher = AES.new(key, AES.MODE_ECB) 

	previous_ciphertext = iv
	cleartext_array = []
	
	# for each block
	for block in blocks:

		# decrypt it with the key
		xored_block = cipher.decrypt(block)

		# xor previous ciphertext or iv
		cleartext_block = xor_blocks(previous_ciphertext, xored_block)
		cleartext_array.append(cleartext_block)

		previous_ciphertext = block

	# Check if the padding is correct
	is_correct = check_pkcs7_padding(cleartext_array[-1])

	return is_correct


# ~~~ Debug and attack functions ~~~

def split_into_chunks(byte_string, chunk_size=16):
    for i in range(0, len(byte_string), chunk_size):
        yield byte_string[i:i + chunk_size]

def print_hex_chunks(ciphertext):
	i = 0
	for chunk in split_into_chunks(ciphertext):
		print(f"{i*0x10:02x}: {chunk.hex()}")
		i += 1

def bruteforce_last_hexbyte(iv, ciphertext_original):
	ciphertext = bytearray(ciphertext_original)

	original_value = ciphertext[0x2f]

	good_val = None

	for i in range(0x00, 0x100):
		if i == original_value:
			continue

		ciphertext[0x2f] = i
		
		if decryption_oracle(iv, ciphertext, AES_KEY):
			print(f'0x{i:02x}')
			good_val = i
	
	return good_val


"""
For reference see this video : https://www.youtube.com/watch?v=4EgD4PEatA8

     Ciphertetext 1                          Ciphertext 2
┌──┬──┬──┬──┬──┬──┬──┬──┐               ┌──┬──┬──┬──┬──┬──┬──┬──┐
│  │  │  │  │  │  │C2│C1│               │  │  │  │  │  │  │  │  │
└──┴──┴──┴─┬┴──┴──┴──┴──┘               └──┴──┴──┴──┼──┴──┴──┴──┘
           │                                        │
           │                               ┌────────▼─────────┐
           │                   Key ───────►│   Block Cipher   │
           │                               │    Decryption    │
           │                               └────────┬─────────┘
           │                                        │
           │                            ┌──┬──┬──┬──▼──┬──┬──┬──┐
           │                            │  │  │  │  │  │  │X2│X1│
           │                            └──┴──┴──┴──┼──┴──┴──┴──┘
           │                                        │
           │                                      ┌─▼─┐
           └─────────────────────────────────────►│Xor│
                                                  └─┬─┘
                                                    │
                                        ┌──┬──┬──┬──▼──┬──┬──┬──┐
                                        │  │  │  │  │  │  │P2│P1│
                                        └──┴──┴──┴──┴──┴──┴──┴──┘
                                               Plaintext

We change the value of the previous block of ciphertext to find T1 such as
P1 = 0x01

This would be valid padding

     Ciphertetext 1                          Ciphertext 2
┌──┬──┬──┬──┬──┬──┬──┬──┐               ┌──┬──┬──┬──┬──┬──┬──┬──┐
│  │  │  │  │  │  │  │T1│               │  │  │  │  │  │  │  │  │
└──┴──┴──┴─┬┴──┴──┴──┴──┘               └──┴──┴──┴──┼──┴──┴──┴──┘
           │                                        │
           │                               ┌────────▼─────────┐
           │                   Key ───────►│   Block Cipher   │
           │                               │    Decryption    │
           │                               └────────┬─────────┘
           │                                        │
           │                            ┌──┬──┬──┬──▼──┬──┬──┬──┐
           │                            │  │  │  │  │  │  │X2│X1│
           │                            └──┴──┴──┴──┼──┴──┴──┴──┘
           │                                        │
           │                                      ┌─▼─┐
           └─────────────────────────────────────►│Xor│
                                                  └─┬─┘
                                                    │
                                        ┌──┬──┬──┬──▼──┬──┬──┬──┐
                                        │  │  │  │  │  │  │  │01│
                                        └──┴──┴──┴──┴──┴──┴──┴──┘
                                               Plaintext
"""

def bruteforce_byte(iv, ciphertext_original, x_array):
	ciphertext = bytearray(ciphertext_original)
	pad_value = len(x_array) + 0x1

	byte_to_change = len(ciphertext) - 0x10 - pad_value

	original_value = ciphertext[byte_to_change]
	t = None

	i = 1
	for x in x_array:
		ciphertext[byte_to_change + i] = x ^ pad_value
		i += 1

	# hexdump(ciphertext)

	for i in range(0x00, 0x100):
		if i == original_value:
			continue

		ciphertext[byte_to_change] = i
		
		if decryption_oracle(iv, ciphertext, AES_KEY):
			# print(f'0x{i:02x}')
			t = i
	
	if t is None:
		t = original_value

	# see the schema above for what x, c and p are 
	x = t ^ len(x_array) + 0x01
	c = original_value
	# print(f"x: 0x{x:02x}")
	# print(f"c: 0x{c:02x}")
	p = x ^ c
	# print(f"p: 0x{p:02x}")

	return x, p


def decrypt_block(iv, ciphertext):
	x_array = b''
	decrypted = b''
	x = None

	for i in range(0, 0x10):
		x, p = bruteforce_byte(iv, ciphertext, x_array)

		x_array = x.to_bytes(1, 'little') + x_array
		decrypted = p.to_bytes(1, 'little') + decrypted

	return decrypted

def decrypt_aes_cbc(iv, ciphertext):
	decrypted = b''

	while len(ciphertext) > 0x10:
		decrypted = decrypt_block(iv, ciphertext) + decrypted
		ciphertext = ciphertext[:-0x10]

	ciphertext = iv + ciphertext
	decrypted = decrypt_block(iv, ciphertext) + decrypted

	return unpad_pkcs7(decrypted)

if __name__ == '__main__':
	iv, ciphertext = encryption_oracle()
	#print(f"iv: {iv.hex()}, ciphertext: {ciphertext.hex()}")

	#hexdump(ciphertext)

	cleartext = decrypt_aes_cbc(iv, ciphertext)
	print(cleartext)
