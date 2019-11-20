#!/usr/bin/env python3
# coding: utf8

from Crypto.Cipher import AES
import base64

def pad_pkcs7(unpadded_block, length):
	bytes_to_add = length - len(unpadded_block)
	padded_block = unpadded_block + b'\x04' * bytes_to_add

	return padded_block

def unpad_pkcs7(padded_block):
	while (padded_block[-1] == 0x04):
		padded_block = padded_block[:-1]

	return padded_block

def xor_blocks(block1, block2):
	xored_array = [a ^ b for (a, b) in zip (block1, block2)]
	return bytes(xored_array)

def aes_cbc_encrypt(iv, cleartext, key):
	
	# divide cleartext in blocks (AES block = 16 bytes)
	blocks = [cleartext[i:i+16] for i in range(0, len(cleartext), 16)]
	
	# pad the last block of cleartext with PKCS7
	blocks[-1] = pad_pkcs7(blocks[-1], 16)

	
	# for the exercice we implement CBC with ECB
	cipher = AES.new(key, AES.MODE_ECB) 
	
	ciphertext = bytes()

	previous_block = iv
	# for each block
	for block in blocks:
		# xor iv or previous ciphertext
		data_to_encrypt = xor_blocks(previous_block, block)

		# encrypt with key
		cipher_block = cipher.encrypt(data_to_encrypt)
		ciphertext = ciphertext + cipher_block
		
		previous_block = cipher_block

	return ciphertext

def aes_cbc_decrypt(iv, ciphertext, key):
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

	# unpad the last block
	cleartext_array[-1] = unpad_pkcs7(cleartext_array[-1])
	cleartext = b''.join(cleartext_array)

	return cleartext


with open ('10.txt', 'r') as f:
	iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	ciphertext = base64.b64decode(f.read())

	cleartext = aes_cbc_decrypt(iv, ciphertext, 'YELLOW SUBMARINE').decode()
	print (cleartext)