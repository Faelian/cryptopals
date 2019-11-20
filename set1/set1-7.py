#!/usr/bin/env python3
# coding: utf8

from Crypto.Cipher import AES
import base64

with open('7.txt', 'r') as f:
	ciphertext = base64.b64decode(f.read())

	key = b'YELLOW SUBMARINE'
	cipher = AES.new(key, AES.MODE_ECB)

	plaintext = cipher.decrypt(ciphertext)

	print (plaintext.decode('utf-8'))