_#!/usr/bin/env python3
#coding: utf-8

from set2_11 import aes_ecb_encrypt, aes_ecb_decrypt
import json

AES_KEY = b'\xaeJK^\xe1d\xb1M\xfb\xb3[%-\x9c\x14\xe1'

def print_hex(data):
    result = ''
    for c in data:
        result += f'\\x{c:02x}'

    print("b'" + result + "'")


# Functions for the challenge

def decode_querystring(query_string):
	variables = dict()

	for item in query_string.split('&'):
		key, value = item.split('=')

		# if value is an int, parse it
		if value.isdigit():
			value = int(value)

		variables[key] = value
	
	return variables


def encode_querystring(value_dict):
	qs = '&'.join(
		[f"{key}={value_dict[key]}"
			for key in value_dict])

	return qs


def profile_for(email):
	email = email.replace('&', '')
	email = email.replace('=', '')

	profile = {
		'email': email,
		'uid': 10,
		'role': 'user'
	}

	return encode_querystring(profile)



def encrypt_profile(email):
	return aes_ecb_encrypt(profile_for(email).encode(), AES_KEY)

def decrypt_profile(encrypted_cookie):
	cleartext = aes_ecb_decrypt(encrypted_cookie, AES_KEY)
	#print(repr(cleartext))
	profile = decode_querystring(cleartext.decode())
	return profile


# ECB cut and paste !

if __name__ == '__main__':

	input = b'A'*10 + b'admin' + b'\x0b'*11
	ciphertext = encrypt_profile(input.decode())
	cleartext = decrypt_profile(ciphertext)

	qs = aes_ecb_decrypt(ciphertext, AES_KEY)
	print(qs[0:16])
	print(qs[16:32])
	print(qs[32:])

	admin_ecb = ciphertext[16:32]
	print('admin in ecb: ', end='')
	print_hex(admin_ecb)

	print('~~~~~~~~~~~~')

	template_cookie = encrypt_profile('hax0r@pwn.xyz')
	cleartext = decrypt_profile(template_cookie)

	qs = aes_ecb_decrypt(template_cookie, AES_KEY)
	print(qs[0:16])
	print(qs[16:32])
	print(qs[32:])

	print('~~~~~~~~~~~~')

	fake_cookie = template_cookie[:32] + admin_ecb
	print_hex(fake_cookie[32:])
	print(len(fake_cookie))
	print(aes_ecb_decrypt(fake_cookie, AES_KEY))
