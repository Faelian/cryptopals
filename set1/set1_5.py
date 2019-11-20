#!/usr/bin/env python3
#coding: utf-8


def xor_repeatkey(msg, key):
	ciphered = []

	for i in range(0, len(msg)):
		# on utilise un octet de la clé à la fois dans ce chiffrement
		k = key[i % len(key)]

		ciphered_byte = msg[i] ^ k
		ciphered.append(ciphered_byte)

	return bytes(ciphered)


if __name__ == '__main__':
	
	
	key = "ICE"
	msg = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	
	# always operate on raw bytes
	msg_b = bytes(msg, 'utf-8')
	key_b = bytes(key, 'utf-8')

	print (xor_repeatkey(msg_b, key_b).hex())
