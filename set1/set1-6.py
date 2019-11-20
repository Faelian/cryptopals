#!/usr/bin/env python3
#coding: utf-8

import base64
import string
from set1_3 import break_single_key_xor
from set1_5 import xor_repeatkey

# takes 2 bytes
def calculate_hamming_distance(bytes1, bytes2):

	if len(bytes1) != len(bytes2):
		raise """Hamming distance calculation need two objects of the same size
		len bytes1 = {}
		len bytes2 = {}
		""".format(len(bytes1), len(bytes2))
	
	hamming_distance = 0

	# on lit un octet à fois
	for i in range(0, len(bytes1)):
		byte1 = bytes1[i]
		byte2 = bytes2[i]

		bin1 = bin(byte1)[2:].zfill(8)
		bin2 = bin(byte2)[2:].zfill(8)

		for (bit1, bit2) in zip (bin1, bin2):	
			if (bit1 != bit2):
				hamming_distance += 1

	return hamming_distance

def calculate_keysize_vignere(ciphertext):
	## Calculate Hamming Distance ##
	final_keysize = None
	final_hamming_dist   = float('inf')

	for keysize in range (2, 45):

		# store the hamming distances for this keysize
		distances = []

		chunks = [ciphertext[i:i+keysize] for i in range (0, len(ciphertext), keysize)]

		# calculate hamming distance for each 2 chunks of keysize
		while len (chunks) > 2 :
			chunk1 = chunks[0]
			chunk2 = chunks[1]

			normalised_distance = calculate_hamming_distance (chunk1, chunk2) / keysize

			distances.append(normalised_distance)

			del chunks[0]
			del chunks[1]


		#average the hamming distances 
		avg_distance = sum(distances) / len (distances)

		#print ("{} : {}".format(keysize, avg_distance))

		if (avg_distance < final_hamming_dist):
			final_keysize = keysize
			final_hamming_dist = avg_distance

	return final_keysize

with open('6.txt', 'r') as f:
	msg_b64 = f.read().replace('\n', '')

	msg = base64.b64decode(msg_b64)

	keysize = calculate_keysize_vignere(msg)

	# Decipher the message

	single_key_blocks = [[]] * keysize
	decoded_blocks    = [[]] * keysize

	final_key = b''

	for i in range(0, keysize):
		block = b''

		for j in range(i, len(msg), keysize):
			block += bytes([msg[j]])

		key_single_xor, msg_single_xor = break_single_key_xor(block)

		final_key += bytes([key_single_xor])

	print (final_key)

	decrypted_msg = xor_repeatkey(msg, final_key)
	print(decrypted_msg.decode('utf-8'))