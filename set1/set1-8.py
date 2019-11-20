#!/usr/bin/env python3
# coding: utf8

with open('8.txt', 'r') as f:
	lines = f.readlines() 
	n = 16	# 16 char = 16 bytes

	line_number = 0 # for pretty printing

	# In ecb, identical cleartext produce identical ciphertext
	# we look for the hexadecimal string with multiple duplicates blocks

	for line in lines:
		line_number = line_number + 1
		
		# split the string in blocks of 16 chars
		ecb_blocks = [line[i:i+n] for i in range(0, len(line), n)]	

		# set remove the duplicate, and we compare the number of elements
		nb_duplicate = len(ecb_blocks) - len(set(ecb_blocks)) 

		if (nb_duplicate != 0):
			print ('line %d : %d duplicates' % (line_number, nb_duplicate))
		