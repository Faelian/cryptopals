#!/usr/bin/env python3
#coding: utf-8
import string

# https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
# on donne un score à chaque string (est-ce un texte anglais ?) 
def scoreString (dechiphered_string) :
	expFreqsIncludingSpace = [
		0.0651738, 0.0124248, 0.0217339, 0.0349835,  #'A', 'B', 'C', 'D',...
		0.1041442, 0.0197881, 0.0158610, 0.0492888, 
		0.0558094, 0.0009033, 0.0050529, 0.0331490,
		0.0202124, 0.0564513, 0.0596302, 0.0137645, 
		0.0008606, 0.0497563, 0.0515760, 0.0729357, 
		0.0225134, 0.0082903, 0.0171272, 0.0013692, 
		0.0145984, 0.0007836, 0.1918182] ; #'Y', 'Z', ' '


	dechiphered_string = dechiphered_string.upper()
	CHARS_CONSIDERED = 27 # lettres en majuscules + espace

	char_count = [0] * CHARS_CONSIDERED
	char_freq  = [None] * CHARS_CONSIDERED

	# des fois qu'on ait de caractères bizarres au milieu qui ne comptent pas ?
	totCount = 0

	for c in dechiphered_string :
		index = ord(c) - ord('A')

		if (index >= 0 and index <26):
			char_count[index] = char_count[index] + 1
			totCount = totCount + 1

		elif (c == ' '):
			char_count[26] = char_count[26] + 1
			totCount = totCount + 1

		# on met un score elevé si on a des caractères non ascii
		elif (c not in string.printable):
			return 100000


	if totCount == 0 : totCount = 1
	
	chiSquareScore = 0

	for i in range (0, len(char_count)):
		char_freq[i] = char_count[i] / totCount
		chiSquareScore = chiSquareScore + ((char_freq[i] - expFreqsIncludingSpace[i]) * (char_freq[i] - expFreqsIncludingSpace[i]) / \
		expFreqsIncludingSpace[i]) 

	return chiSquareScore

def decrypt_single_char_xor_str(encrypted_string):
	encrypted_bytes = bytes.fromhex(encrypted_string)

	current_score = 100000000000
	messages = [None]

	# déchiffrement avec tous les clés possibles
	for key in range (0x00, 0xff + 1):
		decrypted = [key ^ a for a in encrypted_bytes] 

		# si on ne peut pas décoder la chaine
		try:
			decrypted_string = bytes(decrypted).decode('utf-8')
		
		except UnicodeDecodeError as e:
			#print (repr(e))
			continue

		score = scoreString (decrypted_string)

		# si on a plusieurs message avec le même score, on les affiche tous	
		if (score < current_score):
			messages = [decrypted_string]
			current_score = score

		elif (score == current_score):
			messages.append(decrypted_string)

	# for message in messages:
	# 	print (message)

	return (current_score, messages)



if __name__ == '__main__':

	with open ('4.txt', 'r') as f:		
		final_score = float('inf')
		final_messages = [None]

		for line in f:
			score, messages = decrypt_single_char_xor_str(line.replace('\n', ''))

			if score < final_score:
				final_score = score
				final_messages = messages

		for message in final_messages :
			print (message.replace('\n', ''))
