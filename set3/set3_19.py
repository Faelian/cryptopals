#!/usr/bin/env python3
# coding: utf-8

from Crypto.Cipher import AES
from hexdoor import hexdump
from base64 import b64decode
import string

from set3_18 import aes_ctr, generate_keystream, xor_blocks
from pprint import pprint

BLOCKSIZE = 16
IV = b'\x00'*8
KEY = bytes.fromhex('2df42ea1f5d236fb8966a6726606b9db') # generated with secrets.token_bytes(16)

SECRET_MESSAGES = [
	'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
	'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
	'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
	'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
	'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
	'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
	'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
	'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
	'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
	'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
	'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
	'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
	'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
	'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
	'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
	'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
	'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
	'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
	'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
	'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
	'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
	'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
	'U2hlIHJvZGUgdG8gaGFycmllcnM/',
	'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
	'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
	'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
	'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
	'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
	'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
	'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
	'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
	'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
	'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
	'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
	'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
	'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
	'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
	'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
	'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
	'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
]

# Copy pasted from  set1_3.py

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

def break_single_key_xor(encrypted_bytes):
	final_score = 100000000000
	final_key = None
	message = None

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
		if (score < final_score):
			message = decrypted_string
			final_key = key
			final_score = score

	return final_key, message


# Functions for this set


def split_in_single_key(message, single_key_blocks):
	for i in range(len(message)):
		single_key_blocks[i].append(message[i])

if __name__ == '__main__':
	# initalize the challenge:
	# encrypt every message with the KEY
	ciphertexts = []

	for message in SECRET_MESSAGES:
		encrypted_message = aes_ctr(IV, b64decode(message), KEY)
		ciphertexts.append(encrypted_message)

	# Since the same keystream is use to encrypt every message,
	# we can group bytes of ciphertext by the keystream that encrypt the message

	max_length_of_ciphertext = max([len(ciphertext) for ciphertext in ciphertexts])

	single_key_blocks = [[] for _ in range(max_length_of_ciphertext)]


	# create array of single byte arry
	for encrypted_message in ciphertexts:
		split_in_single_key(encrypted_message, single_key_blocks)	

	pprint(single_key_blocks[0])	


	for single_key_bytes in single_key_blocks:
		print(bytes(single_key_bytes).hex())

	key, message = break_single_key_xor(single_key_blocks[0])
	print(message)