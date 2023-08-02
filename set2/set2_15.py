#!/usr/bin/env python3
# coding: utf-8

# This function fail if we have incorrect padding
def unpad_pkcs7(padded_block):
	pad_length = padded_block[-1]

	# let check if we effectively have padding
	padding = padded_block[-pad_length:]
	for byte_pad in padding:
		if byte_pad != pad_length:
			raise ValueError(f'''
PKCS#7 padding error: every byte of the padding should have the value of the length of the padding.
pad_length={pad_length}
{padded_block}''')

	padded_block = padded_block[:-pad_length]

	return padded_block


print(unpad_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04"))