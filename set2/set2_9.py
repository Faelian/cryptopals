#!/usr/bin/env python3
# coding: utf8

def pkcs7(unpadded_block, length):
	bytes_to_add = length - len(unpadded_block)
	padded_block = unpadded_block + chr(bytes_to_add).encode() * bytes_to_add

	return padded_block

if __name__ == "__main__":
	unpadded = b'YELLOW SUBMARINE'
	padded = pkcs7 (unpadded, 20)
	print (padded)