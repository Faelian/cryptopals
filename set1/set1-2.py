#!/usr/bin/env python3
#coding: utf-8

hex_str1 = '1c0111001f010100061a024b53535009181c'
hex_str2 = '686974207468652062756c6c277320657965'

# hex decoding
bytes1 = bytes.fromhex(hex_str1)
bytes2 = bytes.fromhex(hex_str2)

# xor all the bytes !
xored = [a ^ b for (a, b) in zip (bytes1, bytes2)]
print(bytes(xored).decode("utf-8"))

# convert list of bytes to hex
hex_xored = bytes(xored).hex()
print (hex_xored)