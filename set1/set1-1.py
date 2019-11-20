#!/usr/bin/env python3
#coding: utf-8

import base64

hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

decoded_hex = bytes.fromhex(hex_string).decode('utf-8')
print (decoded_hex)

base64string = base64.b64encode(bytes(decoded_hex, "utf-8"))

print (base64string)