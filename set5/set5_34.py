#!/usr/bin/env python3
#coding: utf-8

from set5_33 import Diffie_Hellman, mod_exp

annie = Diffie_Hellman()
betty = Diffie_Hellman()

p = annie.p
g = annie.g
A = annie.public
B = betty.public

# print(f'p: {annie.p}')
# print(f'g: {annie.g}')

# print(f'A: {annie.public}')
# print(f'B: {betty.public}')

annie.derive_secret(B)
betty.derive_secret(A)

iv, ciphertext = annie.encrypt_aes(b'Hello word !')
print(repr(ciphertext))