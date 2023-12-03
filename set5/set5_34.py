#!/usr/bin/env python3
#coding: utf-8

from set5_33 import Diffie_Hellman, mod_exp

annie = Diffie_Hellman()


# A->M
# Send "p", "g", "A"
p = annie.p
g = annie.g
A = annie.public

# M->B
# Send "p", "g", "p"
betty = Diffie_Hellman()
betty.derive_secret(p)

# B->M
# Send "B"
B = betty.public

# M->A
# Send "p"
annie.derive_secret(p)
print('plop')
print(f'annie secret: {annie.shared}')

# A->M
# Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
msg = b'Hello World !'
iv, cipher1 = annie.encrypt_aes(msg)

# # B->M
# # Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
# msg2 = b'Hi, how are you ?'
# iv2, cipher2 = betty.encrypt(msg2)


# annie.derive_secret(B)
# betty.derive_secret(A)

# iv, ciphertext = annie.encrypt_aes(b'Hello word !')
# print(repr(ciphertext))
# cleartext = annie.decrypt_aes(iv, ciphertext)
# print(repr(cleartext))