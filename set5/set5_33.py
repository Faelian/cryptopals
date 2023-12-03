#!/usr/bin/env python3
#coding: utf-8

from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import secrets
import binascii

# Diffie-Hellman constants

class Diffie_Hellman(object):
	"""docstring for Diffie_Hellman"""
	
	# diffie hellman constants
	default_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
	g = 2
	

	def __init__(self, p=default_p, g=2):
		self.p = p
		self.g = g

		self.secret = secrets.randbelow(pow(2, 1024)-1)
		self.public = mod_exp(g, self.secret, p)
		self.shared = None


	def derive_secret(self, B):
		self.shared = mod_exp(B, self.secret, self.p)

	def derive_key(self):
		if not self.shared:
			print('we first need a shared secret')
			return None

		print(f'shared secret: {hex(self.shared)}')
		#key = self.shared.to_bytes(128, byteorder='little')
		key = binascii.unhexlify(hex(self.shared)[2:])
		key = sha1(key).digest()[:16]
		return key


	def encrypt_aes(self, msg):
		iv = secrets.token_bytes(16)
		key = self.derive_key()
		print(f'key: {key.hex()}')

		cipher = AES.new(key, AES.MODE_CBC, iv=iv)
		ciphertext = cipher.encrypt(pad(msg, AES.block_size))

		return (iv, ciphertext) 

# b puissance e modulo m
def mod_exp(b, e, m):
	if m == -1:
		return 0

	b = b % m

	x = 1

	while e > 0:
		if e % 2 == 0:
			x = b * x % m

		b = b * b % m
		e = e // 2

	return x

# g = 2
# p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff


# a = gen_secret_number()
# print(f'a: {hex(a)}')
# A = mod_exp(g, a, p)

# b = 3
# B = mod_exp(g, b, p)

# print(f'A: {hex(A)}')
# print(f'B: {hex(B)}')

# # ---------------------

# s1 = mod_exp(A, b, p)
# print(f's1: {hex(s1)}')
# print(f"hash: {md5(s1.to_bytes(2048, 'little')).hexdigest()}")


if __name__ == '__main__':
	alphonse = Diffie_Hellman()
	bettie = Diffie_Hellman()

	print(f"- alphonse -\nsecret: {hex(alphonse.secret)}\npublic: {hex(alphonse.public)}\n")
	print(f"- bettie -\nsecret: {hex(bettie.secret)}\npublic: {hex(bettie.public)}\n")