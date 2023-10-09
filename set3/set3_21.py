#!/usr/bin/env python3
# coding: utf-8

import sys


# w, n, m, r, a, u, d, s, b, t, c, l, f

w, n, m, r = 32, 624, 397, 31
a = 0x9908b0df
u, d = 11, 0xffffffff
s, b =  7, 0x9d2c5680
t, c = 15, 0xefc60000
l = 18
f = 1812433253

print(f"w:{w}, n:{n}, m:{m}, r:{r}")
print(f"a:{a}")
print(f"u:{u}, d:{d}")
print(f"s:{s}, b:{b}")
print(f"t:{t}, c:{c}")
print(f"l:{l}")

# Create a length n array to store the state of the generator
MT = [None] * n

index = n+1
lower_w_bits = (1 << w) - 1 # 0xffffffff

lower_mask = (1 << r) - 1 # That is, the binary number of r 1's
upper_mask = ~lower_mask ^ lower_w_bits

print(f'upper_mask: {bin(upper_mask)}')


# Initialize the generator from a seed
def seed_mt(seed):
	global index
	index = n
	MT[0] = seed

	for i in range(1, n):

		MT[i] = lower_w_bits ^ (
			f * (
				MT[i-1]
				^ 
				MT[i-1] >> (w-2)
				)
			+ i
			)

# Extract a tempered value based on MT[index]
# calling twist() every n numbers

def extract_number():
	if index >= n:
		if index > n:
			print(f"index: {index}")
			print(f"n: {n}")
			raise Exception("Error, generator was never seeded")
		twist()

	y = MT[index]
	y = y ^ ((y >> u) & d)

def twist():
	for i in range(0, 8):
		print(bin(MT[i])[0:32])
		x = (MT[i] & upper_mask)
		print(bin(x)[0:32])
	exit()


if __name__ == '__main__':
	
	seed_mt(0)
	extract_number()
